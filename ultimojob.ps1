# === PARAMETRI ===
param(
    [int]$thresholdHours = 24
)

# === CONFIGURAZIONE ===
$csvPath  = "C:\Temp\Veeam_All_Jobs_Report.csv"
$htmlPath = "C:\Temp\Veeam_Alert_Report.html"
$txtPath  = "C:\Temp\Veeam_Alert_Report.txt"
$logPath  = Join-Path $PSScriptRoot ("ultimojob_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

# === LOGGING ===
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR")][string]$Level = "INFO"
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $logPath -Value $line -Encoding UTF8
    switch ($Level) {
        "INFO"  { Write-Host $line }
        "WARN"  { Write-Host $line -ForegroundColor Yellow }
        "ERROR" { Write-Host $line -ForegroundColor Red }
    }
}

# Traduce il valore Result di Veeam in etichetta leggibile.
# Success e Warning sono entrambi considerati OK (backup completato con o senza avvisi).
function Get-ResultLabel {
    param([string]$Result)
    switch ($Result) {
        "Success" { return "Completato con successo" }
        "Warning" { return "Completato con avvisi"  }
        "Failed"  { return "Fallito"                }
        "None"    { return "In esecuzione"           }
        default   { return $Result                   }
    }
}

Write-Log "=== Avvio script ultimojob ==="
Write-Log "Soglia: $thresholdHours ore | Log: $logPath"
Write-Log "PowerShell: $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"

# === Email (opzionale) ===
$enableEmail   = $false
$emailSubject  = "Veeam: backup in stato critico (soglia $thresholdHours ore)"
$emailTo       = "admin@tuodominio.com"
$emailFrom     = "backup-alert@tuodominio.com"
$smtpServer    = "smtp.tuodominio.com"
$smtpPort      = 587
$emailUser     = "smtpuser@tuodominio.com"
# Imposta la password come variabile d'ambiente nel sistema o nel Task Scheduler:
#   [System.Environment]::SetEnvironmentVariable("VEEAM_SMTP_PASSWORD","tuapassword","Machine")
$emailPassword = $Env:VEEAM_SMTP_PASSWORD

# === PREPARAZIONE OUTPUT ===
try {
    New-Item -ItemType Directory -Path (Split-Path $csvPath) -Force | Out-Null
    Write-Log "Cartella output verificata: $(Split-Path $csvPath)"
} catch {
    Write-Log "Impossibile creare la cartella output: $_" "ERROR"
}

# === CARICAMENTO MODULO VEEAM ===
try {
    Import-Module Veeam.Backup.PowerShell -ErrorAction Stop
    Write-Log "Modulo Veeam.Backup.PowerShell caricato correttamente."
} catch {
    Write-Log "Import-Module Veeam.Backup.PowerShell fallito: $_" "ERROR"
    if ($PSVersionTable.PSEdition -eq "Desktop") {
        try {
            Add-PSSnapin VeeamPSSnapIn -ErrorAction Stop
            Write-Log "Fallback: VeeamPSSnapIn (snapin legacy PS5) caricato."
        } catch {
            Write-Log "Errore caricamento snapin legacy: $_" "ERROR"
            Write-Log "Impossibile continuare. Uscita." "ERROR"
            exit 1
        }
    } else {
        Write-Log "Impossibile continuare. Uscita." "ERROR"
        exit 1
    }
}

# === RACCOLTA JOB ===
# Get-VBRJob restituisce tutti i tipi in un'unica chiamata:
#   Backup              = job VM (Hyper-V, VMware)
#   EpAgentBackup       = job Veeam Agent (Windows/Linux)
#   VmbApiPolicyTempJob = job Proxmox VE
try {
    $vbrJobs = @(Get-VBRJob)
    Write-Log "Get-VBRJob: $($vbrJobs.Count) job trovati"
    foreach ($j in $vbrJobs) { Write-Log "  '$($j.Name)' | Tipo: $($j.JobType)" }
} catch {
    Write-Log "Errore in Get-VBRJob: $_" "ERROR"
    exit 1
}

# === ANALISI ===
# Si usa FindLastSession(), metodo nativo sull'oggetto job.
# Funziona per tutti i tipi: Backup (VM), EpAgentBackup (Agent), VmbApiPolicyTempJob (Proxmox).
# Get-VBRBackupSession non copre Agent e Proxmox in questa versione del modulo.
#
# Logica alert:
#   - Success o Warning entro soglia  → OK
#   - Success o Warning oltre soglia  → ALERT (backup scaduto)
#   - Failed                          → ALERT (ultimo run fallito)
#   - None (job in esecuzione)        → OK (il job sta girando adesso)
#   - Nessuna sessione                → ALERT (mai eseguito)

$allJobInfo   = [System.Collections.Generic.List[PSCustomObject]]::new()
$alertJobs    = [System.Collections.Generic.List[PSCustomObject]]::new()
$healthyJobs  = [System.Collections.Generic.List[PSCustomObject]]::new()
$healthyCount = 0
$alertCount   = 0

foreach ($job in $vbrJobs) {
    $jobType = $job.JobType.ToString()
    Write-Log "--- [$jobType] '$($job.Name)' ---"

    try {
        $lastSession = $job.FindLastSession()

        if ($null -eq $lastSession) {
            # Nessuna sessione: job mai avviato
            Write-Log "  FindLastSession() = null: job mai eseguito." "WARN"

            $entry = [PSCustomObject]@{
                JobName          = $job.Name
                JobType          = $jobType
                UltimaEsecuzione = "N/A"
                Stato            = "Mai eseguito"
                OreTrascorse     = "N/A"
            }
            $allJobInfo.Add($entry)
            $alertJobs.Add($entry)
            $alertCount++

        } else {
            $result  = $lastSession.Result.ToString()
            $endTime = $lastSession.EndTime
            Write-Log "  Ultima sessione: Risultato=$result | Fine=$endTime"

            if ($result -eq "None") {
                # Job attualmente in esecuzione
                Write-Log "  Job in esecuzione adesso → OK"
                $entry = [PSCustomObject]@{
                    JobName          = $job.Name
                    JobType          = $jobType
                    UltimaEsecuzione = "In corso"
                    Stato            = "In esecuzione"
                    OreTrascorse     = 0
                }
                $allJobInfo.Add($entry)
                $healthyJobs.Add($entry)
                $healthyCount++

            } elseif ($result -in @("Success", "Warning")) {
                $hoursAgo = [math]::Round((New-TimeSpan -Start $endTime -End (Get-Date)).TotalHours, 2)
                $label    = Get-ResultLabel $result
                Write-Log "  $label | $hoursAgo ore fa"

                $entry = [PSCustomObject]@{
                    JobName          = $job.Name
                    JobType          = $jobType
                    UltimaEsecuzione = $endTime
                    Stato            = $label
                    OreTrascorse     = $hoursAgo
                }
                $allJobInfo.Add($entry)

                if ($hoursAgo -gt $thresholdHours) {
                    Write-Log "  ALERT: oltre la soglia di $thresholdHours ore." "WARN"
                    $alertJobs.Add($entry)
                    $alertCount++
                } else {
                    $healthyJobs.Add($entry)
                    $healthyCount++
                }

            } else {
                # Failed (o altro stato non positivo)
                $hoursAgo = [math]::Round((New-TimeSpan -Start $endTime -End (Get-Date)).TotalHours, 2)
                $label    = Get-ResultLabel $result
                Write-Log "  ALERT: $label | $hoursAgo ore fa." "WARN"

                $entry = [PSCustomObject]@{
                    JobName          = $job.Name
                    JobType          = $jobType
                    UltimaEsecuzione = $endTime
                    Stato            = $label
                    OreTrascorse     = $hoursAgo
                }
                $allJobInfo.Add($entry)
                $alertJobs.Add($entry)
                $alertCount++
            }
        }

    } catch {
        Write-Log "  Errore nell'analisi del job '$($job.Name)': $_" "ERROR"
    }
}

Write-Log "=== Riepilogo: OK=$healthyCount | ALERT=$alertCount ==="

# === ESPORTA CSV (tutti i job) ===
try {
    $allJobInfo | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV generato: $csvPath"
} catch {
    Write-Log "Errore CSV: $_" "ERROR"
}

# === HTML (tutti i job: sezione rossa alert + sezione verde OK) ===
try {
    $alertRows = ""
    foreach ($j in $alertJobs) {
        $alertRows += "  <tr><td>$($j.JobName)</td><td>$($j.JobType)</td><td>$($j.UltimaEsecuzione)</td><td>$($j.Stato)</td><td>$($j.OreTrascorse)</td></tr>`n"
    }
    $healthyRows = ""
    foreach ($j in $healthyJobs) {
        $healthyRows += "  <tr><td>$($j.JobName)</td><td>$($j.JobType)</td><td>$($j.UltimaEsecuzione)</td><td>$($j.Stato)</td><td>$($j.OreTrascorse)</td></tr>`n"
    }
    $html = @"
<!DOCTYPE html><html><head><meta charset='UTF-8'>
<style>
  body  { font-family: Arial, sans-serif; margin: 20px; }
  h2    { margin-bottom: 4px; }
  p     { margin-top: 4px; color: #555; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }
  th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
  tr:nth-child(even) { background: #f9f9f9; }
  .th-alert { background: #d9534f; color: white; }
  .th-ok    { background: #5cb85c; color: white; }
</style></head><body>
<h2>Veeam - Stato Backup</h2>
<p>Generato: $(Get-Date)&nbsp;&nbsp;|&nbsp;&nbsp;Soglia: $thresholdHours ore&nbsp;&nbsp;|&nbsp;&nbsp;
   <strong style='color:#d9534f'>Alert: $alertCount</strong>&nbsp;&nbsp;|&nbsp;&nbsp;
   <strong style='color:#5cb85c'>OK: $healthyCount</strong>&nbsp;&nbsp;|&nbsp;&nbsp;
   Totale: $($vbrJobs.Count)</p>

<h3 style='color:#d9534f'>Job in stato critico ($alertCount)</h3>
<table>
  <tr><th class='th-alert'>Job</th><th class='th-alert'>Tipo</th><th class='th-alert'>Ultima Esecuzione</th><th class='th-alert'>Stato</th><th class='th-alert'>Ore Trascorse</th></tr>
$alertRows</table>

<h3 style='color:#5cb85c'>Job OK ($healthyCount)</h3>
<table>
  <tr><th class='th-ok'>Job</th><th class='th-ok'>Tipo</th><th class='th-ok'>Ultima Esecuzione</th><th class='th-ok'>Stato</th><th class='th-ok'>Ore Trascorse</th></tr>
$healthyRows</table>
</body></html>
"@
    $html | Out-File -Encoding UTF8 -FilePath $htmlPath
    Write-Log "HTML generato: $htmlPath"
} catch {
    Write-Log "Errore HTML: $_" "ERROR"
}

# === TXT (solo job in alert) ===
if ($alertJobs.Count -gt 0) {
    try {
        $txt = "=== VEEAM - JOB IN STATO CRITICO ===`nSoglia: $thresholdHours ore | Generato: $(Get-Date)`n"
        foreach ($j in $alertJobs) {
            $txt += "`nJob:               $($j.JobName)`nTipo:              $($j.JobType)`nUltima esecuzione: $($j.UltimaEsecuzione)`nStato:             $($j.Stato)`nOre trascorse:     $($j.OreTrascorse)`n"
        }
        $txt | Out-File -Encoding UTF8 -FilePath $txtPath
        Write-Log "TXT generato: $txtPath"
    } catch {
        Write-Log "Errore TXT: $_" "ERROR"
    }
}

# === INVIO EMAIL ===
if ($enableEmail -and $alertJobs.Count -gt 0 -and (Test-Path $htmlPath)) {
    try {
        if (-not $emailPassword) { throw "Variabile d'ambiente VEEAM_SMTP_PASSWORD non impostata." }
        $securePass = ConvertTo-SecureString $emailPassword -AsPlainText -Force
        $cred       = New-Object System.Management.Automation.PSCredential ($emailUser, $securePass)
        Send-MailMessage -From $emailFrom -To $emailTo -Subject $emailSubject `
            -Body "$alertCount job su $($vbrJobs.Count) in stato critico. Vedi report allegato." `
            -Attachments $htmlPath -SmtpServer $smtpServer -Port $smtpPort -UseSsl -Credential $cred
        Write-Log "Email inviata a $emailTo."
    } catch {
        Write-Log "Errore invio email: $_" "ERROR"
    }
}

Write-Log "=== Script completato ==="
