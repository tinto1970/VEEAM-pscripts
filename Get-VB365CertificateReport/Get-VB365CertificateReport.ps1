<#
.SYNOPSIS
    Elenca i certificati usati dalle organizzazioni di Veeam Backup for Microsoft 365
    e segnala quelli in scadenza, con email di allarme opzionale.

.DESCRIPTION
    Per ogni organizzazione attiva (con almeno un job di backup abilitato) legge
    i certificati usati per Exchange, SharePoint e dalle applicazioni di backup
    aggiuntive. Cerca ogni thumbprint negli store del computer (Cert:\LocalMachine)
    e riporta emittente, Friendly Name, soggetto e data di scadenza.

    Stato di ogni certificato:
        OK           scade tra più di -WarningDays giorni
        IN SCADENZA  scade entro -WarningDays giorni (default 20)
        SCADUTO      già scaduto
        SCONOSCIUTA  thumbprint non trovato negli store: scadenza non leggibile

    Se è indicato -MailTo e ci sono certificati IN SCADENZA o SCADUTI (e, con
    -AlertOnUnknown, anche SCONOSCIUTA), invia un'email di allarme con il dettaglio.

    Codice di uscita, utile per attività pianificate e sistemi di monitoraggio:
        0  nessun allarme
        1  almeno un certificato in allarme
        2  errore durante l'esecuzione

.PARAMETER Server
    Server VB365 a cui connettersi (default: localhost).

.PARAMETER WarningDays
    Soglia in giorni per lo stato IN SCADENZA (default: 20).

.PARAMETER IncludeInactive
    Include anche le organizzazioni senza job di backup abilitati.

.PARAMETER AlertOnUnknown
    Considera in allarme anche i certificati con scadenza sconosciuta.

.PARAMETER CsvPath
    Salva il report anche in CSV.

.PARAMETER MailTo
    Uno o più destinatari dell'email di allarme. Richiede -MailFrom e -SmtpServer.

.PARAMETER MailFrom
    Mittente dell'email.

.PARAMETER SmtpServer
    Server SMTP.

.PARAMETER SmtpPort
    Porta SMTP (default: 25).

.PARAMETER UseSsl
    Usa TLS per la connessione SMTP.

.PARAMETER SmtpCredential
    Credenziali SMTP (PSCredential).

.PARAMETER SmtpCredentialFile
    File con credenziali SMTP salvate con Export-Clixml, per le attività pianificate.
    Va creato con lo stesso utente e sullo stesso computer che eseguono lo script:
        Get-Credential | Export-Clixml C:\Scripts\smtp.cred

.PARAMETER AlwaysSendMail
    Invia l'email con il report anche quando non ci sono allarmi.

.PARAMETER PassThru
    Restituisce le righe del report come oggetti, per elaborarle in pipeline.

.EXAMPLE
    .\Get-VB365CertificateReport.ps1

.EXAMPLE
    .\Get-VB365CertificateReport.ps1 -WarningDays 30 -IncludeInactive -CsvPath C:\Reports\vb365-cert.csv

.EXAMPLE
    .\Get-VB365CertificateReport.ps1 -MailTo backup-team@contoso.com -MailFrom vb365@contoso.com `
        -SmtpServer smtp.contoso.com -SmtpPort 587 -UseSsl -SmtpCredentialFile C:\Scripts\smtp.cred

.NOTES
    Richiede il modulo Veeam.Archiver.PowerShell (installato con VB365).
    Va eseguito sul server VB365 (o su un computer che abbia gli stessi certificati
    negli store), con privilegi sufficienti a leggere Cert:\LocalMachine.
#>

[CmdletBinding()]
param(
    [string]$Server = 'localhost',
    [ValidateRange(1, 3650)][int]$WarningDays = 20,
    [switch]$IncludeInactive,
    [switch]$AlertOnUnknown,
    [string]$CsvPath,
    [string[]]$MailTo,
    [string]$MailFrom,
    [string]$SmtpServer,
    [int]$SmtpPort = 25,
    [switch]$UseSsl,
    [pscredential]$SmtpCredential,
    [string]$SmtpCredentialFile,
    [switch]$AlwaysSendMail,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$ComputerName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }

# --------------------------------------------------------------------------
#  Funzioni
# --------------------------------------------------------------------------

function Get-Prop {
    # Legge una proprietà annidata senza errori se manca (es. 'Organization.Name')
    param($Object, [string]$Name)
    $cur = $Object
    foreach ($p in $Name.Split('.')) {
        if ($null -eq $cur) { return $null }
        $prop = $cur.PSObject.Properties[$p]
        if (-not $prop) { return $null }
        $cur = $prop.Value
    }
    return $cur
}

function Find-Certificate {
    # Cerca un certificato per thumbprint in tutti gli store di LocalMachine (con cache)
    param([string]$Thumbprint, [hashtable]$Cache)
    if ($Cache.ContainsKey($Thumbprint)) { return $Cache[$Thumbprint] }
    $cert = Get-ChildItem -Path Cert:\LocalMachine -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.PSObject.Properties['Thumbprint'] -and $_.Thumbprint -eq $Thumbprint } |
            Select-Object -First 1
    $Cache[$Thumbprint] = $cert
    return $cert
}

function Get-OrgCertificateUsage {
    # Certificati di un'organizzazione: Exchange, SharePoint e applicazioni di backup.
    # Exchange e SharePoint con la stessa app e lo stesso certificato diventano una riga.
    param($Org)
    $rows = [System.Collections.Generic.List[object]]::new()

    $add = {
        param([string]$Usage, [string]$AppId, [string]$Thumb, [string]$AppName)
        if (-not $Thumb) { return }
        $Thumb = ($Thumb -replace '\s', '').ToUpper()
        $same = $rows | Where-Object { $_.Thumbprint -eq $Thumb -and $_.ApplicationId -eq $AppId } | Select-Object -First 1
        if ($same) { $same.Usage = "$($same.Usage), $Usage"; return }
        $rows.Add([pscustomobject]@{ Usage = $Usage; ApplicationId = $AppId; AppName = $AppName; Thumbprint = $Thumb })
    }

    foreach ($part in @(@('Exchange', 'Office365ExchangeConnectionSettings'), @('SharePoint', 'Office365SharePointConnectionSettings'))) {
        $cs = Get-Prop $Org $part[1]
        if ($cs) { & $add $part[0] ([string](Get-Prop $cs 'ApplicationId')) ([string](Get-Prop $cs 'ApplicationCertificateThumbprint')) $null }
    }
    foreach ($app in @(Get-Prop $Org 'BackupApplications')) {
        if ($app) {
            & $add 'BackupApplication' ([string](Get-Prop $app 'ApplicationId')) ([string](Get-Prop $app 'ApplicationCertificateThumbprint')) `
                ([string](Get-Prop $app 'DisplayName'))
        }
    }
    return $rows.ToArray()
}

function Get-StatusColor {
    param([string]$Status)
    switch ($Status) {
        'OK'          { 'Green' }
        'IN SCADENZA' { 'Yellow' }
        'SCADUTO'     { 'Red' }
        default       { 'DarkYellow' }
    }
}

function Write-Report {
    # Tabella a colori sulla console
    param($Rows)
    $fmt = '{0,-38} {1,-22} {2,-24} {3,-26} {4,-10} {5,6}  {6}'
    Write-Host ''
    Write-Host ($fmt -f 'Organizzazione', 'Uso', 'Friendly Name', 'Emittente', 'Scadenza', 'Giorni', 'Stato') -ForegroundColor Cyan
    Write-Host ('-' * 142) -ForegroundColor DarkGray
    foreach ($r in $Rows) {
        $cut = { param($s, $n) if (-not $s) { '-' } elseif ($s.Length -gt $n) { $s.Substring(0, $n - 1) + '…' } else { $s } }
        $issuer = if ($r.Issuer) { ($r.Issuer -replace '^CN=([^,]+).*$', '$1') } else { $null }
        $org = if ($r.Active) { $r.Organization } else { "$($r.Organization) (inattiva)" }
        $line = $fmt -f (& $cut $org 38), (& $cut $r.Usage 22), (& $cut $r.FriendlyName 24), (& $cut $issuer 26),
                       $(if ($r.NotAfter) { $r.NotAfter.ToString('yyyy-MM-dd') } else { '-' }),
                       $(if ($null -ne $r.DaysLeft) { $r.DaysLeft } else { '-' }), $r.Status
        Write-Host $line -ForegroundColor (Get-StatusColor $r.Status)
    }
    Write-Host ''
}

function ConvertTo-HtmlReport {
    # Corpo HTML dell'email
    param($Rows, [int]$AlertCount)
    $enc = { param($s) if ($null -eq $s -or $s -eq '') { '-' } else { [System.Net.WebUtility]::HtmlEncode([string]$s) } }
    $bg  = @{ 'OK' = '#e8f5e9'; 'IN SCADENZA' = '#fff8e1'; 'SCADUTO' = '#ffebee'; 'SCONOSCIUTA' = '#f5f5f5' }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<html><body style='font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#222'>")
    [void]$sb.Append("<h3 style='margin:0 0 8px'>Certificati Veeam Backup for Microsoft 365 &ndash; $(& $enc $ComputerName)</h3>")
    [void]$sb.Append("<p style='margin:0 0 12px'>$AlertCount certificati in allarme (soglia $WarningDays giorni). Report del $((Get-Date).ToString('yyyy-MM-dd HH:mm')).</p>")
    [void]$sb.Append("<table cellpadding='6' cellspacing='0' style='border-collapse:collapse;border:1px solid #ccc'>")
    [void]$sb.Append("<tr style='background:#37474f;color:#fff;text-align:left'><th>Stato</th><th>Organizzazione</th><th>Uso</th><th>Friendly Name</th><th>Soggetto</th><th>Emittente</th><th>Scadenza</th><th>Giorni</th><th>Thumbprint</th></tr>")
    foreach ($r in $Rows) {
        $color = if ($bg.ContainsKey($r.Status)) { $bg[$r.Status] } else { '#ffffff' }
        $exp = if ($r.NotAfter) { $r.NotAfter.ToString('yyyy-MM-dd') } else { '-' }
        $days = if ($null -ne $r.DaysLeft) { $r.DaysLeft } else { '-' }
        [void]$sb.Append("<tr style='background:$color;border-top:1px solid #ddd'>")
        $org = $(& $enc $r.Organization) + $(if (-not $r.Active) { " <span style='color:#888'>(inattiva)</span>" } else { '' })
        [void]$sb.Append("<td style='white-space:nowrap'><b>$(& $enc $r.Status)</b></td><td>$org</td><td>$(& $enc $r.Usage)</td>")
        [void]$sb.Append("<td>$(& $enc $r.FriendlyName)</td><td>$(& $enc $r.Subject)</td><td>$(& $enc $r.Issuer)</td>")
        [void]$sb.Append("<td style='white-space:nowrap'>$exp</td><td style='text-align:right'>$days</td><td style='font-family:Consolas,monospace;font-size:11px'>$(& $enc $r.Thumbprint)</td></tr>")
    }
    [void]$sb.Append('</table>')
    [void]$sb.Append("<p style='color:#666;font-size:11px;margin-top:12px'>SCONOSCIUTA: il certificato non è negli store del server, la scadenza va verificata nell'app registration in Entra ID.</p>")
    [void]$sb.Append('</body></html>')
    return $sb.ToString()
}

# --------------------------------------------------------------------------
#  Esecuzione
# --------------------------------------------------------------------------

try {
    if ($MailTo -and (-not $MailFrom -or -not $SmtpServer)) {
        throw 'Con -MailTo servono anche -MailFrom e -SmtpServer.'
    }
    if ($SmtpCredentialFile) { $SmtpCredential = Import-Clixml -Path $SmtpCredentialFile }

    Import-Module Veeam.Archiver.PowerShell -ErrorAction Stop
    Connect-VBOServer -Server $Server

    # Organizzazioni attive = con almeno un job di backup abilitato
    $jobs = @(Get-VBOJob)
    $activeOrgs = @($jobs | Where-Object { Get-Prop $_ 'IsEnabled' } | ForEach-Object { Get-Prop $_ 'Organization.Name' } |
                    Where-Object { $_ } | Select-Object -Unique)

    $cache = @{}
    $now = Get-Date
    $report = [System.Collections.Generic.List[object]]::new()
    $noCert = @(); $skipped = @()

    foreach ($org in @(Get-VBOOrganization)) {
        $active = $activeOrgs -contains $org.Name
        if (-not $active -and -not $IncludeInactive) { $skipped += $org.Name; continue }

        $usages = @(Get-OrgCertificateUsage -Org $org)
        if ($usages.Count -eq 0) { $noCert += $org.Name; continue }

        foreach ($u in $usages) {
            $cert = Find-Certificate -Thumbprint $u.Thumbprint -Cache $cache
            $row = [pscustomobject]@{
                Organization  = $org.Name
                Active        = $active
                Usage         = $u.Usage
                ApplicationId = $u.ApplicationId
                AppName       = $u.AppName
                Thumbprint    = $u.Thumbprint
                FriendlyName  = $null
                Subject       = $null
                Issuer        = $null
                NotAfter      = $null
                DaysLeft      = $null
                Store         = $null
                Status        = 'SCONOSCIUTA'
            }
            if ($cert) {
                $row.FriendlyName = $(if ($cert.FriendlyName) { $cert.FriendlyName } else { $null })
                $row.Subject      = $cert.Subject
                $row.Issuer       = $cert.Issuer
                $row.NotAfter     = $cert.NotAfter
                $row.DaysLeft     = [int][Math]::Truncate(($cert.NotAfter - $now).TotalDays)   # giorni interi mancanti (negativi se scaduto)
                $row.Store        = ($cert.PSParentPath -replace '^.*::', '')
                $row.Status       = if ($cert.NotAfter -lt $now) { 'SCADUTO' }
                                    elseif ($row.DaysLeft -lt $WarningDays) { 'IN SCADENZA' }
                                    else { 'OK' }
            }
            $report.Add($row)
        }
    }

    # Ordine: prima gli allarmi, poi per scadenza
    $order = @{ 'SCADUTO' = 0; 'IN SCADENZA' = 1; 'SCONOSCIUTA' = 2; 'OK' = 3 }
    $rows = @($report | Sort-Object @{ e = { $order[$_.Status] } }, @{ e = { if ($_.NotAfter) { $_.NotAfter } else { [datetime]::MaxValue } } }, Organization)

    $alertStatus = @('SCADUTO', 'IN SCADENZA') + $(if ($AlertOnUnknown) { 'SCONOSCIUTA' } else { @() })
    $alerts = @($rows | Where-Object { $alertStatus -contains $_.Status })

    if ($rows.Count -gt 0) { Write-Report -Rows $rows }
    else { Write-Host "`nNessun certificato trovato nelle organizzazioni considerate.`n" -ForegroundColor Yellow }

    Write-Host ("Certificati: {0}  |  in allarme: {1}  |  soglia: {2} giorni" -f $rows.Count, $alerts.Count, $WarningDays)
    if ($noCert)  { Write-Host "Organizzazioni senza certificato (altro tipo di autenticazione): $($noCert -join ', ')" -ForegroundColor DarkGray }
    if ($skipped) { Write-Host "Organizzazioni escluse perché senza job abilitati (usare -IncludeInactive): $($skipped -join ', ')" -ForegroundColor DarkGray }
    $unknown = @($rows | Where-Object { $_.Status -eq 'SCONOSCIUTA' })
    if ($unknown -and -not $AlertOnUnknown) {
        Write-Host "$($unknown.Count) certificati non trovati negli store: scadenza da verificare in Entra ID (-AlertOnUnknown per includerli negli allarmi)" -ForegroundColor DarkYellow
    }

    if ($CsvPath) {
        $rows | Select-Object Status, Organization, Active, Usage, AppName, ApplicationId, FriendlyName, Subject, Issuer,
                              @{ n = 'NotAfter'; e = { if ($_.NotAfter) { $_.NotAfter.ToString('yyyy-MM-dd') } } }, DaysLeft, Store, Thumbprint |
            Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "Report salvato in $CsvPath"
    }

    if ($MailTo -and ($alerts.Count -gt 0 -or $AlwaysSendMail)) {
        $subject = if ($alerts.Count -gt 0) {
            "[VB365] $($alerts.Count) certificati in scadenza o scaduti su $ComputerName"
        } else {
            "[VB365] Report certificati ${ComputerName}: nessun allarme"
        }
        $mail = @{
            To         = $MailTo
            From       = $MailFrom
            Subject    = $subject
            Body       = ConvertTo-HtmlReport -Rows $rows -AlertCount $alerts.Count
            BodyAsHtml = $true
            SmtpServer = $SmtpServer
            Port       = $SmtpPort
            Encoding   = [System.Text.Encoding]::UTF8
            Priority   = $(if ($alerts.Count -gt 0) { 'High' } else { 'Normal' })
        }
        if ($UseSsl) { $mail.UseSsl = $true }
        if ($SmtpCredential) { $mail.Credential = $SmtpCredential }
        Send-MailMessage @mail -WarningAction SilentlyContinue
        Write-Host "Email inviata a $($MailTo -join ', ')" -ForegroundColor Cyan
    }
    elseif ($MailTo) {
        Write-Host 'Nessun allarme: email non inviata (-AlwaysSendMail per inviarla comunque)'
    }

    if ($PassThru) { $rows }
    exit $(if ($alerts.Count -gt 0) { 1 } else { 0 })
}
catch {
    Write-Host "ERRORE: $_" -ForegroundColor Red
    exit 2
}
