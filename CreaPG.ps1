#Creazione PG
#v1.0
#
#$pwd = Read-Host "Password VBR" -AsSecureString
#.\Create-VeeamPG.ps1 -PGName "Nome-PG" -Machines "macchina01","macchina02", .... -CredName "dominio\utenza" -VBRServer "ServerVBR" -VBRUser "dominio\veeamadmin" -VBRPassword $pwd



param(
    [Parameter(Mandatory = $true)]
    [string]$PGName,

    [Parameter(Mandatory = $true)]
    [string[]]$Machines,                 # Lista di host/DNS/IP

    [Parameter(Mandatory = $true)]
    [string]$CredName,                   # Nome credenziale registrata in Veeam (per i computer)

    [Parameter(Mandatory = $true)]
    [string]$VBRServer,                  # Veeam Backup & Replication server (FQDN/IP)

    [int]$VBRPort = 9392,                # Porta console VBR

    [string]$VBRUser,                    # (Opz.) utente per Connect-VBRServer
    [SecureString]$VBRPassword,          # (Opz.) password per Connect-VBRServer

    [switch]$Sync                        # (Opz.) rimuove dal PG ciò che NON è nella lista
)

# --- Carica il modulo PowerShell di Veeam 12.x (dll della Console) ---
try {
    $modulePath = "C:\Program Files\Veeam\Backup and Replication\Console\Veeam.Backup.PowerShell.dll"
    if (Test-Path $modulePath) {
        Import-Module $modulePath -DisableNameChecking -ErrorAction Stop
    } else {
        # fallback per ambienti più vecchi
        Add-PSSnapin VeeamPSSnapIn -ErrorAction Stop
    }
} catch {
    Write-Error "Impossibile caricare il modulo/snapin Veeam. Dettagli: $($_.Exception.Message)"
    exit 1
}

# --- Connessione al VBR Server ---
try {
    if ($VBRUser -and $VBRPassword) {
        $plainPwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($VBRPassword)
        )
        Connect-VBRServer -Server $VBRServer -Port $VBRPort -User $VBRUser -Password $plainPwd -ErrorAction Stop | Out-Null
    } else {
        Connect-VBRServer -Server $VBRServer -Port $VBRPort -ErrorAction Stop | Out-Null
    }
} catch {
    Write-Error "Connessione a '${VBRServer}:${VBRPort}' fallita. Dettagli: $($_.Exception.Message)"
    exit 1
}

try {
    Write-Host "=== Creazione/Aggiornamento Protection Group ==="
    Write-Host "Server VBR: ${VBRServer}:${VBRPort}"
    Write-Host "PG: $PGName"
    Write-Host "Macchine: $($Machines -join ', ')"
    Write-Host "Credenziali computer: $CredName"
    if ($Sync) { Write-Host "Sync: ATTIVO (il gruppo verrà allineato alla lista)" }
    Write-Host "==============================================="

    # --- Recupera credenziali Veeam per i computer ---
    $cred = Get-VBRCredentials -Name $CredName
    if (-not $cred) { throw "Credenziali '$CredName' non trovate in Veeam." }

    # --- Opzioni di deployment (12.3): installa AGENT, nessun plugin ---
    # Nota: NON specificare -InstallApplicationPlugins => i plugin (es. RMAN) non vengono installati
    $dist = Get-VBRServer -Name $VBRServer -ErrorAction SilentlyContinue
    if ($dist) {
        $deployment = New-VBRProtectionGroupDeploymentOptions -DistributionServer $dist -InstallAgent
    } else {
        $deployment = New-VBRProtectionGroupDeploymentOptions -InstallAgent
    }

    # --- Funzioni di supporto ---
    function New-DesiredCustomCreds([string[]]$hosts, $ccreds) {
        $list = @()
        foreach ($h in $hosts) {
            $list += New-VBRIndividualComputerCustomCredentials -HostName $h -Credentials $ccreds
        }
        return $list
    }

    # --- Crea/Aggiorna Protection Group con container "Individual computers" ---
    $pg = Get-VBRProtectionGroup -Name $PGName -ErrorAction SilentlyContinue

    if ($pg) {
        Write-Host "Il Protection Group '$PGName' esiste: aggiorno container e deployment options…"

        # Stato attuale
        $current = @()
        if ($pg.Container -and $pg.Container.CustomCredentials) {
            $current = $pg.Container.CustomCredentials
        }

        # Costruisci la lista desiderata
        $desired = New-DesiredCustomCreds -hosts $Machines -ccreds $cred

        if ($Sync) {
            # Allinea 1:1 al set desiderato
            $newList = $desired
        } else {
            # Unione: mantieni gli esistenti + aggiungi i nuovi mancanti
            $map = @{}
            foreach ($c in $current) { $map[$c.HostName.ToLower()] = $c }
            foreach ($d in $desired) { $map[$d.HostName.ToLower()] = $d }
            $newList = $map.Values
        }

        # Aggiorna container e opzioni di deployment
        $newContainer = Set-VBRIndividualComputerContainer -Container $pg.Container -CustomCredentials $newList
        Set-VBRProtectionGroup -ProtectionGroup $pg -Container $newContainer -DeploymentOptions $deployment | Out-Null
    }
    else {
        Write-Host "Creo un nuovo Protection Group '$PGName'…"
        $customCreds = New-DesiredCustomCreds -hosts $Machines -ccreds $cred
        $container   = New-VBRIndividualComputerContainer -CustomCredentials $customCreds

        # (ScheduleOptions è opzionale; se vuoi discovery periodico posso aggiungerlo)
        $pg = Add-VBRProtectionGroup -Name $PGName -Container $container -DeploymentOptions $deployment
    }


    Write-Host "✅ Completato: Protection Group '$PGName' pronto."
}
catch {
    Write-Error "Errore: $($_.Exception.Message)"
    exit 1
}
finally {
    try { Disconnect-VBRServer | Out-Null } catch {}
}
