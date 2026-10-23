# Get-VB365CertificateReport

Script PowerShell che elenca i certificati usati dalle organizzazioni di **Veeam Backup for Microsoft 365** e segnala quelli in scadenza, con email di allarme opzionale.

Pensato per girare ogni giorno come attività pianificata sul server VB365: se un certificato scade entro la soglia (default **20 giorni**) o è già scaduto, invia un'email al team.

## Cosa fa

- Considera le organizzazioni **attive**, cioè con almeno un job di backup abilitato (`-IncludeInactive` per includere anche le altre)
- Per ogni organizzazione legge i certificati usati per Exchange, SharePoint e dalle applicazioni di backup aggiuntive
- Cerca ogni certificato negli store del computer (`Cert:\LocalMachine`) e riporta **emittente**, **Friendly Name**, soggetto e **data di scadenza**
- Mostra una tabella a colori, con gli allarmi in cima
- Invia un'email HTML solo se ci sono allarmi (oppure sempre, con `-AlwaysSendMail`)
- Restituisce un codice di uscita utilizzabile da attività pianificate e sistemi di monitoraggio

## Stati

| Stato | Significato | In allarme |
|---|---|---|
| `OK` | Scade tra più di `-WarningDays` giorni | No |
| `IN SCADENZA` | Scade entro `-WarningDays` giorni | Sì |
| `SCADUTO` | Già scaduto | Sì |
| `SCONOSCIUTA` | Thumbprint non trovato negli store: scadenza non leggibile | Solo con `-AlertOnUnknown` |

## Requisiti

| Requisito | Dettaglio |
|---|---|
| Veeam Backup for Microsoft 365 | v8.x |
| PowerShell | Windows PowerShell 5.1 sul server VB365 |
| Modulo | `Veeam.Archiver.PowerShell` (installato con VB365) |
| Permessi | Accesso a VB365 e lettura di `Cert:\LocalMachine` |
| Email | Un server SMTP raggiungibile dal server VB365 |

## Utilizzo

### Report a video

```powershell
.\Get-VB365CertificateReport.ps1
```

```text
Organizzazione                         Uso                    Friendly Name            Emittente                  Scadenza   Giorni  Stato
----------------------------------------------------------------------------------------------------------------------------------------------
fabrikam.onmicrosoft.com               BackupApplication      Aux Fabrikam             Contoso Issuing CA         2026-10-20     -3  SCADUTO
contoso.onmicrosoft.com                Exchange, SharePoint   Veeam M365 - Contoso 20… Contoso Issuing CA         2026-11-03     10  IN SCADENZA
northwind.onmicrosoft.com              Exchange               -                        -                          -               -  SCONOSCIUTA
fabrikam.onmicrosoft.com               Exchange, SharePoint   -                        Contoso Issuing CA         2027-08-20    300  OK

Certificati: 4  |  in allarme: 2  |  soglia: 20 giorni
Organizzazioni senza certificato (altro tipo di autenticazione): litware.onmicrosoft.com
Organizzazioni escluse perché senza job abilitati (usare -IncludeInactive): tailspin.onmicrosoft.com
```

### Soglia diversa, organizzazioni inattive e CSV

```powershell
.\Get-VB365CertificateReport.ps1 -WarningDays 30 -IncludeInactive -CsvPath C:\Reports\vb365-cert.csv
```

Il CSV usa il `;` come separatore, così si apre direttamente in Excel con impostazioni italiane.

### Email di allarme

```powershell
.\Get-VB365CertificateReport.ps1 `
    -MailTo backup-team@contoso.com, noc@contoso.com `
    -MailFrom vb365@contoso.com `
    -SmtpServer smtp.contoso.com -SmtpPort 587 -UseSsl `
    -SmtpCredentialFile C:\Scripts\smtp.cred
```

L'email ha priorità alta, un oggetto del tipo `[VB365] 2 certificati in scadenza o scaduti su VB365-SRV` e una tabella con tutti i certificati, colorata per stato.

### Oggetti in pipeline

```powershell
.\Get-VB365CertificateReport.ps1 -PassThru | Where-Object Status -ne 'OK'
```

## Parametri

| Parametro | Default | Descrizione |
|---|---|---|
| `-Server` | `localhost` | Server VB365 |
| `-WarningDays` | `20` | Soglia in giorni per lo stato `IN SCADENZA` |
| `-IncludeInactive` | | Include le organizzazioni senza job abilitati (segnate come "inattiva") |
| `-AlertOnUnknown` | | Considera in allarme anche i certificati con scadenza sconosciuta |
| `-CsvPath` | | Salva il report in CSV |
| `-MailTo` | | Destinatari dell'email (richiede `-MailFrom` e `-SmtpServer`) |
| `-MailFrom` | | Mittente |
| `-SmtpServer` | | Server SMTP |
| `-SmtpPort` | `25` | Porta SMTP |
| `-UseSsl` | | Connessione SMTP con TLS |
| `-SmtpCredential` | | Credenziali SMTP (`PSCredential`) |
| `-SmtpCredentialFile` | | Credenziali SMTP salvate con `Export-Clixml` |
| `-AlwaysSendMail` | | Invia l'email anche senza allarmi |
| `-PassThru` | | Restituisce le righe del report come oggetti |

## Codici di uscita

| Codice | Significato |
|---|---|
| `0` | Nessun allarme |
| `1` | Almeno un certificato in allarme |
| `2` | Errore (connessione a VB365, parametri, invio email) |

## Pianificazione giornaliera

### 1. Credenziali SMTP

Se il server SMTP richiede autenticazione, salva le credenziali **con lo stesso account che eseguirà l'attività**. Il file è cifrato con DPAPI e funziona solo per quell'utente su quel computer:

```powershell
Get-Credential | Export-Clixml C:\Scripts\smtp.cred
```

### 2. Attività pianificata

```powershell
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Get-VB365CertificateReport.ps1" ' +
    '-MailTo backup-team@contoso.com -MailFrom vb365@contoso.com ' +
    '-SmtpServer smtp.contoso.com -SmtpPort 587 -UseSsl -SmtpCredentialFile C:\Scripts\smtp.cred')
$trigger = New-ScheduledTaskTrigger -Daily -At 7:30
Register-ScheduledTask -TaskName 'VB365 - Controllo scadenza certificati' `
    -Action $action -Trigger $trigger -User 'CONTOSO\svc-vb365' -Password '<password>' -RunLevel Highest
```

Usa un account con accesso a VB365. Se scegli SYSTEM, il file delle credenziali SMTP va creato come SYSTEM, oppure usa un relay SMTP che non richiede autenticazione.

## Limiti

- **Scadenza sconosciuta:** la data di scadenza si legge solo se il certificato è negli store di `Cert:\LocalMachine` del server. Se VB365 conserva il certificato altrove, lo stato è `SCONOSCIUTA`. In quel caso controlla la scadenza nell'app registration in Entra ID (**Certificati e segreti**) e valuta `-AlertOnUnknown`.
- **Certificati condivisi:** un certificato usato da più organizzazioni compare una volta per ciascuna.
- **`Send-MailMessage`:** è il cmdlet standard di Windows PowerShell 5.1. Microsoft lo considera obsoleto ma è ancora disponibile; per SMTP moderni con OAuth serve un'altra soluzione.
- **Codifica del file:** lo script è salvato in UTF-8 con BOM, perché Windows PowerShell 5.1 mostri correttamente le lettere accentate. Se lo modifichi, mantieni questa codifica.
