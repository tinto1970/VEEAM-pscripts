# VeeamLogAnonymizer

Anonymizes a **Veeam Backup & Replication** support log bundle (the zip produced by
*Help → Support Information → Export logs*) so that it can be analysed with an AI tool or forwarded to a
third party **without exposing** server names, IP addresses, users, domains, job / repository / bucket
names, access keys, SIDs, MAC addresses and similar data.

It runs on Windows with nothing to install: **Windows PowerShell 5.1** (available on every Windows
Server 2016+) or **PowerShell 7**. The engine is written in C# and compiled on the fly by PowerShell
(`Add-Type`).

## Credits

This project was inspired by the work of **Julien Mousqueton** ([@JMousqueton](https://github.com/JMousqueton)),
who published the first Veeam log anonymization scripts:

- [JMousqueton/VeeamLogAnonymizer](https://github.com/JMousqueton/VeeamLogAnonymizer)
- [JMousqueton/VBRLogAnonymizer](https://github.com/JMousqueton/VBRLogAnonymizer)
- [Introducing a Veeam Backup & Replication Log Anonymization Script](https://community.veeam.com/yara-and-script-library-67/introducing-a-veeam-backup-replication-log-anonymization-script-5696)
  (Veeam Community)

Many thanks to Julien for the idea and for sharing it with the community. This is a new implementation, not
a fork. Julien's scripts apply a fixed set of regular expressions. This one **learns the sensitive names from
the bundle itself**, replaces them consistently everywhere, and then checks the output for leaks.

## Files

| File | Purpose |
|---|---|
| `Invoke-VeeamLogAnonymizer.ps1` | Main script (anonymize, discover-only, restore) |
| `VeeamLogAnonymizer.Engine.cs` | Anonymization engine (C#, compiled at run time) |
| `anonymizer.config.json` | Optional configuration, loaded automatically from the script folder |
| `Anonymize-VeeamLogs.cmd` | Drag & drop launcher (uses `pwsh` if installed, otherwise `powershell`) |

## Quick start

Drag the log bundle zip onto `Anonymize-VeeamLogs.cmd`, or run:

```powershell
.\Invoke-VeeamLogAnonymizer.ps1 -InputPath .\2026-11-04T165607_VeeamBackupLogs.zip
```

If the script was downloaded from the internet, unblock it first (`Get-ChildItem | Unblock-File`) or use
the `.cmd` launcher, which runs it with `-ExecutionPolicy Bypass`.

The following files are created next to the input:

| File | Content | Share it? |
|---|---|---|
| `<name>_ANON.zip` | anonymized bundle (same structure, nested zip/gz archives included) | **Yes**, this is the only one |
| `<name>_ANON.mapping.PRIVATE.tsv` | original ↔ placeholder table | **No** |
| `<name>_ANON.report.PRIVATE.txt` | statistics, checks, leak check | **No** (it contains the original values) |

If real names are still found as whole words in the output, the script reports it in red at the end of the
run. Read the report before sharing the bundle.

## How it works

1. **Extraction**: the main zip and every nested archive (`.zip`, `.gz`).
2. **Discovery**: all logs *and all file/folder names* are scanned to learn sensitive names from
   reliable contexts: URLs, UNC paths (`\\server\share`), `Host 'x'`, `host:port`, `DOMAIN\user`, computer
   accounts (`DOMAIN\PC$`), e-mail addresses, `CN=` / `DC=`, FQDNs with learned domain suffixes,
   `RepositoryName=`, `Job [x]`, job folder names, `Task.<vm>.log`, vSphere inventory paths
   (`vcenter\datacenter\cluster\vm`), `[datastore] vm/vm.vmx`, `name 'x', ref 'datastore-85'`, S3 access
   keys, unmasked passwords / secrets, `/home/<user>`, `C:\Users\<user>`, and more.
3. **Consistent replacement** in file contents and paths: the same name always becomes the same placeholder,
   so the logs can still be analysed ("host003 cannot reach repo01").
4. **Leak check**: the output is re-read looking for every original value, also as a substring. The report
   separates:
   - **A) whole words**: real leaks to fix;
   - **B) only inside longer words** (e.g. a `corp` domain inside `Corporate`): usually false positives.

Example mapping (all values below are fictitious):

| Data | Original | Becomes |
|---|---|---|
| Hostname / FQDN | `srv-vbr01`, `SRV-VBR01`, `srv-vbr01.corp` | `host017`, `HOST017`, `host017.domain02` |
| Domain | `contoso.lan`, `DC=contoso,DC=lan`, `CONTOSO\` | `domain01.lan`, `DC=domain01,DC=lan`, `DOMAIN01\` |
| Private IPv4 | `172.16.10.21`, `172.16.10.50` | `10.200.0.21`, `10.200.0.50` (same /24 → same fake /24, last octet kept) |
| Public IPv4 | `81.2.69.142` | `203.0.113.142` (RFC 5737 documentation range) |
| IPv6 | `fe80::1c2b:3a4d:5e6f:7081` | `fe80::2` |
| IP-like versions | `13.1.1.18`, `Version=10.0.0.0` | **unchanged** (detected by context) |
| Users | `jdoe`, `john.doe@contoso.lan` | `user002`, `user001@domain01.lan` |
| Job / repository / bucket | `Linux-VMs Daily`, `s3-offsite-veeamrepo01` | `job0xx`, `repo01` |
| VM / datastore / cluster | `web01`, `esx01-datastore1` | `vm0xx`, `datastore0x` |
| Access key | `AKIAEXAMPLE0KEY12345` | `ANONACCESSKEY0000001` |
| Domain SID | `S-1-5-21-1111111111-2222222222-3333333333-500` | `S-1-5-21-1000000000-1000000000-1000000001-500` |
| MAC | `00:50:56:12:34:56` | `00:50:56:A0:00:01` (vendor OUI kept) |
| Base64 / JWT | `c3J2LXZicjAxXEFkbWluaXN0cmF0b3I=` | decoded, anonymized and re-encoded; JWT signature removed |
| Certificate thumbprint | `5A3F9C27E0B14D86A1C3F07B92E4D5A6C8B10F3E` | `AA00000000000000000000000000000000000001` (same length and format) |
| SSL / SSH fingerprint | `ssh-rsa q8Zk3...vQk`, `46:D3:8D:...:22` | `ssh-rsa ANONFINGERPRINT000...02`, `AA:00:00:...:03` |
| Database name | `DbName="SalesERP"`, `SalesERP_log`, `SalesERP_001.mdf` | `db001`, `db001_log`, `db001_001.mdf` (system and Veeam databases kept) |
| SQL Server named instance | `SQL01\FINANCE` | `host004\SQLINST01` (`MSSQLSERVER`, `SQLEXPRESS`, `VEEAMSQL*` kept) |
| Microsoft 365 tenant | `contoso.onmicrosoft.com`, `contoso-my.sharepoint.com` | `tenant01.onmicrosoft.com`, `tenant01-my.sharepoint.com` |
| Entra ID / Azure IDs | `TenantId: 3f2504e0-4f89-...` | `TenantId: a0a0a0a0-0000-4000-8000-000000000001` |

Special cases handled: names written with the Veeam file-name escaping (`s3_Boffsite_B...`), names
truncated by Veeam with a random suffix (`...veeamrep_x7kq`), names glued to other text
(`web01D2026-09-15T...vbk`, `esx2veeamworker`), space / underscore variants (`web01 Backup` /
`web01_Backup`).

## Coverage of Veeam KB2462

Veeam [KB2462](https://www.veeam.com/kb2462) lists the kinds of sensitive data that Veeam logs can contain.
This is how each one is handled:

| KB2462 category | Handled | How |
|---|---|---|
| User names, Microsoft 365 user mailbox / group addresses | ✅ | `DOMAIN\user`, `user@domain`, profile paths, keyword contexts |
| Hosts, FQDNs, NetBIOS names, IPv4 / IPv6 addresses | ✅ | learned names + domain suffixes; IPs preserve subnet relationships |
| VMs, datastores, clusters, VM file names and paths | ✅ | vSphere / Hyper-V / Proxmox inventory contexts, `.vmx` paths, task log names |
| Backup paths and backup file names | ✅ partly | job, repository, VM and host names inside paths are replaced; other folder names are not |
| SQL Server database and instance names | ✅ | `DbName=`, `LogicalName=`, `Initial Catalog=`, `Instance=` (system DBs and default instances kept) |
| Oracle SID / global name, PostgreSQL, MongoDB replica set, SAP HANA, Exchange / SharePoint databases | ✅ | `ORACLE_SID=`, `GlobalName=`, `database "x"`, `ReplicaSet=`, `TenantDatabase=`, `ContentDatabase=`, `MailboxDatabase=` |
| SSH host fingerprints | ✅ | `ssh-rsa <fingerprint>`, `fingerprint: ...` |
| Certificate thumbprints | ✅ | `thumbprint` / `fingerprint` contexts, hex with or without separators |
| Microsoft 365 tenant, SharePoint site URLs | ✅ | `<tenant>.onmicrosoft.com`, `<tenant>(-my).sharepoint.com` |
| Entra ID application / tenant / subscription IDs | ✅ | GUIDs after `TenantId`, `ApplicationId`, `AppId`, `client_id`, `SubscriptionId`, `login.microsoftonline.com/<id>` |
| Passwords, keys, tokens (not in the KB, but they happen) | ✅ | `password=`, access keys, `Bearer`, JWT, Base64 blobs |
| SQL / Oracle / PostgreSQL / MongoDB / SAP HANA **query results** | ❌ | free text: not detectable reliably |
| SSH **script and command output** | ❌ | free text: not detectable reliably |
| Exchange item subjects, SharePoint / OneDrive file and list names, Teams team / channel names | ❌ | free text: use `-ExtraTerms` |
| File copy / file-to-tape paths, exported data paths | ⚠️ | only the known names inside them are replaced |
| License information, hardware configuration | ⚠️ | license holder and hardware details are not touched |

If your bundle contains logs from application-aware processing with transaction log backup, SSH scripts, or Veeam
Backup for Microsoft 365, read the report and the bundle more carefully before sharing it.

## Useful options

```powershell
# Customer name or other terms to always hide (also inside longer words)
.\Invoke-VeeamLogAnonymizer.ps1 -InputPath .\bundle.zip -ExtraTerms 'Acme','MilanSite' -SubstringTerms 'acme'

# False positives that must not be touched
.\Invoke-VeeamLogAnonymizer.ps1 -InputPath .\bundle.zip -KeepTerms 'BackupServer'

# Discovery only: see what would be anonymized (report + mapping), without producing the output bundle
.\Invoke-VeeamLogAnonymizer.ps1 -InputPath .\bundle.zip -DiscoverOnly
```

The same settings can be stored in `anonymizer.config.json` (lines starting with `//` are comments):

```json
{
    "ExtraTerms": [ "Acme", { "Original": "acme", "Anonymized": "customer01", "Substring": true } ],
    "KeepTerms": [ "BackupServer" ],
    "WhitelistDomains": [ "backblazeb2.com" ],
    "AnonymizePublicIPs": true,
    "AnonymizeMac": true,
    "AnonymizeIPv6": true,
    "AnonymizeBase64": true,
    "MinBareTermLength": 3
}
```

Other parameters: `-OutputPath` (zip, or a folder if it does not end with `.zip`), `-MappingPath`,
`-ConfigPath`, `-WorkDir` (temporary extraction folder), `-NoLeakCheck`, `-KeepWorkDir`.
Run `Get-Help .\Invoke-VeeamLogAnonymizer.ps1 -Full` for the complete list.

**Several bundles from the same environment**: pass the same `-MappingPath` to every run. The existing
mapping is loaded and extended, so `host017` stays the same server across all bundles.

```powershell
.\Invoke-VeeamLogAnonymizer.ps1 -InputPath .\bundle2.zip -MappingPath .\customer.mapping.PRIVATE.tsv
```

## De-anonymizing the AI answer

```powershell
.\Invoke-VeeamLogAnonymizer.ps1 -Restore -MappingPath .\bundle_ANON.mapping.PRIVATE.tsv -InputPath .\ai-answer.txt
.\Invoke-VeeamLogAnonymizer.ps1 -Restore -MappingPath .\bundle_ANON.mapping.PRIVATE.tsv -Text "host017 cannot reach 10.200.0.21"
# -> "srv-vbr01 cannot reach 172.16.10.21"
```

## Limitations (please read)

- The anonymization is **heuristic**. It cuts the risk a lot, but it cannot guarantee 100%. Before
  forwarding a bundle to third parties, read the *LEAK CHECK* section of the report. If needed, add terms
  with `-ExtraTerms` / `-SubstringTerms` and run again.
- Names that never appear in a recognizable context (for example a VM mentioned only in free text) can
  escape discovery. Add them manually.
- Veeam GUIDs are not changed. They do not identify the customer, and they are needed to correlate the logs.
  Only GUIDs that identify the customer's cloud (Entra ID tenant, application, subscription) are replaced.
- Certificate thumbprints are all replaced, including those of public root CAs. If you need to troubleshoot
  a certificate chain, add the relevant thumbprints with `-KeepTerms`.
- Query results, script output and Microsoft 365 content (mail subjects, file names, Teams names) are free text
  and are not detected. See [Coverage of Veeam KB2462](#coverage-of-veeam-kb2462).
- Binary files in the bundle are copied unchanged and counted in the report.
- Indicative timing: about 3–4 minutes for a bundle of 1.3 GB uncompressed.

## Disclaimer

Provided as is, without warranty. You are responsible for checking the anonymized output before sharing it.
