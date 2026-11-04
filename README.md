# VEEAM-pscripts

# ultimojob.ps1
https://blog.tinivelli.com/veeam-ps-gallery-last-backup-796390f8f0fc

# creaPG.ps1
This script Creates a Protection Group with N machines Install Agents (no CBT for Windows) Does not Install Plug-Ins Does not start a rescan/installation Does not perform automatic reboot Usage:

$pwd = Read-Host "Password VBR" -AsSecureString .\Create-VeeamPG.ps1 -PGName "Nome-PG" -Machines "macchina01","macchina02", .... -CredName "dominio\utenza" -VBRServer "ServerVBR" -VBRUser "dominio\veeamadmin" -VBRPassword $pwd

# Get-VB365CertificateReport
Lists the certificates used by the Veeam Backup for Microsoft 365 organizations and reports the expiring ones, with an optional alert email. Meant to run daily as a scheduled task on the VB365 server. Script and documentation: [Get-VB365CertificateReport/](Get-VB365CertificateReport/)

# VeeamLogAnonymizer
Anonymizes a Veeam Backup & Replication support log bundle (server names, IPs, users, domains, jobs, repositories, keys...) so it can be analysed with AI tools or forwarded safely. It learns the sensitive names from the bundle, replaces them consistently and checks the output for leaks. Inspired by Julien Mousqueton's VeeamLogAnonymizer. Script and documentation: [VeeamLogAnonymizer/](VeeamLogAnonymizer/)
