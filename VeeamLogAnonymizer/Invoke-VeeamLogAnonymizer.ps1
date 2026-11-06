<#
.SYNOPSIS
    Anonymizes a Veeam Backup & Replication support log bundle (zip or folder) so that it can be
    analysed by an AI or forwarded without exposing server names, IP addresses, users, domains,
    job / repository / bucket names, access keys, SIDs, MAC addresses, ...

.DESCRIPTION
    Two-phase approach:
      1. Discovery  - every log (including nested .zip and .gz archives) and every file/folder name is
                      scanned to learn the sensitive names used in this environment (hostnames, FQDNs,
                      domains, users, jobs, repositories, buckets, VMs, inventory objects, keys...).
      2. Replacement - each discovered value is replaced consistently everywhere (content AND paths)
                      with a stable placeholder (host001, domain01.lan, user002, job003, repo01, ...).
                      IPv4 addresses are replaced preserving the subnet relationships (same /24 => same
                      fake /24, host octet preserved). Version numbers that look like IPs (13.1.1.18)
                      are detected by context and kept.
    Finally the output is re-scanned for any original value (substring match) and a leak report is
    written.

    Outputs (next to the input unless specified):
      <name>_ANON.zip                       -> the anonymized bundle: this is the only file to share
      <name>_ANON.mapping.PRIVATE.tsv       -> original <-> placeholder table. KEEP PRIVATE.
      <name>_ANON.report.PRIVATE.txt        -> report with leak check. KEEP PRIVATE (contains originals).

.PARAMETER InputPath
    Veeam log bundle: .zip file or extracted folder. In -Restore mode: a text file to de-anonymize.

.PARAMETER OutputPath
    Output .zip (default <input>_ANON.zip). If it does not end with .zip a folder is produced.

.PARAMETER MappingPath
    Mapping file. If it exists it is loaded first, so the same placeholders are reused across
    several bundles of the same environment. Default: <output>.mapping.PRIVATE.tsv

.PARAMETER ConfigPath
    JSON configuration (extra terms, terms to keep, whitelisted domains, switches).
    Default: anonymizer.config.json next to this script, if present.

.PARAMETER ExtraTerms
    Additional strings to always anonymize (customer name, site names, ...).

.PARAMETER KeepTerms
    Strings that must never be anonymized.

.PARAMETER SubstringTerms
    Strings replaced even when they are part of a longer word (e.g. customer name "acme" in "acmesrv01").

.PARAMETER Restore
    De-anonymize a text (e.g. an AI answer) using a mapping file: -Restore -MappingPath x.tsv -InputPath answer.txt
    or -Restore -MappingPath x.tsv -Text "host001 fails to connect to 10.200.0.108"

.PARAMETER DiscoverOnly
    Run only the discovery phase and write the report/mapping preview (nothing is anonymized).

.EXAMPLE
    .\Invoke-VeeamLogAnonymizer.ps1 -InputPath .\2026-11-04T165607_VeeamBackupLogs.zip

.EXAMPLE
    .\Invoke-VeeamLogAnonymizer.ps1 -InputPath .\bundle.zip -ExtraTerms 'Acme','acme-corp' -KeepTerms 'backupsrv'

.EXAMPLE
    .\Invoke-VeeamLogAnonymizer.ps1 -Restore -MappingPath .\bundle_ANON.mapping.PRIVATE.tsv -InputPath .\ai-answer.txt
#>
[CmdletBinding(DefaultParameterSetName = 'Anonymize')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Anonymize', Position = 0)]
    [Parameter(ParameterSetName = 'Restore', Position = 0)]
    [string]$InputPath,

    [Parameter(ParameterSetName = 'Anonymize')]
    [Parameter(ParameterSetName = 'Restore')]
    [string]$OutputPath,

    [string]$MappingPath,

    [Parameter(ParameterSetName = 'Anonymize')]
    [string]$ConfigPath,

    [Parameter(ParameterSetName = 'Anonymize')]
    [string[]]$ExtraTerms,

    [Parameter(ParameterSetName = 'Anonymize')]
    [string[]]$KeepTerms,

    [Parameter(ParameterSetName = 'Anonymize')]
    [string[]]$SubstringTerms,

    [Parameter(ParameterSetName = 'Anonymize')]
    [string]$WorkDir,

    [Parameter(ParameterSetName = 'Anonymize')]
    [switch]$DiscoverOnly,

    [Parameter(ParameterSetName = 'Anonymize')]
    [switch]$NoLeakCheck,

    [Parameter(ParameterSetName = 'Anonymize')]
    [switch]$KeepWorkDir,

    [Parameter(Mandatory = $true, ParameterSetName = 'Restore')]
    [switch]$Restore,

    [Parameter(ParameterSetName = 'Restore')]
    [string]$Text
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$scriptVersion = '1.1.0'

# ------------------------------------------------------------------------------------------ engine
function Import-AnonymizerEngine {
    if ('VeeamLogAnonymizer.Engine' -as [type]) { return }
    $src = Join-Path $PSScriptRoot 'VeeamLogAnonymizer.Engine.cs'
    if (-not (Test-Path -LiteralPath $src)) { throw "Engine source not found: $src" }
    $code = [IO.File]::ReadAllText($src)
    if ($PSVersionTable.PSEdition -eq 'Core') {
        Add-Type -TypeDefinition $code -Language CSharp
    } else {
        Add-Type -TypeDefinition $code -Language CSharp -ReferencedAssemblies 'System.Core', 'System.dll'
    }
}

function Initialize-Compression {
    try { Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop } catch { }
    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }
}

function Get-FullPath([string]$p) {
    return [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p))
}

function Get-RelativePath([string]$root, [string]$full) {
    $r = $root.TrimEnd('\') + '\'
    if ($full.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)) { return $full.Substring($r.Length) }
    return $full
}

# ------------------------------------------------------------------------------------------ archives
function Expand-NestedArchives([string]$root) {
    $round = 0
    while ($true) {
        $round++
        $items = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force |
                Where-Object { $_.Name -match '\.(zip|gz)$' })
        if ($items.Count -eq 0 -or $round -gt 10) { break }
        foreach ($f in $items) {
            if ($f.Extension -ieq '.zip') {
                $dest = $f.FullName + '~unz'
                try {
                    [IO.Compression.ZipFile]::ExtractToDirectory($f.FullName, $dest)
                    Remove-Item -LiteralPath $f.FullName -Force
                } catch {
                    Write-Warning "Cannot extract nested zip '$($f.FullName)': $($_.Exception.Message). It will be EXCLUDED from the output."
                    if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
                    Remove-Item -LiteralPath $f.FullName -Force
                    $script:ExcludedFiles.Add((Get-RelativePath $root $f.FullName))
                }
            } else {
                $dest = $f.FullName + '~ungz'
                try {
                    $in = [IO.File]::OpenRead($f.FullName)
                    try {
                        $gz = New-Object IO.Compression.GZipStream($in, [IO.Compression.CompressionMode]::Decompress)
                        $out = [IO.File]::Create($dest)
                        try { $gz.CopyTo($out) } finally { $out.Dispose(); $gz.Dispose() }
                    } finally { $in.Dispose() }
                    Remove-Item -LiteralPath $f.FullName -Force
                } catch {
                    Write-Warning "Cannot decompress '$($f.FullName)': $($_.Exception.Message). It will be EXCLUDED from the output."
                    if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force }
                    Remove-Item -LiteralPath $f.FullName -Force
                    $script:ExcludedFiles.Add((Get-RelativePath $root $f.FullName))
                }
            }
        }
    }
}

function Compress-NestedArchives([string]$root) {
    # files first (gz), then directories deepest first (zip)
    Get-ChildItem -LiteralPath $root -Recurse -File -Force | Where-Object { $_.Name.EndsWith('~ungz') } | ForEach-Object {
        $target = $_.FullName.Substring(0, $_.FullName.Length - 5) + '.gz'
        $in = [IO.File]::OpenRead($_.FullName)
        try {
            $out = [IO.File]::Create($target)
            $gz = New-Object IO.Compression.GZipStream($out, [IO.Compression.CompressionLevel]::Optimal)
            try { $in.CopyTo($gz) } finally { $gz.Dispose(); $out.Dispose() }
        } finally { $in.Dispose() }
        Remove-Item -LiteralPath $_.FullName -Force
    }
    $dirs = @(Get-ChildItem -LiteralPath $root -Recurse -Directory -Force | Where-Object { $_.Name.EndsWith('~unz') } |
            Sort-Object { $_.FullName.Split('\').Count } -Descending)
    foreach ($d in $dirs) {
        $target = $d.FullName.Substring(0, $d.FullName.Length - 4)
        if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force }
        [IO.Compression.ZipFile]::CreateFromDirectory($d.FullName, $target, [IO.Compression.CompressionLevel]::Optimal, $false)
        Remove-Item -LiteralPath $d.FullName -Recurse -Force
    }
}

# ------------------------------------------------------------------------------------------ config
function Read-AnonymizerConfig([string]$path) {
    if (-not $path) {
        $default = Join-Path $PSScriptRoot 'anonymizer.config.json'
        if (Test-Path -LiteralPath $default) { $path = $default } else { return $null }
    }
    if (-not (Test-Path -LiteralPath $path)) { throw "Config file not found: $path" }
    $raw = [IO.File]::ReadAllText((Get-FullPath $path))
    # allow // comments in the JSON file
    $raw = [regex]::Replace($raw, '(?m)^\s*//.*$', '')
    Write-Host "Config: $path"
    return ($raw | ConvertFrom-Json)
}

function Get-ConfigValue($cfg, [string]$name, $default) {
    if ($null -eq $cfg) { return $default }
    $p = $cfg.PSObject.Properties[$name]
    if ($null -eq $p -or $null -eq $p.Value) { return $default }
    return $p.Value
}

# ------------------------------------------------------------------------------------------ restore mode
if ($PSCmdlet.ParameterSetName -eq 'Restore') {
    Import-AnonymizerEngine
    if (-not $MappingPath) { throw '-MappingPath is required in -Restore mode' }
    $engine = New-Object VeeamLogAnonymizer.Engine
    [void]$engine.LoadMapping((Get-FullPath $MappingPath))
    $engine.MarkFinalizedForReverse()
    if ($Text) { return $engine.RestoreText($Text) }
    if (-not $InputPath) { throw 'Specify -Text or -InputPath' }
    $inFull = Get-FullPath $InputPath
    $ft = [VeeamLogAnonymizer.Engine]::ReadText($inFull)
    $restored = $engine.RestoreText($ft.Text)
    if (-not $OutputPath) {
        $OutputPath = Join-Path ([IO.Path]::GetDirectoryName($inFull)) ([IO.Path]::GetFileNameWithoutExtension($inFull) + '.restored' + [IO.Path]::GetExtension($inFull))
    }
    [IO.File]::WriteAllText((Get-FullPath $OutputPath), $restored, $ft.Encoding)
    Write-Host "Restored text written to $OutputPath" -ForegroundColor Green
    return
}

# ------------------------------------------------------------------------------------------ anonymize
$sw = [Diagnostics.Stopwatch]::StartNew()
Import-AnonymizerEngine
Initialize-Compression
$script:ExcludedFiles = New-Object 'System.Collections.Generic.List[string]'

$inFull = Get-FullPath $InputPath
if (-not (Test-Path -LiteralPath $inFull)) { throw "Input not found: $inFull" }
$inIsZip = (Test-Path -LiteralPath $inFull -PathType Leaf)
$baseName = if ($inIsZip) { [IO.Path]::GetFileNameWithoutExtension($inFull) } else { Split-Path $inFull -Leaf }
$baseDir = Split-Path $inFull -Parent

if (-not $OutputPath) { $OutputPath = Join-Path $baseDir ($baseName + '_ANON.zip') }
$OutputPath = Get-FullPath $OutputPath
$outIsZip = $OutputPath -match '\.zip$'
$outStem = if ($outIsZip) { $OutputPath.Substring(0, $OutputPath.Length - 4) } else { $OutputPath.TrimEnd('\') }
if (-not $MappingPath) { $MappingPath = $outStem + '.mapping.PRIVATE.tsv' }
$MappingPath = Get-FullPath $MappingPath
$ReportPath = $outStem + '.report.PRIVATE.txt'

if (-not $WorkDir) { $WorkDir = Join-Path ([IO.Path]::GetTempPath()) ('vla_' + [Guid]::NewGuid().ToString('N').Substring(0, 8)) }
$WorkDir = Get-FullPath $WorkDir
$srcRoot = Join-Path $WorkDir 'in'
$dstRoot = Join-Path $WorkDir 'out'
New-Item -ItemType Directory -Force -Path $srcRoot, $dstRoot | Out-Null

Write-Host "VeeamLogAnonymizer $scriptVersion  (PowerShell $($PSVersionTable.PSVersion))" -ForegroundColor Cyan
Write-Host "Input : $inFull"
Write-Host "Work  : $WorkDir"

try {
    # ---- engine configuration
    $engine = New-Object VeeamLogAnonymizer.Engine
    $cfg = Read-AnonymizerConfig $ConfigPath
    $engine.AnonymizePublicIPs = [bool](Get-ConfigValue $cfg 'AnonymizePublicIPs' $true)
    $engine.AnonymizeMac = [bool](Get-ConfigValue $cfg 'AnonymizeMac' $true)
    $engine.AnonymizeIPv6 = [bool](Get-ConfigValue $cfg 'AnonymizeIPv6' $true)
    $engine.AnonymizeBase64 = [bool](Get-ConfigValue $cfg 'AnonymizeBase64' $true)
    $engine.MinBareTermLength = [int](Get-ConfigValue $cfg 'MinBareTermLength' 3)
    foreach ($k in @(Get-ConfigValue $cfg 'KeepTerms' @()) + @($KeepTerms)) { if ($k) { $engine.AddKeepTerm([string]$k) } }
    foreach ($d in @(Get-ConfigValue $cfg 'WhitelistDomains' @())) { if ($d) { $engine.AddWhitelistDomain([string]$d) } }
    foreach ($t in @(Get-ConfigValue $cfg 'ExtraTerms' @()) + @($ExtraTerms)) {
        if ($null -eq $t) { continue }
        if ($t -is [string]) { $engine.AddExtraTerm($t, $null) }
        elseif ([bool](Get-ConfigValue $t 'Substring' $false)) { $engine.AddSubstringTerm([string]$t.Original, [string](Get-ConfigValue $t 'Anonymized' $null)) }
        else { $engine.AddExtraTerm([string]$t.Original, [string](Get-ConfigValue $t 'Anonymized' $null)) }
    }
    foreach ($t in @($SubstringTerms)) { if ($t) { $engine.AddSubstringTerm([string]$t, $null) } }
    if (Test-Path -LiteralPath $MappingPath) {
        $n = $engine.LoadMapping($MappingPath)
        Write-Host "Loaded $n entries from existing mapping $MappingPath (placeholders will be reused)"
    }

    # ---- stage input
    Write-Host '[1/6] Extracting bundle...' -ForegroundColor Yellow
    if ($inIsZip) { [IO.Compression.ZipFile]::ExtractToDirectory($inFull, $srcRoot) }
    else { Copy-Item -LiteralPath (Join-Path $inFull '*') -Destination $srcRoot -Recurse -Force }
    Expand-NestedArchives $srcRoot
    $files = @(Get-ChildItem -LiteralPath $srcRoot -Recurse -File -Force)
    $totalBytes = ($files | Measure-Object Length -Sum).Sum
    Write-Host ("      {0} files, {1:N0} MB uncompressed" -f $files.Count, ($totalBytes / 1MB))

    # ---- discovery
    Write-Host '[2/6] Discovery of sensitive names...' -ForegroundColor Yellow
    $i = 0
    foreach ($f in $files) {
        $i++
        $rel = Get-RelativePath $srcRoot $f.FullName
        if ($i % 5 -eq 0) { Write-Progress -Activity 'Discovery' -Status $rel -PercentComplete ($i * 100 / $files.Count) }
        $engine.DiscoverPath($rel)
        $engine.DiscoverFile($f.FullName)
    }
    Write-Progress -Activity 'Discovery' -Completed
    $engine.FinalizeDiscovery()
    $terms = $engine.GetTerms()
    Write-Host ("      {0} sensitive names learned; domain suffixes: {1}" -f $terms.Count, (($engine.GetSuffixes()) -join ', '))

    if (-not $DiscoverOnly) {
        # ---- anonymize
        Write-Host '[3/6] Anonymizing content and file names...' -ForegroundColor Yellow
        $i = 0
        $usedTargets = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($f in $files) {
            $i++
            $rel = Get-RelativePath $srcRoot $f.FullName
            if ($i % 5 -eq 0) { Write-Progress -Activity 'Anonymizing' -Status $rel -PercentComplete ($i * 100 / $files.Count) }
            $newRel = $engine.AnonymizeRelativePath($rel)
            $target = Join-Path $dstRoot $newRel
            $k = 1
            while (-not $usedTargets.Add($target)) {
                $target = Join-Path $dstRoot ($newRel + '~' + $k); $k++
            }
            [void]$engine.AnonymizeFile($f.FullName, $target)
        }
        Write-Progress -Activity 'Anonymizing' -Completed
        # anonymize directory names that ended up empty-mapped (folders are created on demand by AnonymizeFile)

        # ---- leak check
        $leaks = @()
        if (-not $NoLeakCheck) {
            Write-Host '[4/6] Leak check (searching original values in the output)...' -ForegroundColor Yellow
            $engine.PrepareLeakCheck(4)
            $outFiles = @(Get-ChildItem -LiteralPath $dstRoot -Recurse -File -Force)
            $i = 0
            foreach ($f in $outFiles) {
                $i++
                $rel = Get-RelativePath $dstRoot $f.FullName
                if ($i % 5 -eq 0) { Write-Progress -Activity 'Leak check' -Status $rel -PercentComplete ($i * 100 / $outFiles.Count) }
                $engine.LeakScan($rel, '[path] ' + $rel)
                $engine.LeakScanFile($f.FullName, $rel)
            }
            Write-Progress -Activity 'Leak check' -Completed
            $leaks = $engine.GetLeaks()
        } else { Write-Host '[4/6] Leak check skipped' }

        # ---- package
        Write-Host '[5/6] Re-packing archives...' -ForegroundColor Yellow
        Compress-NestedArchives $dstRoot
        if ($outIsZip) {
            if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Force }
            [IO.Compression.ZipFile]::CreateFromDirectory($dstRoot, $OutputPath, [IO.Compression.CompressionLevel]::Optimal, $false)
        } else {
            if (Test-Path -LiteralPath $OutputPath) { throw "Output folder already exists: $OutputPath" }
            Move-Item -LiteralPath $dstRoot -Destination $OutputPath
        }
    }

    # ---- mapping + report
    Write-Host '[6/6] Writing mapping and report...' -ForegroundColor Yellow
    $engine.SaveMapping($MappingPath)

    $sb = New-Object System.Text.StringBuilder
    $L = { param($s) [void]$sb.AppendLine($s) }
    & $L "VeeamLogAnonymizer $scriptVersion - REPORT  (PRIVATE: contains original values, do not share)"
    & $L ('=' * 100)
    & $L "Date      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    & $L "Input     : $inFull"
    if (-not $DiscoverOnly) { & $L "Output    : $OutputPath" }
    & $L "Mapping   : $MappingPath"
    & $L ("Files     : {0}  ({1:N0} MB)" -f $files.Count, ($totalBytes / 1MB))
    & $L ("Duration  : {0:hh\:mm\:ss}" -f $sw.Elapsed)
    if ($script:ExcludedFiles.Count -gt 0) {
        & $L ''
        & $L 'EXCLUDED (corrupted archives, not included in the output):'
        foreach ($x in $script:ExcludedFiles) { & $L "  $x" }
    }
    & $L ''
    & $L 'REPLACEMENTS'
    & $L ('-' * 100)
    $stats = $engine.GetStats()
    foreach ($k in ($stats.Keys | Sort-Object)) { & $L ("  {0,-22} {1,12:N0}" -f $k, $stats[$k]) }
    $byCat = $terms | Group-Object Category | Sort-Object Name
    foreach ($g in $byCat) {
        $hits = ($g.Group | Measure-Object Hits -Sum).Sum
        & $L ("  {0,-22} {1,12:N0} occurrences   ({2} distinct values)" -f ('Names:' + $g.Name), $hits, $g.Count)
    }
    & $L ''
    & $L 'LEARNED NAMES (original -> placeholder, hits)'
    & $L ('-' * 100)
    foreach ($g in $byCat) {
        & $L "  [$($g.Name)]"
        foreach ($e in ($g.Group | Sort-Object Hits -Descending)) {
            $flag = if ($e.Bare) { '' } else { '  (only inside FQDNs)' }
            & $L ("    {0,-50} -> {1,-30} {2,10:N0}  {3}{4}" -f $e.Original, $e.Fake, $e.Hits, $e.Source, $flag)
        }
    }
    $fixed = $engine.GetFixed()
    & $L ''
    & $L 'NETWORK IDENTIFIERS'
    & $L ('-' * 100)
    foreach ($g in ($fixed | Group-Object Category | Sort-Object Name)) {
        & $L "  [$($g.Name)] $($g.Count) distinct"
        foreach ($e in ($g.Group | Select-Object -First 60)) { & $L ("    {0,-42} -> {1}" -f $e.Original, $e.Fake) }
        if ($g.Count -gt 60) { & $L "    ... see mapping file" }
    }
    if (-not $DiscoverOnly) {
        & $L ''
        & $L 'PUBLIC IPv4 ANONYMIZED WITHOUT A CLEAR NETWORK CONTEXT (check: if some are actually version numbers add them to KeepTerms)'
        & $L ('-' * 100)
        foreach ($kv in $engine.GetPublicIpsAnonymizedWithoutContext() | Select-Object -First 100) { & $L ("    {0,-20} {1,10:N0}" -f $kv.Key, $kv.Value) }
        & $L ''
        & $L 'IPv4-LIKE TOKENS KEPT AS VERSION NUMBERS / SPECIAL ADDRESSES (check that none of them is a real address)'
        & $L ('-' * 100)
        foreach ($kv in $engine.GetKeptIpLike() | Select-Object -First 150) { & $L ("    {0,-20} {1,10:N0}" -f $kv.Key, $kv.Value) }
        & $L ''
        & $L 'LEAK CHECK (original values still present in the output, substring match, case-insensitive)'
        & $L ('-' * 100)
        if ($NoLeakCheck) { & $L '  skipped' }
        elseif ($leaks.Count -eq 0) { & $L '  OK - no original value found in the output.' }
        else {
            $whole = @($leaks | Where-Object { $_.WholeWord -gt 0 })
            $part = @($leaks | Where-Object { $_.WholeWord -eq 0 })
            & $L "  A) WHOLE-WORD occurrences: $($whole.Count) values  <-- real leaks, review them"
            & $L '     Fix: add the longer name that contains it to ExtraTerms, or the value to SubstringTerms, then re-run.'
            foreach ($lk in $whole) {
                & $L ("  {0,-12} {1,-40} {2,8:N0}x whole, {3,8:N0}x partial   file: {4}" -f $lk.Category, $lk.Original, $lk.WholeWord, $lk.Partial, $lk.FirstFile)
                & $L ("               ...{0}..." -f $lk.WholeSample)
            }
            & $L ''
            & $L "  B) PARTIAL occurrences only (value inside a longer word, e.g. 'station' in 'Workstation'): $($part.Count) values"
            & $L '     Usually false positives. If the longer word is sensitive too, add it to ExtraTerms / SubstringTerms.'
            foreach ($lk in $part) {
                & $L ("  {0,-12} {1,-40} {2,8:N0}x partial   file: {3}" -f $lk.Category, $lk.Original, $lk.Partial, $lk.FirstFile)
                & $L ("               ...{0}..." -f $lk.Sample)
            }
        }
    }
    & $L ''
    & $L 'TOP DISCOVERY CANDIDATES (including those rejected by filters)'
    & $L ('-' * 100)
    foreach ($c in ($engine.GetCandidates() | Select-Object -First 300)) { & $L ("    {0,-14} {1,-50} {2,10:N0}  {3}" -f $c.Category, $c.Value, $c.Count, $c.Source) }
    [IO.File]::WriteAllText($ReportPath, $sb.ToString(), (New-Object Text.UTF8Encoding($true)))

    $sw.Stop()
    Write-Host ''
    Write-Host ("Done in {0:hh\:mm\:ss}" -f $sw.Elapsed) -ForegroundColor Green
    if (-not $DiscoverOnly) { Write-Host "  Anonymized bundle (shareable): $OutputPath" -ForegroundColor Green }
    Write-Host "  Mapping  (PRIVATE)           : $MappingPath" -ForegroundColor DarkYellow
    Write-Host "  Report   (PRIVATE)           : $ReportPath" -ForegroundColor DarkYellow
    if (-not $DiscoverOnly -and -not $NoLeakCheck) {
        $wl = @($leaks | Where-Object { $_.WholeWord -gt 0 })
        $pl = @($leaks | Where-Object { $_.WholeWord -eq 0 })
        if ($leaks.Count -eq 0) { Write-Host '  Leak check: OK, no original value found in the output.' -ForegroundColor Green }
        elseif ($wl.Count -eq 0) { Write-Host ("  Leak check: OK for whole words; {0} values appear only inside longer words (see report, section B)." -f $pl.Count) -ForegroundColor Yellow }
        else {
            Write-Host ("  Leak check: {0} values still present as WHOLE WORDS - review the report before sharing!" -f $wl.Count) -ForegroundColor Red
            foreach ($lk in ($wl | Select-Object -First 10)) { Write-Host ("     {0,-10} {1,-30} {2,7:N0}x" -f $lk.Category, $lk.Original, $lk.WholeWord) -ForegroundColor Red }
        }
    }
}
finally {
    if (-not $KeepWorkDir -and (Test-Path -LiteralPath $WorkDir)) {
        Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    } elseif ($KeepWorkDir) { Write-Host "Work directory kept: $WorkDir" }
}
