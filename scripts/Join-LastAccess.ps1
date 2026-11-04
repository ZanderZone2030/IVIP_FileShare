<#
.SYNOPSIS
    Adds "last used" to a list of who can reach which app or folder, from the last-access store, and
    marks access that is not used.

.DESCRIPTION
    Reads an access list and the store written by Merge-LastAccess.ps1, and writes the access list
    again with these columns added:

      LastUsed       last time one of the person's accounts used the app or folder (UTC)
      LastWrite      last write in the folder (folder-level audit only)
      DaysSinceUse   days from LastUsed to the end of the coverage
      Status         Used, Unused or Unknown
      Evidence       what the status is based on: sign-in log, share connection (5140) or folder
                     audit (4663 / 5145)
      Detail         one line in words

    Status rules, with -UnusedDays N (default 90):
      Used      used in the last N days
      Unused    not used in the last N days, and the log was read without a gap for at least N days.
                LastUsed is empty when the person was never seen since the log was first read.
      Unknown   not used in the last N days, but the log covers less than N days, or there is no
                log for this platform or folder at all. Never read "Unknown" as "Unused".
    The N days are counted back from the end of the coverage, not from today, so a store that was
    not updated for a while does not make everybody look unused.

    Two kinds of access list are understood:

    Apps: the <name>_access.csv of IVIP App Access (App, Platform, Person, Accounts, ...). The
    Platform is matched to the Source of the store rows (Entra, Okta, or any other source written in
    the same layout, such as SAP or Citrix), and the app to their ObjectName or ObjectId. AD FS has no
    collector yet, so its apps stay Unknown.

    Folders: any CSV with FolderPath and Account (or Accounts) columns, such as a list of who can
    reach which folder. A folder counts as used when the person
      - wrote or read in it or below it, by a 4663 / 5145 event, when that folder is inside an
        audited folder (the Scope of the 4663 coverage); or else
      - connected to a share that contains the folder, or a share inside it (5140). This is weaker:
        it shows that the person used the share, not this folder. It is used when the folder is not
        audited, or its audit does not cover -UnusedDays yet.

    Accounts are matched without DOMAIN\ and @domain, the same as the graph scripts. In an Accounts
    cell, several accounts are separated by ";" and may start with a platform word ("AD CORP\jdoe;
    Entra jdoe@companyx.com").

.PARAMETER AccessPath
    The access list CSV.

.PARAMETER StorePath
    The store folder of Merge-LastAccess.ps1.

.PARAMETER OutputPath
    Output CSV. Default: <access list name>_lastused.csv next to the access list.

.PARAMETER UnusedDays
    Access not used for this many days is Unused. Default 90.

.PARAMETER FileServer
    For a folder list: only use the store rows of this file server (the Origin, e.g. FS01). Default: all.

.EXAMPLE
    .\Join-LastAccess.ps1 -AccessPath .\AppAccess_access.csv -StorePath \\admin01\ivip\lastaccess

.EXAMPLE
    .\Join-LastAccess.ps1 -AccessPath .\FS01_who_can_access.csv -StorePath .\store -FileServer FS01 -UnusedDays 180
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AccessPath,

    [Parameter(Mandatory = $true)]
    [string]$StorePath,

    [string]$OutputPath,

    [ValidateRange(1, 3650)]
    [int]$UnusedDays = 90,

    [string]$FileServer
)

$ErrorActionPreference = 'Stop'
$script:IsCore = $PSVersionTable.PSVersion.Major -ge 6
$script:Inv = [System.Globalization.CultureInfo]::InvariantCulture

# =============================================================================================
# Helpers
# =============================================================================================

function ConvertTo-UtcDate {
    # A DateTime or an ISO 8601 string as UTC. Strings without an offset are taken as UTC.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTime]) {
        if ($Value.Kind -eq [DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [DateTime]::SpecifyKind($Value, [DateTimeKind]::Utc)
    }
    $s = ([string]$Value).Trim()
    if (-not $s) { return $null }
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    $d = [DateTime]::MinValue
    if ([DateTime]::TryParse($s, $script:Inv, $styles, [ref]$d)) { return $d }
    $null
}

function Format-UtcDate {
    param($Date)
    if ($null -eq $Date) { return '' }
    $Date.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", $script:Inv)
}

function Get-CsvEncoding {
    # The byte-order mark if there is one, else UTF-8 when the start of the file is valid UTF-8, else the
    # ANSI code page (a CSV re-saved from Excel)
    param([string]$File)
    $buf = [byte[]]::new(1MB)
    $fs  = [System.IO.File]::OpenRead($File)
    try { $n = $fs.Read($buf, 0, $buf.Length) } finally { $fs.Dispose() }
    if ($n -ge 3 -and $buf[0] -eq 0xEF -and $buf[1] -eq 0xBB -and $buf[2] -eq 0xBF) { return 'UTF8' }
    if ($n -ge 2 -and $buf[0] -eq 0xFF -and $buf[1] -eq 0xFE) { return 'Unicode' }
    if ($n -ge 2 -and $buf[0] -eq 0xFE -and $buf[1] -eq 0xFF) { return 'BigEndianUnicode' }
    try {
        $null = [System.Text.UTF8Encoding]::new($false, $true).GetDecoder().GetChars($buf, 0, $n, [char[]]::new($n), 0)
        return 'UTF8'
    } catch [System.Text.DecoderFallbackException] { }
    if ($script:IsCore) {
        return [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage)
    }
    'Default'
}

function Import-AnyCsv {
    # Comma, semicolon or tab separated; UTF-8 (with or without BOM), UTF-16 with BOM, or ANSI
    param([string]$File)
    $encoding = Get-CsvEncoding $File
    $first = [string](Get-Content -LiteralPath $File -TotalCount 1 -Encoding $encoding)
    $best = ','; $bestCount = -1
    foreach ($d in @(',', ';', "`t")) {
        $c = $first.Split($d).Count - 1
        if ($c -gt $bestCount) { $best = $d; $bestCount = $c }
    }
    @(Import-Csv -LiteralPath $File -Delimiter $best -Encoding $encoding)
}

function Export-Utf8Csv {
    param($Rows, [string]$File, [string[]]$Columns)
    if (@($Rows).Count -eq 0) {
        $line = ($Columns | ForEach-Object { '"' + $_ + '"' }) -join ','
        [System.IO.File]::WriteAllText($File, $line + "`r`n", [System.Text.UTF8Encoding]::new($true))
        return
    }
    $enc = if ($script:IsCore) { 'utf8BOM' } else { 'UTF8' }
    $Rows | Select-Object -Property $Columns | Export-Csv -LiteralPath $File -NoTypeInformation -Encoding $enc
}

function Get-Col {
    param($Row, [string]$Name)
    $p = $Row.PSObject.Properties[$Name]
    if ($p -and $null -ne $p.Value) { ([string]$p.Value).Trim() } else { '' }
}

function Get-AccountKeys {
    # "AD CORP\jdoe; Entra jdoe@companyx.com" -> jdoe (DOMAIN\ and @domain removed, lower case)
    param([string]$Text)
    $keys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($part in $Text.Split(';')) {
        $a = $part.Trim()
        if (-not $a) { continue }
        $sp = $a.LastIndexOf(' ')
        if ($sp -ge 0) { $a = $a.Substring($sp + 1) }
        $i = $a.LastIndexOf('\'); if ($i -ge 0) { $a = $a.Substring($i + 1) }
        $i = $a.LastIndexOf('@'); if ($i -gt 0) { $a = $a.Substring(0, $i) }
        if ($a) { $null = $keys.Add($a.ToLowerInvariant()) }
    }
    , $keys
}

function Test-UnderPath {
    param([string]$Path, [string]$Root)
    if (-not $Root -or -not $Path) { return $false }
    if ($Path.Equals($Root, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    $r = if ($Root.EndsWith('\')) { $Root } else { $Root + '\' }
    $Path.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)
}

# =============================================================================================
# Store
# =============================================================================================

$storeFile = Join-Path $StorePath 'lastaccess.csv'
$covFile = Join-Path $StorePath 'coverage.csv'
if (-not (Test-Path -LiteralPath $storeFile)) { throw "No lastaccess.csv in $StorePath. Run Merge-LastAccess.ps1 first." }
$rows = @(Import-AnyCsv $storeFile)
$cov = if (Test-Path -LiteralPath $covFile) { @(Import-AnyCsv $covFile) } else { @() }

# Store rows by account key
$byKey = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$appIds = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($r in $rows) {
    if ($FileServer -and $r.Source -eq 'FileShare' -and $r.Origin -ne $FileServer) { continue }
    $r | Add-Member -NotePropertyName Last -NotePropertyValue (ConvertTo-UtcDate $r.LastSeen)
    $r | Add-Member -NotePropertyName Write -NotePropertyValue (ConvertTo-UtcDate $r.LastWrite)
    $l = $null
    if (-not $byKey.TryGetValue($r.AccountKey, [ref]$l)) { $l = [System.Collections.Generic.List[object]]::new(); $byKey[$r.AccountKey] = $l }
    $l.Add($r)
    # The IDs each app name goes by, so coverage scoped to an ID (SAP 'PRD/100') covers the app's name too
    if ($r.ObjectName -and $r.ObjectId) {
        $ik = $r.Source + '|' + $r.ObjectName
        $s = $null
        if (-not $appIds.TryGetValue($ik, [ref]$s)) { $s = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase); $appIds[$ik] = $s }
        [void]$s.Add($r.ObjectId)
    }
}

# Coverage periods
$periods = foreach ($c in $cov) {
    if ($FileServer -and $c.Source -eq 'FileShare' -and $c.Origin -ne $FileServer) { continue }
    [pscustomobject]@{ Source = $c.Source; Origin = $c.Origin; Feed = $c.Feed; Scope = @(([string]$c.Scope).Split('|'))
                       From = (ConvertTo-UtcDate $c.From); To = (ConvertTo-UtcDate $c.To) }
}
$periods = @($periods)

function Get-Coverage {
    # The newest continuous period of the feeds that pass the filter: @{ From; To } or $null
    param([scriptblock]$Filter)
    $best = $null
    foreach ($p in $periods) {
        if (-not (& $Filter $p)) { continue }
        if ($null -eq $best -or $p.To -gt $best.To -or ($p.To -eq $best.To -and $p.From -lt $best.From)) { $best = $p }
    }
    $best
}

function Get-Status {
    # Used / Unused / Unknown from the last use and the coverage
    param($Last, $Coverage, [string]$Watched)
    $res = [ordered]@{ Status = 'Unknown'; Days = ''; Detail = '' }
    if ($null -eq $Coverage) {
        $res.Detail = "Nothing collects $Watched yet."
        if ($Last) { $res.Status = 'Used'; $res.Detail = "Seen in the store, but no coverage is recorded for $Watched." }
        return $res
    }
    $ref = $Coverage.To
    $limit = $ref.AddDays(-$UnusedDays)
    $watchedDays = [int][Math]::Floor(($ref - $Coverage.From).TotalDays)
    if ($Last) { $res.Days = [int][Math]::Floor(($ref - $Last).TotalDays); if ($res.Days -lt 0) { $res.Days = 0 } }
    if ($Last -and $Last -ge $limit) {
        $res.Status = 'Used'
        $res.Detail = 'Last use {0:yyyy-MM-dd}.' -f $Last
    }
    elseif ($watchedDays -ge $UnusedDays) {
        $res.Status = 'Unused'
        $res.Detail = if ($Last) { 'Not used in {0} days; last use {1:yyyy-MM-dd}.' -f $UnusedDays, $Last }
                      else { 'Never seen since {0:yyyy-MM-dd} ({1} days of {2}).' -f $Coverage.From, $watchedDays, $Watched }
    }
    else {
        $res.Detail = if ($Last) { 'Last use {0:yyyy-MM-dd}; only {1} days of {2} are collected, {3} needed.' -f $Last, $watchedDays, $Watched, $UnusedDays }
                      else { 'Not seen, but only {0} days of {1} are collected, {2} needed.' -f $watchedDays, $Watched, $UnusedDays }
    }
    $res
}

# =============================================================================================
# Join
# =============================================================================================

$access = @(Import-AnyCsv $AccessPath)
if (-not $access.Count) { throw "$AccessPath is empty." }
$names = @($access[0].PSObject.Properties.Name)
$isFolder = $names -contains 'FolderPath'
$acctCol = if ($names -contains 'Accounts') { 'Accounts' } elseif ($names -contains 'Account') { 'Account' } else { throw 'The access list needs an Account or Accounts column.' }
if (-not $isFolder -and -not ($names -contains 'App')) { throw 'The access list needs an App column (apps) or a FolderPath column (folders).' }

$out = [System.Collections.Generic.List[object]]::new()
$tally = @{ Used = 0; Unused = 0; Unknown = 0 }
foreach ($a in $access) {
    $keys = Get-AccountKeys (Get-Col $a $acctCol)
    $mine = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $keys) { $l = $null; if ($byKey.TryGetValue($k, [ref]$l)) { $mine.AddRange($l) } }

    $last = $null; $write = $null; $evidence = ''
    if ($isFolder) {
        $folder = (Get-Col $a 'FolderPath').TrimEnd('\')
        # Folder-level audit, when the folder is inside an audited folder
        $fcov = Get-Coverage { param($p) $p.Source -eq 'FileShare' -and $p.Feed -ne '5140' -and @($p.Scope | Where-Object { Test-UnderPath $folder $_ }).Count -gt 0 }
        if ($fcov) {
            foreach ($r in $mine) {
                if ($r.Source -eq 'FileShare' -and $r.ObjectType -eq 'Folder' -and (Test-UnderPath $r.ObjectId $folder)) {
                    if ($null -eq $last -or $r.Last -gt $last) { $last = $r.Last }
                    if ($r.Write -and ($null -eq $write -or $r.Write -gt $write)) { $write = $r.Write }
                }
            }
            $evidence = 'Folder audit (4663/5145)'
            $st = Get-Status $last $fcov 'folder auditing'
        }
        if (-not $fcov -or $st.Status -eq 'Unknown') {
            # No folder audit here, or not long enough yet: fall back to the share connections
            $folderNote = if ($fcov) { ' Folder auditing: ' + $st.Detail } else { '' }
            $last = $null; $write = $null
            $scov = Get-Coverage { param($p) $p.Source -eq 'FileShare' -and $p.Feed -eq '5140' }
            foreach ($r in $mine) {
                if ($r.Source -eq 'FileShare' -and $r.ObjectType -eq 'Share' -and ((Test-UnderPath $folder $r.ObjectId) -or (Test-UnderPath $r.ObjectId $folder))) {
                    if ($null -eq $last -or $r.Last -gt $last) { $last = $r.Last }
                }
            }
            $evidence = 'Share connection (5140)'
            $st = Get-Status $last $scov 'share auditing'
            $st.Detail += $folderNote
        }
    }
    else {
        $app = Get-Col $a 'App'
        $platform = Get-Col $a 'Platform'
        $source = $platform
        foreach ($r in $mine) {
            if ($r.Source -ne $source -or ($r.ObjectType -ne 'App' -and $r.ObjectType -ne 'Desktop')) { continue }
            if (-not ($r.ObjectName -eq $app -or $r.ObjectId -eq $app)) { continue }
            if ($null -eq $last -or $r.Last -gt $last) { $last = $r.Last }
        }
        # The coverage of this platform; for an application's own log, the period that names the app
        $ids = $null
        if (-not $appIds.TryGetValue($source + '|' + $app, [ref]$ids)) { $ids = @() }
        $acov = Get-Coverage { param($p) $p.Source -eq $source -and ($p.Scope -contains '*' -or $p.Scope -contains $app -or @($p.Scope | Where-Object { $ids -contains $_ }).Count -gt 0) }
        $evidence = switch ($source) { 'Entra' { 'Entra sign-in log' } 'Okta' { 'Okta System Log' } default { "$platform log" } }
        $st = Get-Status $last $acov "the $evidence"
    }
    $tally[$st.Status]++
    $o = [ordered]@{}
    foreach ($n in $names) { $o[$n] = $a.$n }
    $o.LastUsed = Format-UtcDate $last
    $o.LastWrite = Format-UtcDate $write
    $o.DaysSinceUse = $st.Days
    $o.Status = $st.Status
    $o.Evidence = $(if ($st.Detail -like 'Nothing collects*') { '' } else { $evidence })
    $o.Detail = $st.Detail
    $out.Add([pscustomobject]$o)
}

if (-not $OutputPath) {
    $item = Get-Item -LiteralPath $AccessPath
    $OutputPath = Join-Path $item.DirectoryName ($item.BaseName + '_lastused.csv')
}
Export-Utf8Csv $out $OutputPath ($names + @('LastUsed', 'LastWrite', 'DaysSinceUse', 'Status', 'Evidence', 'Detail'))
Write-Host ("{0} access rows: {1} used, {2} unused (not used in {3} days), {4} unknown. Written to {5}" -f `
    $out.Count, $tally.Used, $tally.Unused, $UnusedDays, $tally.Unknown, $OutputPath)
