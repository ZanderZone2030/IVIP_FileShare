<#
.SYNOPSIS
    Merges the output of the last-access collectors into one rolling "last seen" store.

.DESCRIPTION
    The collectors (Get-ShareAccessEvents.ps1, Get-EntraSignIns.ps1, Get-OktaSignIns.ps1) each read a
    short period, because the logs they read do not keep much: a Security log wraps in days, Entra keeps
    sign-ins 30 days, Okta 90. This script folds every run into a store that keeps one row per source,
    object and account, for as long as -RetentionDays.

    The merge only takes the earliest FirstSeen and the latest LastSeen and LastWrite, so it is
    idempotent: merging the same run twice, or two runs that overlap, gives the same store. The
    number of events is not kept in the store for that reason.

    The store also keeps coverage.csv: for each source, origin (server, tenant, org) and feed (event
    ID or log), the periods that were actually read, joined where they touch. A person who was never
    seen only counts as "not using" an object when the coverage reaches back far enough. Gaps are
    reported.

    Retention: rows last seen before -RetentionDays are removed, and coverage is cut to the same
    period, so an old row that was removed is never read as "never used".

    Input rows can come from any source in the same layout, for example the last logon export of an
    application that signs in against AD directly. The required columns are Source, ObjectType,
    ObjectId, LastSeen and AccountKey or Account. See docs\last-access.md.

    Store folder:
      lastaccess.csv   Source, Origin, ObjectType, ObjectId, ObjectName, AccountKey, Account, AccountSid,
                       AccountId, DisplayName, FirstSeen, LastSeen, LastWrite, LastClient, Updated
      coverage.csv     Source, Origin, Feed, Scope, From, To, Collected
      *.bak            the previous version of both files

    The store names accounts and what they use. Treat it as sensitive.

.PARAMETER Path
    Collector output folders (with lastaccess.csv and coverage.csv) or lastaccess.csv files. A
    coverage.csv next to a file is read too.

.PARAMETER StorePath
    The store folder. Created if needed.

.PARAMETER RetentionDays
    How long a row is kept after it was last seen. Default 400, so a yearly review still sees a full year.

.PARAMETER AccountMapPath
    accounts.csv files of the IVIP App Access collectors (Get-EntraAppAccess.ps1, Get-OktaAppAccess.ps1).
    Cloud accounts that are linked to an AD account get that sAMAccountName as AccountKey, so the
    store matches people across platforms even when the login is not the sAMAccountName.

.PARAMETER MaxGapMinutes
    Two coverage periods that are at most this far apart are joined into one. Default 60.

.PARAMETER AsOf
    The time the retention is counted from. Default: now. Set it to rebuild a store as of a past date.

.EXAMPLE
    .\Merge-LastAccess.ps1 -Path .\ShareAccess_20261022_0600, .\EntraSignIns_20261022_0610 -StorePath \\admin01\ivip\lastaccess

.EXAMPLE
    .\Merge-LastAccess.ps1 -Path .\okta -StorePath .\store -AccountMapPath .\OktaAppAccess\accounts.csv, .\EntraAppAccess\accounts.csv
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Path,

    [Parameter(Mandatory = $true)]
    [string]$StorePath,

    [ValidateRange(1, 3650)]
    [int]$RetentionDays = 400,

    [string[]]$AccountMapPath,

    [ValidateRange(0, 10080)]
    [int]$MaxGapMinutes = 60,

    [Nullable[datetime]]$AsOf
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

function Get-BareAccount {
    # DOMAIN\name and name@domain -> name, lower case (the account rule of the graph scripts)
    param([string]$Name)
    $n = $Name.Trim()
    $i = $n.LastIndexOf('\'); if ($i -ge 0) { $n = $n.Substring($i + 1) }
    $i = $n.LastIndexOf('@'); if ($i -gt 0) { $n = $n.Substring(0, $i) }
    $n.ToLowerInvariant()
}

function Write-Atomic {
    # Write to a temporary file, keep the old file as .bak, then move the new one in place
    param($Rows, [string]$File, [string[]]$Columns)
    $tmp = "$File.tmp"
    Export-Utf8Csv $Rows $tmp $Columns
    if (Test-Path -LiteralPath $File) { Copy-Item -LiteralPath $File -Destination "$File.bak" -Force }
    Move-Item -LiteralPath $tmp -Destination $File -Force
}

$RowCols = 'Source', 'Origin', 'ObjectType', 'ObjectId', 'ObjectName', 'AccountKey', 'Account', 'AccountSid', 'AccountId', 'DisplayName',
           'FirstSeen', 'LastSeen', 'LastWrite', 'LastClient', 'Updated'
$CovCols = 'Source', 'Origin', 'Feed', 'Scope', 'From', 'To', 'Collected'

$asOfUtc = if ($AsOf) { ConvertTo-UtcDate $AsOf } else { [DateTime]::UtcNow }
$cutoff = $asOfUtc.AddDays(-$RetentionDays)
$stamp = Format-UtcDate $asOfUtc

# =============================================================================================
# Account map: cloud login or ID -> AD sAMAccountName
# =============================================================================================

$accountMap = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($f in @($AccountMapPath)) {
    if (-not $f) { continue }
    foreach ($a in (Import-AnyCsv $f)) {
        $sam = Get-Col $a 'OnPremSam'
        if (-not $sam) { continue }
        $src = Get-Col $a 'Source'
        foreach ($v in @((Get-Col $a 'AccountId'), (Get-Col $a 'Login'), (Get-Col $a 'Email'))) {
            if ($v) { $accountMap["$src|$v"] = $sam.ToLowerInvariant() }
        }
    }
}
if ($accountMap.Count) { Write-Verbose "Account map: $($accountMap.Count) entries." }

# =============================================================================================
# Load the store
# =============================================================================================

if (-not (Test-Path -LiteralPath $StorePath)) { $null = New-Item -ItemType Directory -Path $StorePath }
$storeFile = Join-Path $StorePath 'lastaccess.csv'
$covFile   = Join-Path $StorePath 'coverage.csv'

$store = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$covList = [System.Collections.Generic.List[object]]::new()

function Get-RowKey {
    param($r)
    '{0}|{1}|{2}|{3}|{4}' -f $r.Source, $r.Origin, $r.ObjectType, $r.ObjectId, $r.AccountKey
}

if (Test-Path -LiteralPath $storeFile) {
    foreach ($r in (Import-AnyCsv $storeFile)) {
        $o = [ordered]@{}
        foreach ($c in $RowCols) { $o[$c] = Get-Col $r $c }
        $o.First = ConvertTo-UtcDate $o.FirstSeen; $o.Last = ConvertTo-UtcDate $o.LastSeen; $o.Write = ConvertTo-UtcDate $o.LastWrite
        $store[(Get-RowKey $o)] = $o
    }
}
$before = $store.Count
if (Test-Path -LiteralPath $covFile) { foreach ($c in (Import-AnyCsv $covFile)) { $covList.Add($c) } }

# =============================================================================================
# Merge the runs
# =============================================================================================

$added = 0; $changed = 0; $read = 0; $bad = 0
foreach ($p in $Path) {
    $item = Get-Item -LiteralPath $p
    if ($item.PSIsContainer) { $rowFile = Join-Path $item.FullName 'lastaccess.csv'; $cf = Join-Path $item.FullName 'coverage.csv' }
    else { $rowFile = $item.FullName; $cf = Join-Path $item.DirectoryName 'coverage.csv' }
    if (Test-Path -LiteralPath $rowFile) {
        foreach ($r in (Import-AnyCsv $rowFile)) {
            $read++
            $n = [ordered]@{}
            foreach ($c in $RowCols) { $n[$c] = Get-Col $r $c }
            if (-not $n.AccountKey -and $n.Account) { $n.AccountKey = Get-BareAccount $n.Account }
            $n.AccountKey = $n.AccountKey.ToLowerInvariant()
            if ($n.Source -ne 'FileShare') {
                $sam = $null
                if (($n.AccountId -and $accountMap.TryGetValue("$($n.Source)|$($n.AccountId)", [ref]$sam)) -or
                    ($n.Account -and $accountMap.TryGetValue("$($n.Source)|$($n.Account)", [ref]$sam))) { $n.AccountKey = $sam }
            }
            if ($n.ObjectType -eq 'Share' -or $n.ObjectType -eq 'Folder') { $n.ObjectId = $n.ObjectId.TrimEnd('\') }
            $n.First = ConvertTo-UtcDate $n.FirstSeen; $n.Last = ConvertTo-UtcDate $n.LastSeen; $n.Write = ConvertTo-UtcDate $n.LastWrite
            if (-not $n.First) { $n.First = $n.Last }
            if (-not $n.Source -or -not $n.ObjectType -or -not $n.ObjectId -or -not $n.AccountKey -or -not $n.Last) { $bad++; continue }
            if ($n.Last -lt $cutoff) { continue }

            $k = Get-RowKey $n
            $o = $null
            if (-not $store.TryGetValue($k, [ref]$o)) {
                $n.Updated = $stamp
                $store[$k] = $n
                $added++
                continue
            }
            $was = '{0}|{1}|{2}' -f $o.First, $o.Last, $o.Write
            if ($n.First -lt $o.First) { $o.First = $n.First }
            if ($n.Last -gt $o.Last) {
                $o.Last = $n.Last
                if ($n.LastClient) { $o.LastClient = $n.LastClient }
                foreach ($c in 'ObjectName', 'Account', 'AccountSid', 'AccountId', 'DisplayName') { if ($n[$c]) { $o[$c] = $n[$c] } }
            }
            else {
                foreach ($c in 'ObjectName', 'Account', 'AccountSid', 'AccountId', 'DisplayName', 'LastClient') { if (-not $o[$c] -and $n[$c]) { $o[$c] = $n[$c] } }
            }
            if ($n.Write -and (-not $o.Write -or $n.Write -gt $o.Write)) { $o.Write = $n.Write }
            if ($was -ne ('{0}|{1}|{2}' -f $o.First, $o.Last, $o.Write)) { $o.Updated = $stamp; $changed++ }
        }
    }
    else { Write-Warning "No lastaccess.csv in $p" }
    if (Test-Path -LiteralPath $cf) { foreach ($c in (Import-AnyCsv $cf)) { $covList.Add($c) } }
    else { Write-Warning "No coverage.csv for $p. Its rows count as use, but nothing can be called unused from them." }
}

# =============================================================================================
# Retention
# =============================================================================================

$expired = 0
foreach ($k in @($store.Keys)) {
    if ($store[$k].Last -lt $cutoff) { $null = $store.Remove($k); $expired++ }
}

# =============================================================================================
# Coverage: join the periods per source, origin, feed and scope; cut to the retention
# =============================================================================================

$groups = [ordered]@{}
foreach ($c in $covList) {
    $from = ConvertTo-UtcDate (Get-Col $c 'From'); $to = ConvertTo-UtcDate (Get-Col $c 'To')
    if (-not $from -or -not $to -or $to -le $from) { continue }
    $scope = Get-Col $c 'Scope'; if (-not $scope) { $scope = '*' }
    $g = '{0}|{1}|{2}|{3}' -f (Get-Col $c 'Source'), (Get-Col $c 'Origin'), (Get-Col $c 'Feed'), $scope
    if (-not $groups.Contains($g)) { $groups[$g] = [System.Collections.Generic.List[object]]::new() }
    $groups[$g].Add(@{ Source = (Get-Col $c 'Source'); Origin = (Get-Col $c 'Origin'); Feed = (Get-Col $c 'Feed'); Scope = $scope
                       From = $from; To = $to; Collected = (ConvertTo-UtcDate (Get-Col $c 'Collected')) })
}
$gap = [TimeSpan]::FromMinutes($MaxGapMinutes)
$covOut = [System.Collections.Generic.List[object]]::new()
foreach ($g in $groups.Keys) {
    $list = @($groups[$g] | Sort-Object -Property { $_.From })
    $cur = $null
    $merged = [System.Collections.Generic.List[object]]::new()
    foreach ($i in $list) {
        if ($cur -and $i.From -le $cur.To.Add($gap)) {
            if ($i.To -gt $cur.To) { $cur.To = $i.To }
            if ($i.Collected -and (-not $cur.Collected -or $i.Collected -gt $cur.Collected)) { $cur.Collected = $i.Collected }
        }
        else { $cur = @{} + $i; $merged.Add($cur) }
    }
    for ($j = 0; $j -lt $merged.Count; $j++) {
        $m = $merged[$j]
        if ($m.To -le $cutoff) { continue }
        if ($m.From -lt $cutoff) { $m.From = $cutoff }
        if ($j -gt 0 -and $merged[$j - 1].To -gt $cutoff) {
            Write-Warning ("Coverage gap for {0} {1} {2}: {3:yyyy-MM-dd HH:mm} to {4:yyyy-MM-dd HH:mm} UTC. Use in that time is not known." -f `
                $m.Source, $m.Origin, $m.Feed, $merged[$j - 1].To, $m.From)
        }
        $covOut.Add([pscustomobject]@{ Source = $m.Source; Origin = $m.Origin; Feed = $m.Feed; Scope = $m.Scope
                                       From = (Format-UtcDate $m.From); To = (Format-UtcDate $m.To); Collected = (Format-UtcDate $m.Collected) })
    }
}

# =============================================================================================
# Write
# =============================================================================================

$out = foreach ($o in $store.Values) {
    $o.FirstSeen = Format-UtcDate $o.First; $o.LastSeen = Format-UtcDate $o.Last; $o.LastWrite = Format-UtcDate $o.Write
    $x = [ordered]@{}
    foreach ($c in $RowCols) { $x[$c] = $o[$c] }
    [pscustomobject]$x
}
$out = @($out | Sort-Object -Property Source, Origin, ObjectType, ObjectId, AccountKey)
Write-Atomic $out $storeFile $RowCols
Write-Atomic @($covOut | Sort-Object -Property Source, Origin, Feed, Scope, From) $covFile $CovCols

Write-Host ("Rows read: {0} ({1} unusable). Store: {2} before, {3} added, {4} updated, {5} removed by retention, {6} now. Written to {7}" -f `
    $read, $bad, $before, $added, $changed, $expired, $out.Count, $StorePath)
foreach ($c in $covOut) {
    Write-Host ("  {0,-9} {1,-30} {2,-24} {3} to {4}" -f $c.Source, $c.Origin, $c.Feed, $c.From.Substring(0, 10), $c.To.Substring(0, 10))
}
