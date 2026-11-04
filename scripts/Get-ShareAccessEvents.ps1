<#
.SYNOPSIS
    Reads file share audit events (5140, and optionally 4663 / 5145) and writes who last used which
    share or folder, in the last-access layout read by Merge-LastAccess.ps1.

.DESCRIPTION
    No store in Windows keeps "last access per user per folder", so it is read from the Security log.

      5140  A network share object was accessed. Audit policy "Audit File Share" (Success).
            One event per SMB session and share, so it tells who connected to which share and when.
            Recommended: cheap, no SACL needed, covers every share on the server.
      4663  An attempt was made to access an object. Audit policy "Audit File System" plus a SACL
            on the folder. Tells which folder was used and whether something was written. Set it
            only on sensitive folders: it is very noisy.
      5145  A network share object was checked for access ("Audit Detailed File Share"). Per file,
            very noisy. Read only when asked for with -EventId.

    Sources, pick one:
      (default)     the Security log of this computer, or of -ComputerName (Event Log Readers rights,
                    "Remote Event Log Management" firewall rule)
      -LogName      another log, e.g. ForwardedEvents on a Windows Event Forwarding collector
      -EvtxPath     saved .evtx files (Windows only)
      -XmlPath      events exported as XML: wevtutil qe Security /q:"*[System[(EventID=5140)]]" /f:xml
      -CsvPath      a SIEM export with one row per event: TimeCreated, EventID, Computer and the event
                    data fields by name (SubjectUserSid, SubjectUserName, SubjectDomainName, IpAddress,
                    ShareName, ShareLocalPath, ObjectName, RelativeTargetName, AccessMask)

    Events are folded into one row per object and account: first and last time seen, the last write
    (4663 / 5145 with a write, append or delete right), the number of events and the last client address.
    The objects use the server's local path (D:\Shares\Finance), the same as the FolderPath column of
    Get-FolderPermissions.ps1, so the rows join directly to a scan.

      - 5140 rows have ObjectType Share and the share's local path.
      - 4663 / 5145 rows have ObjectType Folder. The file is rolled up to the deepest folder of
        -FolderListPath (a scan CSV) that contains it, or else to its parent folder, at most
        -FolderDepth levels below the share root.

    Computer accounts (name ending in $), SYSTEM, LOCAL SERVICE, NETWORK SERVICE, ANONYMOUS LOGON and
    the shares in -ExcludeShare are left out.

    Writes two CSV files (UTF-8 with BOM) into -OutputFolder:
      lastaccess.csv  one row per object and account
      coverage.csv    which period each server and event ID covers. Merge-LastAccess.ps1 needs it to
                      tell "not used" from "not watched".

    The output names accounts and folders. Treat it as sensitive.

.PARAMETER ComputerName
    File servers whose Security log is read. Default: this computer.

.PARAMETER LogName
    Log to read on the computers. Default Security. Use ForwardedEvents on an event collector; the
    events keep the name of the server they came from.

.PARAMETER EvtxPath
    Saved .evtx files to read instead of a live log.

.PARAMETER XmlPath
    Event XML files (wevtutil /f:xml, or Get-WinEvent ... | ForEach-Object ToXml) to read instead of
    a live log.

.PARAMETER CsvPath
    SIEM export files to read instead of a live log. Comma, semicolon or tab separated.

.PARAMETER EventId
    Event IDs to read. Default 5140 and 4663. Add 5145 only if detailed file share auditing is on.

.PARAMETER Since
    Read events from this time. Default: everything in the log, or the end of the period already in
    -StorePath for that server.

.PARAMETER Until
    Read events up to this time. Default: now.

.PARAMETER StorePath
    The last-access store folder (Merge-LastAccess.ps1 -StorePath). When set and -Since is not, each
    server is read from where the store's coverage ends, so a daily run only reads new events.

.PARAMETER FolderListPath
    A Get-FolderPermissions.ps1 scan CSV. 4663 / 5145 events are rolled up to the folders listed there,
    so the rows match the folders of the permission graph exactly.

.PARAMETER FolderDepth
    When there is no -FolderListPath: how many folder levels below the share root to keep for 4663 /
    5145 events. Default 3.

.PARAMETER AuditedFolder
    Local paths of the folders that have a 4663 SACL. Written to coverage.csv as the scope of the
    4663 data (one row per folder), so only those folders are judged on folder-level use. Default:
    the share roots that produced 4663 events.

.PARAMETER ExcludeShare
    Share names to leave out. Default IPC$, ADMIN$, print$, SYSVOL, NETLOGON and the drive shares (C$, D$...).

.PARAMETER IncludeComputerAccounts
    Keep computer and managed service accounts (names ending in $).

.PARAMETER OutputFolder
    Folder for the CSV files. Default: .\ShareAccess_<yyyyMMdd_HHmm>. Created if needed.

.EXAMPLE
    .\Get-ShareAccessEvents.ps1 -ComputerName FS01, FS02 -StorePath \\admin01\ivip\lastaccess

    Daily run on two file servers, from where the store ends.

.EXAMPLE
    .\Get-ShareAccessEvents.ps1 -LogName ForwardedEvents -FolderListPath .\FS01_scan.csv -AuditedFolder 'D:\Shares\HR', 'D:\Shares\Finance'

    On a Windows Event Forwarding collector, with folder-level events from two audited folders.

.EXAMPLE
    .\Get-ShareAccessEvents.ps1 -CsvPath .\siem_5140_export.csv -Since 2026-07-01 -Until 2026-10-01
#>
#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'Live')]
param(
    [Parameter(ParameterSetName = 'Live')]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter(ParameterSetName = 'Live')]
    [string]$LogName = 'Security',

    [Parameter(ParameterSetName = 'Evtx', Mandatory = $true)]
    [string[]]$EvtxPath,

    [Parameter(ParameterSetName = 'Xml', Mandatory = $true)]
    [string[]]$XmlPath,

    [Parameter(ParameterSetName = 'Csv', Mandatory = $true)]
    [string[]]$CsvPath,

    [int[]]$EventId = @(5140, 4663),

    [Nullable[datetime]]$Since,

    [Nullable[datetime]]$Until,

    [string]$StorePath,

    [string]$FolderListPath,

    [ValidateRange(0, 50)]
    [int]$FolderDepth = 3,

    [string[]]$AuditedFolder,

    [string[]]$ExcludeShare = @('IPC$', 'ADMIN$', 'print$', 'SYSVOL', 'NETLOGON'),

    [switch]$IncludeComputerAccounts,

    [string]$OutputFolder
)

$ErrorActionPreference = 'Stop'
$script:IsCore = $PSVersionTable.PSVersion.Major -ge 6
$script:Inv = [System.Globalization.CultureInfo]::InvariantCulture
$collected = [DateTime]::UtcNow

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

function Get-ShortHost {
    # FS01.corp.local -> FS01
    param([string]$Name)
    $n = ([string]$Name).Trim()
    if (-not $n) { return '' }
    $i = $n.IndexOf('.')
    if ($i -gt 0) { $n = $n.Substring(0, $i) }
    $n.ToUpperInvariant()
}

function Get-CleanPath {
    # \??\D:\Shares\Finance\ -> D:\Shares\Finance
    param([string]$Path)
    $p = ([string]$Path).Trim()
    if ($p.StartsWith('\??\')) { $p = $p.Substring(4) }
    if ($p.Length -gt 3) { $p = $p.TrimEnd('\') }
    $p
}

function Get-ParentPath {
    # D:\Shares\Finance -> D:\Shares; D:\Shares -> D:\; D:\ -> '' (string based, so it works the same on every OS)
    param([string]$Path)
    $i = $Path.LastIndexOf('\')
    if ($i -lt 0) { return '' }
    $p = if ($i -eq 2 -and $Path[1] -eq ':') { $Path.Substring(0, 3) } else { $Path.Substring(0, $i) }
    if ($p -eq $Path) { return '' }
    $p
}

function Test-UnderPath {
    param([string]$Path, [string]$Root)
    if (-not $Root) { return $false }
    if ($Path.Equals($Root, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    $r = if ($Root.EndsWith('\')) { $Root } else { $Root + '\' }
    $Path.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)
}

# =============================================================================================
# Settings
# =============================================================================================

$SkipSids = @{ 'S-1-5-18' = 1; 'S-1-5-19' = 1; 'S-1-5-20' = 1; 'S-1-5-7' = 1; 'S-1-0-0' = 1 }
$excluded = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($s in $ExcludeShare) { if ($s) { $null = $excluded.Add($s.Trim().TrimStart('\', '*')) } }
$wanted = @{}
foreach ($i in $EventId) { $wanted[[int]$i] = $true }
$WriteMask = 0x2 -bor 0x4 -bor 0x40 -bor 0x10000      # WriteData, AppendData, DeleteChild, DELETE

$sinceUtc = if ($Since) { ConvertTo-UtcDate $Since } else { $null }
$untilUtc = if ($Until) { ConvertTo-UtcDate $Until } else { $collected }

# Known folders from a scan
$knownFolders = $null
if ($FolderListPath) {
    $knownFolders = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in (Import-AnyCsv $FolderListPath)) { $p = Get-CleanPath $r.FolderPath; if ($p) { $null = $knownFolders.Add($p) } }
    Write-Verbose "Folder list: $($knownFolders.Count) folders."
}

# Where the store's coverage ends, per server and event ID
$storeEnd = @{}
if ($StorePath) {
    $covFile = Join-Path $StorePath 'coverage.csv'
    if (Test-Path -LiteralPath $covFile) {
        foreach ($c in (Import-AnyCsv $covFile)) {
            if ($c.Source -ne 'FileShare') { continue }
            $to = ConvertTo-UtcDate $c.To
            $k = ('{0}|{1}' -f $c.Origin, $c.Feed).ToUpperInvariant()
            if ($to -and (-not $storeEnd.ContainsKey($k) -or $to -gt $storeEnd[$k])) { $storeEnd[$k] = $to }
        }
    }
}

# =============================================================================================
# Fold events into rows
# =============================================================================================

$rows     = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$coverage = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$shareMap = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)   # origin|local path -> share name
$roots4663 = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)  # origin -> set of roots
$script:Read = 0; $script:Kept = 0; $script:Skipped = 0

function Get-ShareRoot {
    # The local path of the share that contains a path on this server, from the 5140 / 5145 events seen
    param([string]$Origin, [string]$Path)
    $best = ''
    foreach ($k in $shareMap.Keys) {
        $bar = $k.IndexOf('|')
        if (-not $k.Substring(0, $bar).Equals($Origin, [StringComparison]::OrdinalIgnoreCase)) { continue }
        $root = $k.Substring($bar + 1)
        if ((Test-UnderPath $Path $root) -and $root.Length -gt $best.Length) { $best = $root }
    }
    $best
}

$folderCache = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)

function Get-FolderFor {
    # Folder a file event is counted on: the deepest scanned folder that holds it, else its parent
    # folder cut to -FolderDepth levels below the share root
    param([string]$Origin, [string]$Path)
    $ck = "$Origin|$Path"
    $hit = $null
    if ($folderCache.TryGetValue($ck, [ref]$hit)) { return $hit }
    $hit = Find-Folder $Origin $Path
    $folderCache[$ck] = $hit
    $hit
}

function Find-Folder {
    param([string]$Origin, [string]$Path)
    if ($knownFolders) {
        $p = $Path
        while ($p) {
            if ($knownFolders.Contains($p)) { return $p }
            $p = Get-ParentPath $p
        }
    }
    $parent = Get-ParentPath $Path
    if (-not $parent) { $parent = $Path }
    if ($parent.Length -gt 3) { $parent = $parent.TrimEnd('\') }
    $root = Get-ShareRoot $Origin $parent
    $parts = $parent.Split('\')
    $base = if ($root) { $root.Split('\').Count } else { 1 }
    if ($parts.Count -gt $base + $FolderDepth) { $parent = ($parts[0..($base + $FolderDepth - 1)]) -join '\' }
    $parent
}

function Add-Coverage {
    param([string]$Origin, [int]$Id, [DateTime]$Time)
    $k = "$Origin|$Id"
    $c = $null
    if (-not $coverage.TryGetValue($k, [ref]$c)) {
        $c = @{ Origin = $Origin; Feed = [string]$Id; First = $Time; Last = $Time; Events = 0; LogStart = $null }
        $coverage[$k] = $c
    }
    if ($Time -lt $c.First) { $c.First = $Time }
    if ($Time -gt $c.Last) { $c.Last = $Time }
    $c.Events++
}

function Add-ShareEvent {
    # One audit event: Time (UTC), Id, Computer and the event data fields by name
    param([DateTime]$Time, [int]$Id, [string]$Computer, [hashtable]$Data)
    $script:Read++
    if (-not $wanted.ContainsKey($Id)) { return }
    if ($sinceUtc -and $Time -lt $sinceUtc) { return }
    if ($Time -gt $untilUtc) { return }
    $origin = Get-ShortHost $Computer
    $sid  = [string]$Data['SubjectUserSid']
    $name = [string]$Data['SubjectUserName']
    $dom  = [string]$Data['SubjectDomainName']
    $sk = "$origin|$Id".ToUpperInvariant()
    if ($storeEnd.ContainsKey($sk) -and -not $sinceUtc -and $Time -le $storeEnd[$sk]) { return }
    Add-Coverage $origin $Id $Time

    if ($SkipSids.ContainsKey($sid) -or -not $name -or $name -eq '-') { $script:Skipped++; return }
    if (-not $IncludeComputerAccounts -and $name.EndsWith('$')) { $script:Skipped++; return }

    $share = [string]$Data['ShareName']                       # \\*\Finance
    $shareBare = $share.TrimStart('\', '*')
    $local = Get-CleanPath ([string]$Data['ShareLocalPath'])
    if ($shareBare -and ($excluded.Contains($shareBare) -or $shareBare -match '^[A-Za-z]\$$')) { $script:Skipped++; return }
    if ($shareBare -and $local) { $shareMap["$origin|$local"] = $shareBare }

    $mask = 0
    $m = [string]$Data['AccessMask']
    if ($m) { try { $mask = if ($m.StartsWith('0x')) { [Convert]::ToInt32($m.Substring(2), 16) } else { [int]$m } } catch { $mask = 0 } }

    switch ($Id) {
        5140 { $type = 'Share'; $object = $local; $write = $false }
        5145 {
            $type = 'Folder'
            $rel = ([string]$Data['RelativeTargetName']).Trim('\')
            $full = if ($rel) { "$local\$rel" } else { $local }
            $object = if ($rel) { Get-FolderFor $origin $full } else { $local }
            $write = ($mask -band $WriteMask) -ne 0
        }
        4663 {
            $type = 'Folder'
            $full = Get-CleanPath ([string]$Data['ObjectName'])
            if (-not $full -or ([string]$Data['ObjectType']) -notin @('File', '')) { $script:Skipped++; return }
            $object = Get-FolderFor $origin $full
            $write = ($mask -band $WriteMask) -ne 0
            $set = $null
            if (-not $roots4663.TryGetValue($origin, [ref]$set)) {
                $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase); $roots4663[$origin] = $set
            }
            $null = $set.Add($object)
        }
        default { return }
    }
    if (-not $object) { $script:Skipped++; return }

    $acct = if ($dom -and $dom -ne '-') { "$dom\$name" } else { $name }
    $key = "$origin|$type|$object|$name"
    $r = $null
    if (-not $rows.TryGetValue($key, [ref]$r)) {
        $r = @{ Origin = $origin; Type = $type; Object = $object; Share = $shareBare; Key = $name.ToLowerInvariant(); Account = $acct; Sid = $sid
                First = $Time; Last = $Time; Write = $null; Events = 0; Client = '' }
        $rows[$key] = $r
    }
    if ($Time -lt $r.First) { $r.First = $Time }
    if ($Time -ge $r.Last) {
        $r.Last = $Time
        $ip = ([string]$Data['IpAddress']) -replace '^::ffff:', ''
        if ($ip -and $ip -ne '-') { $r.Client = $ip }
    }
    if ($write -and ($null -eq $r.Write -or $Time -gt $r.Write)) { $r.Write = $Time }
    if (-not $r.Share -and $shareBare) { $r.Share = $shareBare }
    $r.Events++
    $script:Kept++
}

function Read-EventXml {
    # One <Event> element (Get-WinEvent ToXml or wevtutil /f:xml)
    param([System.Xml.XmlElement]$Event)
    $sys = $Event.System
    $id = [int]([string]$sys.EventID.InnerText)
    if (-not $id) { $id = [int]([string]$sys.EventID) }
    $time = ConvertTo-UtcDate $sys.TimeCreated.SystemTime
    $data = @{}
    foreach ($d in @($Event.EventData.Data)) {
        if ($null -eq $d) { continue }
        $n = $d.GetAttribute('Name')
        if ($n) { $data[$n] = $d.InnerText }
    }
    Add-ShareEvent $time $id ([string]$sys.Computer) $data
}

# =============================================================================================
# Read
# =============================================================================================

$logStart = @{}     # origin -> oldest event in the live log

switch ($PSCmdlet.ParameterSetName) {
    'Xml' {
        $settings = [System.Xml.XmlReaderSettings]::new()
        $settings.ConformanceLevel = [System.Xml.ConformanceLevel]::Fragment
        $settings.IgnoreWhitespace = $true
        foreach ($f in $XmlPath) {
            $reader = [System.Xml.XmlReader]::Create((Resolve-Path -LiteralPath $f).ProviderPath, $settings)
            try {
                while (-not $reader.EOF) {
                    if ($reader.NodeType -eq [System.Xml.XmlNodeType]::Element -and $reader.LocalName -eq 'Event') {
                        $doc = [System.Xml.XmlDocument]::new()
                        $doc.Load($reader.ReadSubtree())
                        Read-EventXml $doc.DocumentElement
                        $reader.Skip()
                    }
                    else { $null = $reader.Read() }
                }
            }
            finally { $reader.Dispose() }
        }
    }
    'Csv' {
        foreach ($f in $CsvPath) {
            foreach ($r in (Import-AnyCsv $f)) {
                $data = @{}
                foreach ($p in $r.PSObject.Properties) { $data[$p.Name] = [string]$p.Value }
                $t = $null; $i = 0; $c = ''
                foreach ($n in 'TimeCreated', 'TimeGenerated', 'Timestamp', '_time', 'EventTime') { if ($data[$n]) { $t = ConvertTo-UtcDate $data[$n]; break } }
                foreach ($n in 'EventID', 'EventCode', 'Id') { if ($data[$n]) { $i = [int]$data[$n]; break } }
                foreach ($n in 'Computer', 'ComputerName', 'MachineName', 'Host') { if ($data[$n]) { $c = $data[$n]; break } }
                if ($t -and $i) { Add-ShareEvent $t $i $c $data }
            }
        }
    }
    default {
        $filter = @{ Id = $EventId }
        $targets = if ($PSCmdlet.ParameterSetName -eq 'Evtx') { @($EvtxPath) } else { @($ComputerName) }
        foreach ($t in $targets) {
            $f = $filter.Clone()
            $common = @{ ErrorAction = 'Stop' }
            if ($PSCmdlet.ParameterSetName -eq 'Evtx') { $f['Path'] = (Resolve-Path -LiteralPath $t).ProviderPath }
            else {
                $f['LogName'] = $LogName
                if ($t -and $t -ne $env:COMPUTERNAME) { $common['ComputerName'] = $t }
                if ($LogName -eq 'Security') {
                    try {
                        $oldest = Get-WinEvent -LogName $LogName -MaxEvents 1 -Oldest @common
                        $logStart[(Get-ShortHost $(if ($t) { $t } else { $env:COMPUTERNAME }))] = $oldest.TimeCreated.ToUniversalTime()
                    }
                    catch { Write-Warning "Cannot read the oldest event of $LogName on ${t}: $($_.Exception.Message)" }
                }
            }
            $start = $sinceUtc
            if (-not $start -and $PSCmdlet.ParameterSetName -eq 'Live' -and $storeEnd.Count) {
                $ends = @($storeEnd.Keys | Where-Object { $_.StartsWith((Get-ShortHost $t) + '|') } | ForEach-Object { $storeEnd[$_] })
                if ($ends.Count) { $start = ($ends | Measure-Object -Minimum).Minimum }
            }
            if ($start) { $f['StartTime'] = $start.ToLocalTime() }
            $f['EndTime'] = $untilUtc.ToLocalTime()
            Write-Verbose "Reading $t ..."
            try {
                Get-WinEvent -FilterHashtable $f @common | ForEach-Object {
                    $x = [xml]$_.ToXml()
                    Read-EventXml $x.DocumentElement
                }
            }
            catch {
                if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { Write-Warning "No events $($EventId -join ', ') on $t in this period." }
                else { Write-Warning "Cannot read ${t}: $($_.Exception.Message)" }
            }
        }
    }
}

# =============================================================================================
# Write
# =============================================================================================

if (-not $OutputFolder) { $OutputFolder = Join-Path (Get-Location).Path ('ShareAccess_{0:yyyyMMdd_HHmm}' -f (Get-Date)) }
if (-not (Test-Path -LiteralPath $OutputFolder)) { $null = New-Item -ItemType Directory -Path $OutputFolder }

$out = [System.Collections.Generic.List[object]]::new()
foreach ($r in $rows.Values) {
    $shareName = ''
    if ($r.Type -eq 'Share') { $shareName = $shareMap["$($r.Origin)|$($r.Object)"] }
    else {
        $root = Get-ShareRoot $r.Origin $r.Object
        if ($root) { $shareName = $shareMap["$($r.Origin)|$root"] + $r.Object.Substring($root.Length) }
    }
    $out.Add([pscustomobject]@{
        Source = 'FileShare'; Origin = $r.Origin; ObjectType = $r.Type; ObjectId = $r.Object
        ObjectName = $(if ($shareName) { "\\$($r.Origin)\$shareName" } else { '' })
        AccountKey = $r.Key; Account = $r.Account; AccountSid = $r.Sid; AccountId = ''; DisplayName = ''
        FirstSeen = (Format-UtcDate $r.First); LastSeen = (Format-UtcDate $r.Last); LastWrite = (Format-UtcDate $r.Write)
        Events = $r.Events; LastClient = $r.Client
    })
}
$out = @($out | Sort-Object -Property Origin, ObjectType, ObjectId, AccountKey)

$cov = [System.Collections.Generic.List[object]]::new()
foreach ($c in $coverage.Values) {
    $from = if ($sinceUtc) { $sinceUtc } else { $c.First }
    $k = "$($c.Origin)|$($c.Feed)".ToUpperInvariant()
    if (-not $sinceUtc -and $storeEnd.ContainsKey($k)) { $from = $storeEnd[$k] }
    if ($logStart.ContainsKey($c.Origin) -and $logStart[$c.Origin] -gt $from) {
        Write-Warning ("{0}: the Security log only goes back to {1:u}; events before that are lost. Run more often or forward the events." -f $c.Origin, $logStart[$c.Origin])
        $from = $logStart[$c.Origin]
    }
    $to = if ($Until -or $PSCmdlet.ParameterSetName -eq 'Live') { $untilUtc } else { $c.Last }
    # 5140 covers every share of the server. 4663 / 5145 cover the audited folders: one row each, so
    # a folder keeps its own continuous period when more folders are audited later
    $scopes = @('*')
    if ($c.Feed -ne '5140') {
        if ($AuditedFolder) { $scopes = @($AuditedFolder | ForEach-Object { Get-CleanPath $_ }) }
        elseif ($roots4663.ContainsKey($c.Origin)) {
            $tops = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($o in $roots4663[$c.Origin]) { $root = Get-ShareRoot $c.Origin $o; $null = $tops.Add($(if ($root) { $root } else { $o })) }
            $scopes = @($tops | Sort-Object)
        }
    }
    foreach ($scope in $scopes) {
        $cov.Add([pscustomobject]@{
            Source = 'FileShare'; Origin = $c.Origin; Feed = $c.Feed; Scope = $scope
            From = (Format-UtcDate $from); To = (Format-UtcDate $to); Events = $c.Events; Collected = (Format-UtcDate $collected)
        })
    }
}
foreach ($i in $EventId) {
    if (-not @($cov | Where-Object { $_.Feed -eq [string]$i }).Count) {
        Write-Warning "No $i events were found. Check the audit policy ($(if ($i -eq 5140) { 'Audit File Share' } elseif ($i -eq 5145) { 'Audit Detailed File Share' } else { 'Audit File System and a SACL' }))."
    }
}

$cols = 'Source', 'Origin', 'ObjectType', 'ObjectId', 'ObjectName', 'AccountKey', 'Account', 'AccountSid', 'AccountId', 'DisplayName',
        'FirstSeen', 'LastSeen', 'LastWrite', 'Events', 'LastClient'
Export-Utf8Csv $out (Join-Path $OutputFolder 'lastaccess.csv') $cols
Export-Utf8Csv @($cov | Sort-Object -Property Origin, Feed, Scope) (Join-Path $OutputFolder 'coverage.csv') @('Source', 'Origin', 'Feed', 'Scope', 'From', 'To', 'Events', 'Collected')

Write-Host ("Events read: {0}, counted: {1}, left out: {2}. Rows: {3}. Written to {4}" -f $script:Read, $script:Kept, $script:Skipped, $out.Count, $OutputFolder)
