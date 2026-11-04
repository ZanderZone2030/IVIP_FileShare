<#
.SYNOPSIS
    Writes the synthetic "Company X" file share audit logs the samples are built from. Every name, account, SID, IP
    address and ID here is made up.

.DESCRIPTION
    Server FS01, the accounts of the IVIP FileShare demo directory and the folders of samples\SampleScan.csv:
        samples\lastaccess\logs\FS01_Security_2026Q3.xml     5140 and 4663 events, 2026-07-01 to 2026-09-30,
        samples\lastaccess\logs\FS01_Security_2026-10.xml    and 2026-10-01 to 2026-10-21, as wevtutil /f:xml writes them
        samples\lastaccess\FS01_who_can_access.csv           who can reach which folder (input of Join-LastAccess.ps1)

    The behaviour is fixed (seeded random numbers), so the samples do not change between runs.
#>
#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$samples = Join-Path (Join-Path $root 'samples') 'lastaccess'
$inv = [System.Globalization.CultureInfo]::InvariantCulture
$rnd = [System.Random]::new(20261022)
$utf8 = [System.Text.UTF8Encoding]::new($false)

foreach ($d in @("$samples\logs")) {
    $d = $d.Replace('\', [System.IO.Path]::DirectorySeparatorChar)
    if (-not (Test-Path -LiteralPath $d)) { $null = New-Item -ItemType Directory -Path $d }
}
function Join-Sample { param([string]$Rel) Join-Path $samples $Rel.Replace('\', [System.IO.Path]::DirectorySeparatorChar) }

function Get-Utc { param([string]$Text) [DateTime]::SpecifyKind([DateTime]::ParseExact($Text, 'yyyy-MM-dd', $inv), [DateTimeKind]::Utc) }
function Format-Iso { param([DateTime]$Date, [switch]$Fraction)
    if ($Fraction) { $Date.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", $inv) } else { $Date.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", $inv) } }

function Get-Days {
    # Working days from Start to End (exclusive) on which a person shows up, about PerWeek times a week
    param([DateTime]$Start, [DateTime]$End, [double]$PerWeek)
    $d = $Start
    while ($d -lt $End) {
        if ($d.DayOfWeek -ne 'Saturday' -and $d.DayOfWeek -ne 'Sunday' -and $rnd.NextDouble() -lt ($PerWeek / 5.0)) {
            $d.AddMinutes(420 + $rnd.Next(0, 600)).AddSeconds($rnd.Next(0, 60))
        }
        $d = $d.AddDays(1)
    }
}

function Write-Csv {
    param($Rows, [string]$File)
    $text = ($Rows | ConvertTo-Csv -NoTypeInformation) -join "`r`n"
    [System.IO.File]::WriteAllText($File, $text + "`r`n", [System.Text.UTF8Encoding]::new($true))
}

# =============================================================================================
# File share FS01
# =============================================================================================

$sidBase = 'S-1-5-21-100-200-300'
$acct = [ordered]@{}            # sam -> SID (the RIDs of the mock directory)
$acct['jdoe'] = "$sidBase-1101"; $acct['old.user'] = "$sidBase-1102"; $acct['hr-lead'] = "$sidBase-1103"
foreach ($i in 1..6)  { $acct["hr.user$i"] = "$sidBase-$(1109 + $i)" }
foreach ($i in 1..40) { $acct[('fin.user{0:d2}' -f $i)] = "$sidBase-$(1200 + $i)" }
foreach ($i in 1..5)  { $acct["intern$i"] = "$sidBase-$(1300 + $i)" }
foreach ($i in 1..3)  { $acct["adm.$i"] = "$sidBase-$(1400 + $i)" }
foreach ($i in 1..20) { $acct[('user{0:d3}' -f $i)] = "$sidBase-$(5000 + $i)" }
$acct['ext.anna'] = "$sidBase-1501"; $acct['ext.bob'] = "$sidBase-1502"
$acct['WS-0042$'] = "$sidBase-2501"; $acct['svc-backup$'] = "$sidBase-2601"
foreach ($i in 21..300) { $acct[('user{0:d3}' -f $i)] = "$sidBase-$(5000 + $i)" }
$ipOf = @{}
$n = 20
foreach ($k in $acct.Keys) { $ipOf[$k] = '10.20.{0}.{1}' -f [int][Math]::Floor($n / 200), (10 + $n % 200); $n++ }

$shares = @{ Finance = 'D:\Shares\Finance'; HR = 'D:\Shares\HR'; Public = 'D:\Shares\Public'; Big = 'D:\Shares\Big' }
$start = Get-Utc '2026-07-01'; $q4 = Get-Utc '2026-10-01'; $end = Get-Utc '2026-10-22'

# Who connects to which share, how often, until when
$plans = [System.Collections.Generic.List[object]]::new()
function Add-Plan { param([string]$Sam, [string]$Share, [double]$PerWeek, [string]$Until = '2026-10-22', [string]$From = '2026-07-01')
    $plans.Add(@{ Sam = $Sam; Share = $Share; PerWeek = $PerWeek; From = (Get-Utc $From); Until = (Get-Utc $Until) }) }
foreach ($i in 1..12) {
    $u = '2026-10-22'
    if ($i -eq 5) { $u = '2026-07-14' }        # moved to another team in July
    if ($i -eq 9) { $u = '2026-07-20' }
    Add-Plan ('fin.user{0:d2}' -f $i) Finance 4 $u
}
Add-Plan 'jdoe' Finance 2; Add-Plan 'jdoe' HR 1; Add-Plan 'jdoe' Public 1
Add-Plan 'hr-lead' HR 4
foreach ($i in 1..6) { Add-Plan "hr.user$i" HR 4 $(if ($i -eq 4) { '2026-07-10' } else { '2026-10-22' }) }
Add-Plan 'intern1' Public 3; Add-Plan 'intern2' Public 3
Add-Plan 'intern1' Finance 2 '2026-08-15'      # summer intern, still in GG-Finance-Interns
Add-Plan 'ext.anna' Finance 3 '2026-07-15'     # consultant, project ended
foreach ($i in 1..10) { Add-Plan ('user{0:d3}' -f $i) Public 1 }
Add-Plan 'user015' Big 1 '2026-07-25'
# The rest of the people the shares reach, so every share and team shows used and unused people:
# the other GG-Finance-Team members, the GG-Big-n members and the staff behind BUILTIN\Users on Public
foreach ($i in 13..40) {
    if ($i % 13 -eq 0 -or $i % 7 -eq 0) { continue }                     # disabled accounts, and a few who never connect
    if ($i % 5 -eq 0) { Add-Plan ('fin.user{0:d2}' -f $i) Finance 2 ('2026-07-{0:d2}' -f (5 + $i % 20)) } else { Add-Plan ('fin.user{0:d2}' -f $i) Finance 3 }
}
foreach ($n in 1..17) {
    foreach ($u in @(($n + 1), ($n + 21))) {
        $sam = 'user{0:d3}' -f $u
        if ($sam -eq 'user015' -or ($u + $n) % 3 -eq 0) { continue }
        if (($u + $n) % 3 -eq 1) { Add-Plan $sam Big 1 } else { Add-Plan $sam Big 1 ('2026-07-{0:d2}' -f (3 + $u % 25)) }
    }
}
foreach ($i in 21..300) {
    $sam = 'user{0:d3}' -f $i
    switch ($i % 6) { 0 { Add-Plan $sam Public 0.6 } 1 { Add-Plan $sam Public 1 } 2 { Add-Plan $sam Public 0.5 ('2026-07-{0:d2}' -f (2 + $i % 26)) } default { } }
}

$events = [System.Collections.Generic.List[object]]::new()
function Add-Event { param([DateTime]$Time, [int]$Id, [string]$Sam, [hashtable]$Extra)
    $events.Add(@{ Time = $Time; Id = $Id; Sam = $Sam; Extra = $Extra }) }

foreach ($p in $plans) {
    foreach ($t in (Get-Days $p.From $p.Until $p.PerWeek)) {
        Add-Event $t 5140 $p.Sam @{ ShareName = "\\*\$($p.Share)"; ShareLocalPath = "\??\$($shares[$p.Share])" }
    }
}
# Noise that the collector must leave out: computer and service accounts, IPC$, admin shares, anonymous
foreach ($t in (Get-Days $start $end 5)) {
    Add-Event $t.Date.AddHours(1) 5140 'svc-backup$' @{ ShareName = '\\*\Finance'; ShareLocalPath = '\??\D:\Shares\Finance' }
    Add-Event $t.AddMinutes(-3) 5140 'WS-0042$' @{ ShareName = '\\*\Public'; ShareLocalPath = '\??\D:\Shares\Public' }
    Add-Event $t.AddMinutes(-1) 5140 'jdoe' @{ ShareName = '\\*\IPC$'; ShareLocalPath = '' }
}
foreach ($t in (Get-Days $start $end 1)) {
    Add-Event $t 5140 'adm.1' @{ ShareName = '\\*\D$'; ShareLocalPath = '\??\D:\' }
    Add-Event $t 5140 'ANONYMOUS LOGON' @{ ShareName = '\\*\IPC$'; ShareLocalPath = ''; Sid = 'S-1-5-7'; Domain = 'NT AUTHORITY' }
}

# 4663 on the audited folders: D:\Shares\HR since 2026-07-01, D:\Shares\Finance\Budget since 2026-10-01
function Add-FileUse { param([string]$Sam, [string]$File, [double]$PerWeek, [int]$Mask, [string]$From = '2026-07-01')
    foreach ($t in (Get-Days (Get-Utc $From) $end $PerWeek)) {
        Add-Event $t.AddMinutes(2) 4663 $Sam @{ ObjectName = $File; AccessMask = ('0x{0:x}' -f $Mask) }
    }
}
Add-FileUse 'hr.user1' 'D:\Shares\HR\Payroll\2026\Payroll run.xlsx' 2 0x2
Add-FileUse 'hr.user3' 'D:\Shares\HR\Payroll\2026\Payroll run.xlsx' 1 0x1
Add-FileUse 'hr-lead'  'D:\Shares\HR\Secret\Cases.docx' 1 0x1
Add-FileUse 'hr.user2' 'D:\Shares\HR\Secret\Cases.docx' 0.5 0x1
Add-FileUse 'hr.user2' 'D:\Shares\HR\Templates\Letter.dotx' 1 0x1
Add-FileUse 'hr.user5' 'D:\Shares\HR\Templates\Letter.dotx' 2 0x1
Add-FileUse 'hr.user6' 'D:\Shares\HR\Templates\Letter.dotx' 2 0x6
Add-FileUse 'jdoe'      'D:\Shares\Finance\Budget\2026\Q1\Forecast.xlsx' 1 0x1 '2026-10-01'
Add-FileUse 'fin.user01' 'D:\Shares\Finance\Budget\2026\Budget.xlsx' 2 0x2 '2026-10-01'
Add-FileUse 'fin.user02' 'D:\Shares\Finance\Budget\2026\Budget.xlsx' 1 0x1 '2026-10-01'
Add-FileUse 'fin.user03' 'D:\Shares\Finance\Budget\2026\Q1\Forecast.xlsx' 1 0x10000 '2026-10-01'
# A 4663 on a folder that is not audited any more must not count as coverage, but its row still counts as use
Add-Event ((Get-Utc '2026-07-03').AddHours(9)) 4663 'fin.user04' @{ ObjectName = 'D:\Shares\Finance\Budget\2026\Q1\Old.xlsx'; AccessMask = '0x1' }

$ordered = @($events | Sort-Object -Property { $_.Time })
$record = 4800000
function Write-EventXml {
    param([string]$File, [DateTime]$From, [DateTime]$To)
    $sb = [System.Text.StringBuilder]::new()
    foreach ($e in $ordered) {
        if ($e.Time -lt $From -or $e.Time -ge $To) { continue }
        $script:record++
        $sid = if ($e.Extra.Sid) { $e.Extra.Sid } else { $acct[$e.Sam] }
        $dom = if ($e.Extra.Domain) { $e.Extra.Domain } else { 'CORP' }
        $logon = '0x{0:x}' -f (0x3a0000 + ($script:record % 65536))
        $task = if ($e.Id -eq 5140) { 12808 } else { 12800 }
        [void]$sb.Append("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>")
        [void]$sb.Append("<EventID>$($e.Id)</EventID><Version>1</Version><Level>0</Level><Task>$task</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords>")
        [void]$sb.Append("<TimeCreated SystemTime='$(Format-Iso $e.Time -Fraction)'/><EventRecordID>$($script:record)</EventRecordID><Correlation/>")
        [void]$sb.Append("<Execution ProcessID='4' ThreadID='$(5000 + $script:record % 400)'/><Channel>Security</Channel><Computer>FS01.corp.local</Computer><Security/></System><EventData>")
        $data = [ordered]@{ SubjectUserSid = $sid; SubjectUserName = $e.Sam; SubjectDomainName = $dom; SubjectLogonId = $logon }
        if ($e.Id -eq 5140) {
            $data.ObjectType = 'File'; $data.IpAddress = $(if ($ipOf[$e.Sam]) { $ipOf[$e.Sam] } else { '10.20.9.9' }); $data.IpPort = [string](49152 + $script:record % 16000)
            $data.ShareName = $e.Extra.ShareName; $data.ShareLocalPath = $e.Extra.ShareLocalPath; $data.AccessMask = '0x1'; $data.AccessList = '%%4416'
        }
        else {
            $data.ObjectServer = 'Security'; $data.ObjectType = 'File'; $data.ObjectName = $e.Extra.ObjectName; $data.HandleId = '0x1a2c'
            $data.AccessList = '%%4416'; $data.AccessMask = $e.Extra.AccessMask; $data.ProcessId = '0x4'; $data.ProcessName = ''; $data.ResourceAttributes = ''
        }
        foreach ($k in $data.Keys) { [void]$sb.Append("<Data Name='$k'>$([System.Security.SecurityElement]::Escape([string]$data[$k]))</Data>") }
        [void]$sb.Append("</EventData></Event>`r`n")
    }
    [System.IO.File]::WriteAllText($File, $sb.ToString(), $utf8)
}
Write-EventXml (Join-Sample 'logs\FS01_Security_2026Q3.xml') $start $q4
Write-EventXml (Join-Sample 'logs\FS01_Security_2026-10.xml') $q4 $end

# Who can reach which folder (normally from the permission graph; here written by hand to match SampleScan.csv)
$reach = [System.Collections.Generic.List[object]]::new()
function Add-Reach { param([string]$Folder, [string[]]$Sams, [string]$Rights, [string]$Via)
    foreach ($s in $Sams) { $reach.Add([pscustomobject]@{ FolderPath = $Folder; Account = "CORP\$s"; Rights = $Rights; Via = $Via }) } }
$finTeam = @(1..40 | ForEach-Object { 'fin.user{0:d2}' -f $_ })
Add-Reach 'D:\Shares\Finance' ($finTeam + 'ext.anna') 'Modify' 'GG-Finance-Team'
Add-Reach 'D:\Shares\Finance' @('jdoe') 'Modify' 'GG-Shares-RW'
Add-Reach 'D:\Shares\Finance\Budget' @('fin.user01', 'fin.user02', 'fin.user03', 'fin.user05') 'Modify' 'GG-Finance-Team'
Add-Reach 'D:\Shares\Finance\Budget' @('intern1', 'intern2') 'ReadAndExecute' 'GG-Finance-Interns'
Add-Reach 'D:\Shares\Finance\Budget' @('jdoe') 'FullControl' 'CORP\jdoe (own entry)'
Add-Reach 'D:\Shares\HR' (@(1..6 | ForEach-Object { "hr.user$_" }) + 'hr-lead') 'Modify' 'GG-HR-RW'
Add-Reach 'D:\Shares\HR\Payroll' @('hr.user1', 'hr.user3', 'hr.user4', 'hr.user5', 'hr-lead') 'Modify' 'GG-HR-RW'
Add-Reach 'D:\Shares\HR\Secret' @('hr-lead', 'hr.user2', 'jdoe') 'Modify' 'CORP\hr-lead; GG-HR-RW'
Add-Reach 'D:\Shares\Public' (@(1..300 | ForEach-Object { 'user{0:d3}' -f $_ }) + 'intern1' + 'intern2' + 'ext.bob') 'ReadAndExecute' 'BUILTIN\Users'
foreach ($n in 1..17) { Add-Reach 'D:\Shares\Big' @(('user{0:d3}' -f ($n + 1)), ('user{0:d3}' -f ($n + 21))) 'ReadAndExecute' "GG-Big-$n" }
Write-Csv $reach (Join-Sample 'FS01_who_can_access.csv')

Write-Host ("Sample logs: {0} file share events." -f $ordered.Count)
