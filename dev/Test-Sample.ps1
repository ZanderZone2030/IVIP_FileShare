<#
.SYNOPSIS
    Runs the file share last-access chain on the synthetic Company X data, without a file server, and
    writes the samples.

.DESCRIPTION
    1. dev\New-SampleLogs.ps1 writes the Security log exports (event XML) of FS01 and the folder access list.
    2. Get-ShareAccessEvents.ps1 reads them in two runs: 2026-07-01 to 2026-10-01 (HR audited), then
       to 2026-10-22 (HR and Finance\Budget audited).
    3. Merge-LastAccess.ps1 folds the runs into samples\lastaccess\store one at a time, then merges everything a
       second time to show that the result does not change.
    4. Join-LastAccess.ps1 adds "last used" to samples\lastaccess\FS01_who_can_access.csv.
#>
#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
function P { param([string]$Rel) Join-Path $root $Rel.Replace('\', [System.IO.Path]::DirectorySeparatorChar) }

& (P 'dev\New-SampleLogs.ps1')

$runs = P 'samples\lastaccess\runs'
$store = P 'samples\lastaccess\store'
if (Test-Path -LiteralPath $store) { Remove-Item -LiteralPath $store -Recurse -Force }
if (-not (Test-Path -LiteralPath $runs)) { $null = New-Item -ItemType Directory -Path $runs }
foreach ($r in @(Get-ChildItem -LiteralPath $runs -Directory | ForEach-Object { $_.Name })) {
    $d = Join-Path $runs $r
    if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }
}
$asOf = [datetime]'2026-10-22T06:00:00'

& (P 'scripts\Get-ShareAccessEvents.ps1') -XmlPath (P 'samples\lastaccess\logs\FS01_Security_2026Q3.xml') -Since '2026-07-01' -Until '2026-10-01' `
    -FolderListPath (P 'samples\SampleScan.csv') -AuditedFolder 'D:\Shares\HR' -OutputFolder (Join-Path $runs 'fs01-2026q3')
& (P 'scripts\Get-ShareAccessEvents.ps1') -XmlPath (P 'samples\lastaccess\logs\FS01_Security_2026-10.xml') -Since '2026-10-01' -Until '2026-10-22' `
    -FolderListPath (P 'samples\SampleScan.csv') -AuditedFolder 'D:\Shares\HR', 'D:\Shares\Finance\Budget' -OutputFolder (Join-Path $runs 'fs01-2026-10')

# One merge per run, the way a daily task would add them
foreach ($r in 'fs01-2026q3', 'fs01-2026-10') {
    & (P 'scripts\Merge-LastAccess.ps1') -Path (Join-Path $runs $r) -StorePath $store -AsOf $asOf
}
$first = [System.IO.File]::ReadAllText((Join-Path $store 'lastaccess.csv'))
$firstCov = [System.IO.File]::ReadAllText((Join-Path $store 'coverage.csv'))

# Merging everything again must not change anything
$all = @(Get-ChildItem -LiteralPath $runs -Directory | ForEach-Object { $_.FullName })
& (P 'scripts\Merge-LastAccess.ps1') -Path $all -StorePath $store -AsOf $asOf
if ([System.IO.File]::ReadAllText((Join-Path $store 'lastaccess.csv')) -ne $first -or
    [System.IO.File]::ReadAllText((Join-Path $store 'coverage.csv')) -ne $firstCov) { throw 'Merging the same runs again changed the store.' }
Write-Host 'Second merge of the same runs: store unchanged.'
Get-ChildItem -LiteralPath $store -Filter '*.bak' | Remove-Item -Force

& (P 'scripts\Join-LastAccess.ps1') -AccessPath (P 'samples\lastaccess\FS01_who_can_access.csv') -StorePath $store -FileServer FS01
