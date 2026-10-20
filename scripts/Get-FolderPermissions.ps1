<#
.SYNOPSIS
    Recursively maps every folder under a parent path and exports its NTFS permissions to CSV.

.DESCRIPTION
    Walks the whole folder tree starting at -Path (the parent folder itself included) and writes
    one CSV row per access control entry (ACE) per folder, in tree order.

    Folders that cannot be read are still written, with the error in the Note column, so the
    report shows exactly where coverage is missing instead of silently skipping them.

    Junctions and symbolic links are reported but not descended into, to avoid loops and
    double-counting.

    Output columns:
      FolderPath          Full path of the folder
      Depth               0 = the parent folder, 1 = its direct subfolders, ...
      Owner               Folder owner
      InheritanceDisabled True when inheritance is broken on this folder
      Identity            User / group the ACE applies to
      Rights              FullControl, Modify, ReadAndExecute, ... (generic rights translated)
      AccessType          Allow / Deny
      IsInherited         True = inherited from a parent, False = set explicitly on this folder
      AppliesTo           Same wording as the Advanced Security dialog ("This folder, subfolders and files", ...)
      UnresolvedSid       True when the identity is a SID that no longer resolves (deleted / orphaned account)
      Note                Errors, or a remark for junctions / empty DACLs

.PARAMETER Path
    Parent folder to start from. Local path or UNC, e.g. D:\Data or \\fileserver\share.

.PARAMETER OutputPath
    CSV file to write. Default: FolderPermissions_<timestamp>.csv in the current directory.

.PARAMETER MaxDepth
    How many levels below -Path to go. 0 = the parent folder only. Default: no limit.

.PARAMETER ExplicitOnly
    Report only explicitly set (non-inherited) ACEs. Much smaller report on large trees and
    shows exactly where permissions were changed.

.EXAMPLE
    .\Get-FolderPermissions.ps1 -Path "D:\Shares\Finance"

.EXAMPLE
    .\Get-FolderPermissions.ps1 -Path "\\fs01\Projects" -MaxDepth 3 -ExplicitOnly -OutputPath "C:\Temp\projects_acl.csv"
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = 'Parent folder to scan, e.g. D:\Data or \\server\share')]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    [string]$OutputPath,

    [ValidateRange(0, 2147483647)]
    [int]$MaxDepth = 2147483647,

    [switch]$ExplicitOnly
)

# ---------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------

function ConvertTo-RightsText {
    # Generic rights (typical on CREATOR OWNER and inherit-only ACEs) come back as raw numbers
    # such as 268435456 or -536805376. Map them to the equivalent file-system rights so the
    # report reads "FullControl" / "Modify" instead. "Synchronize" is dropped as noise.
    param($Rights)

    $raw = [int64]$Rights.value__ -band 4294967295          # treat as unsigned 32-bit

    if (($raw -band 4026531840) -ne 0) {                     # any GENERIC_* bit set (0xF0000000)
        $mapped = $raw -band 268435455                       # keep standard/specific bits (0x0FFFFFFF)
        if ($raw -band 2147483648) { $mapped = $mapped -bor 1179785 }   # GENERIC_READ    -> FILE_GENERIC_READ    (0x120089)
        if ($raw -band 1073741824) { $mapped = $mapped -bor 1179926 }   # GENERIC_WRITE   -> FILE_GENERIC_WRITE   (0x120116)
        if ($raw -band 536870912)  { $mapped = $mapped -bor 1179808 }   # GENERIC_EXECUTE -> FILE_GENERIC_EXECUTE (0x1200A0)
        if ($raw -band 268435456)  { $mapped = $mapped -bor 2032127 }   # GENERIC_ALL     -> FILE_ALL_ACCESS      (0x1F01FF)
        $raw = $mapped
    }

    $text  = [Enum]::ToObject([System.Security.AccessControl.FileSystemRights], [int32]$raw).ToString()
    $clean = ($text -split ',\s*' | Where-Object { $_ -ne 'Synchronize' }) -join ', '
    if ($clean) { $clean } else { $text }
}

function Get-AppliesTo {
    # Translates inheritance/propagation flags into the wording of the Windows security dialog.
    param($InheritanceFlags, $PropagationFlags)

    $ci = $InheritanceFlags.HasFlag([System.Security.AccessControl.InheritanceFlags]::ContainerInherit)
    $oi = $InheritanceFlags.HasFlag([System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
    $io = $PropagationFlags.HasFlag([System.Security.AccessControl.PropagationFlags]::InheritOnly)
    $np = $PropagationFlags.HasFlag([System.Security.AccessControl.PropagationFlags]::NoPropagateInherit)

    $text = switch ('{0}{1}{2}' -f [int]$ci, [int]$oi, [int]$io) {
        '000'   { 'This folder only' }
        '110'   { 'This folder, subfolders and files' }
        '100'   { 'This folder and subfolders' }
        '010'   { 'This folder and files' }
        '111'   { 'Subfolders and files only' }
        '101'   { 'Subfolders only' }
        '011'   { 'Files only' }
        default { "Inheritance=$InheritanceFlags; Propagation=$PropagationFlags" }
    }
    if ($np) { $text += ' (this level only)' }
    $text
}

function New-PermissionRow {
    # Every row has the same columns, so error rows and ACE rows line up in the CSV.
    param(
        [string]$FolderPath,
        [int]$Depth,
        [string]$Owner = '',
        $InheritanceDisabled = '',
        $Rule = $null,
        [string]$Note = ''
    )

    $row = [ordered]@{
        FolderPath          = $FolderPath
        Depth               = $Depth
        Owner               = $Owner
        InheritanceDisabled = $InheritanceDisabled
        Identity            = ''
        Rights              = ''
        AccessType          = ''
        IsInherited         = ''
        AppliesTo           = ''
        UnresolvedSid       = ''
        Note                = $Note
    }

    if ($null -ne $Rule) {
        $identity          = $Rule.IdentityReference.Value
        $row.Identity      = $identity
        $row.Rights        = ConvertTo-RightsText -Rights $Rule.FileSystemRights
        $row.AccessType    = $Rule.AccessControlType.ToString()
        $row.IsInherited   = $Rule.IsInherited
        $row.AppliesTo     = Get-AppliesTo -InheritanceFlags $Rule.InheritanceFlags -PropagationFlags $Rule.PropagationFlags
        $row.UnresolvedSid = $identity -like 'S-1-*'
    }

    $script:RowCount++
    [pscustomobject]$row
}

function Get-FolderPermissionRows {
    # Walks the tree depth-first with an explicit stack (no call-depth limit on very deep trees)
    # and emits rows in tree order: a folder, then everything beneath it, then its next sibling.
    param(
        [string]$RootPath,
        [int]$MaxDepth,
        [switch]$ExplicitOnly
    )

    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push([pscustomobject]@{ Path = $RootPath; Depth = 0; LinkType = $null })

    while ($stack.Count -gt 0) {
        $folder = $stack.Pop()
        $script:FolderCount++

        if ($script:FolderCount % 100 -eq 0) {
            Write-Progress -Activity 'Mapping folder permissions' `
                -Status ('{0:N0} folders scanned, {1:N0} pending' -f $script:FolderCount, $stack.Count) `
                -CurrentOperation $folder.Path
        }

        $linkNote = if ($folder.LinkType) { "$($folder.LinkType) - subfolders not scanned" } else { '' }

        # 1) Permissions on this folder
        $rows = $null
        try {
            $acl       = Get-Acl -LiteralPath $folder.Path -ErrorAction Stop
            $owner     = $acl.Owner
            $protected = $acl.AreAccessRulesProtected
            $rules     = @($acl.Access)
            if ($ExplicitOnly) { $rules = @($rules | Where-Object { -not $_.IsInherited }) }

            $rows = @(
                if ($rules.Count -eq 0 -and -not $ExplicitOnly) {
                    New-PermissionRow -FolderPath $folder.Path -Depth $folder.Depth -Owner $owner `
                        -InheritanceDisabled $protected -Note 'No access rules returned (empty or null DACL)'
                }
                foreach ($rule in $rules) {
                    New-PermissionRow -FolderPath $folder.Path -Depth $folder.Depth -Owner $owner `
                        -InheritanceDisabled $protected -Rule $rule -Note $linkNote
                }
            )
        }
        catch {
            $script:ErrorCount++
            $rows = New-PermissionRow -FolderPath $folder.Path -Depth $folder.Depth `
                -Note ('ERROR reading permissions: ' + $_.Exception.Message)
        }
        $rows

        # 2) Queue subfolders (not beyond MaxDepth, never through junctions/symlinks)
        if ($folder.Depth -ge $MaxDepth -or $folder.LinkType) { continue }

        try {
            $children = @(Get-ChildItem -LiteralPath $folder.Path -Directory -Force -ErrorAction Stop)
        }
        catch {
            $script:ErrorCount++
            New-PermissionRow -FolderPath $folder.Path -Depth $folder.Depth `
                -Note ('ERROR listing subfolders: ' + $_.Exception.Message)
            continue
        }

        # Push in reverse so subfolders come off the stack in their natural (alphabetical) order
        for ($i = $children.Count - 1; $i -ge 0; $i--) {
            $child = $children[$i]
            $stack.Push([pscustomobject]@{
                Path     = $child.FullName
                Depth    = $folder.Depth + 1
                LinkType = $child.LinkType
            })
        }
    }
}

# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    throw "Folder not found or not accessible: $Path"
}
$rootPath = (Resolve-Path -LiteralPath $Path).ProviderPath

if (-not $OutputPath) {
    $here       = (Get-Location -PSProvider FileSystem).ProviderPath
    $OutputPath = Join-Path $here ('FolderPermissions_{0:yyyyMMdd_HHmmss}.csv' -f (Get-Date))
}

# UTF-8 with BOM so Excel shows accented folder/user names correctly in both PS 5.1 and PS 7
$encoding = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }

$script:FolderCount = 0
$script:RowCount    = 0
$script:ErrorCount  = 0
$timer = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "Scanning $rootPath ..."

Get-FolderPermissionRows -RootPath $rootPath -MaxDepth $MaxDepth -ExplicitOnly:$ExplicitOnly |
    Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding $encoding

Write-Progress -Activity 'Mapping folder permissions' -Completed
$timer.Stop()

Write-Host ('Done in {0:hh\:mm\:ss}: {1:N0} folders, {2:N0} rows, {3:N0} errors.' -f `
    $timer.Elapsed, $script:FolderCount, $script:RowCount, $script:ErrorCount)
if ($script:ErrorCount -gt 0) {
    Write-Host 'Folders with errors are listed in the CSV - filter the Note column on "ERROR".' -ForegroundColor Yellow
}
Write-Host "Report: $OutputPath"
