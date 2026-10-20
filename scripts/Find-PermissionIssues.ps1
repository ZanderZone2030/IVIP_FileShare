<#
.SYNOPSIS
    Analyzes the CSV produced by Get-FolderPermissions.ps1 and reports potential NTFS permission
    misconfigurations, as a findings CSV and an HTML report.

.DESCRIPTION
    Each permission entry is reported once, where it is set (an explicit entry, or an entry the
    scanned top folder inherits from above), together with the number of folders that inherit it.
    That keeps one bad entry at the top of a share from turning into thousands of findings.

    Checks
      FP01 Critical  Broad group (Everyone, Authenticated Users, Domain Users, Users, ...) can change permissions
      FP02 High      Broad group has write access
      FP03 Medium    Broad group has read access (Low when it only applies to "This folder only")
      FP04 Medium    Entry for an orphaned SID (deleted account)
      FP05 Medium    Permission granted directly to a user account instead of a group     [needs AD]
      FP06 High      Non-admin identity has Full Control / Change Permissions / Take Ownership
      FP07 Medium    CREATOR OWNER has Full Control
      FP08 Low       Explicit Deny entry
      FP09 Medium    Administrators / SYSTEM have no Full Control where inheritance is broken
      FP10 Medium    Folder could not be read during the scan
      FP11 High      Empty or NULL DACL
      FP12 Medium    Owner is an orphaned SID
      FP13 High      Owner is a broad group
      FP14 Low       Folder owned by an individual user account                           [needs AD]
      FP15 Info      Inheritance disabled
      FP16 Low       Explicit permissions set deep in the tree
      FP17 Low       Too many explicit entries on one folder
      FP18 Low       Explicit entry that duplicates an inherited one

    Checks marked [needs AD] classify accounts as user / group / computer through Active Directory.
    They run automatically when this machine can reach a domain controller and are skipped
    (with a note in the report) otherwise.

    The analysis covers NTFS permissions only. Effective access over the network is also limited
    by share permissions, which are not part of the scan.

.PARAMETER Path
    CSV file written by Get-FolderPermissions.ps1.

.PARAMETER OutputFolder
    Where to write <name>_findings.csv and <name>_findings.html. Default: next to the input CSV.

.PARAMETER AdminIdentity
    Extra identities to treat as administrators (wildcards allowed), e.g. 'CORP\FS-Admins'.

.PARAMETER ExcludeIdentity
    Identities to ignore entirely (wildcards allowed), e.g. 'CORP\svc-backup'.

.PARAMETER MaxExplicitDepth
    Explicit permissions more than this many levels below the scanned folder are flagged (FP16). Default 3.

.PARAMETER MaxExplicitAces
    Folders with more explicit entries than this are flagged (FP17). Default 15.

.PARAMETER SkipAccountLookup
    Do not query Active Directory. FP05 and FP14 are skipped.

.PARAMETER NoHtml
    Write the findings CSV only.

.EXAMPLE
    .\Find-PermissionIssues.ps1 -Path .\FolderPermissions_20261019_171500.csv

.EXAMPLE
    .\Find-PermissionIssues.ps1 -Path C:\Temp\acl.csv -AdminIdentity 'CORP\FS-Admins' -ExcludeIdentity 'CORP\svc-veeam'
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = 'CSV written by Get-FolderPermissions.ps1')]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    [string]$OutputFolder,

    [string[]]$AdminIdentity = @(),

    [string[]]$ExcludeIdentity = @(),

    [ValidateRange(1, 100)]
    [int]$MaxExplicitDepth = 3,

    [ValidateRange(1, 1000)]
    [int]$MaxExplicitAces = 15,

    [switch]$SkipAccountLookup,

    [switch]$NoHtml
)

# =============================================================================================
# Reference data
# =============================================================================================

function New-NameSet {
    param([string[]]$Names)
    $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $Names) { [void]$set.Add($n) }
    return ,$set
}

# Matched on the name part (after the backslash). English, French and German Windows names.
$BroadGroupNames = New-NameSet @(
    'Everyone', 'Tout le monde', 'Jeder',
    'Authenticated Users', 'Utilisateurs authentifiés', 'Authentifizierte Benutzer',
    'Domain Users', 'Utilisateurs du domaine', 'Domänen-Benutzer',
    'Users', 'Utilisateurs', 'Benutzer',
    'Domain Computers', 'Ordinateurs du domaine', 'Domänencomputer',
    'Guests', 'Invités', 'Gäste',
    'Domain Guests', 'Invités du domaine', 'Domänen-Gäste',
    'ANONYMOUS LOGON', 'ANONYMOUS-ANMELDUNG',
    'NETWORK', 'INTERACTIVE'
)
$BuiltinUsersNames = New-NameSet @('Users', 'Utilisateurs', 'Benutzer')

$AdminNames = New-NameSet @(
    'Administrators', 'Administrateurs', 'Administratoren',
    'SYSTEM', 'Système',
    'Domain Admins', 'Admins du domaine', 'Domänen-Admins',
    'Enterprise Admins', "Administrateurs de l'entreprise", 'Organisations-Admins',
    'TrustedInstaller'
)

$CreatorOwnerNames = New-NameSet @('CREATOR OWNER', 'CREATEUR PROPRIETAIRE', 'ERSTELLER-BESITZER')
$OwnerRightsNames  = New-NameSet @('OWNER RIGHTS')

# Domains that are never Active Directory objects
$LocalAuthorities = New-NameSet @(
    'BUILTIN', 'NT AUTHORITY', 'AUTORITE NT', 'NT-AUTORITÄT', 'NT SERVICE',
    'APPLICATION PACKAGE AUTHORITY', 'IIS APPPOOL', 'Window Manager', 'Font Driver Host'
)

$ControlRights = New-NameSet @('FullControl', 'ChangePermissions', 'TakeOwnership')
$WriteRights   = New-NameSet @('Modify', 'Write', 'WriteData', 'CreateFiles', 'AppendData', 'CreateDirectories',
                               'Delete', 'DeleteSubdirectoriesAndFiles')
$ReadRights    = New-NameSet @('Read', 'ReadAndExecute', 'ReadData', 'ListDirectory')

$SeverityRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }

$CheckInfo = @{
    FP01 = @{ Name = 'Broad group can change permissions'
              Rec  = 'Remove the entry or replace the broad group with a dedicated security group. Any member can change permissions or take ownership of everything this entry covers.' }
    FP02 = @{ Name = 'Broad group has write access'
              Rec  = 'Replace the broad group with a role-based group (AGDLP domain-local group) containing only the people who need write access.' }
    FP03 = @{ Name = 'Broad group has read access'
              Rec  = 'Confirm this data is meant to be readable by every user. Otherwise replace the broad group with a dedicated read group.' }
    FP04 = @{ Name = 'Orphaned SID (deleted account)'
              Rec  = 'Remove the entry, after confirming the SID does not belong to a trusted domain that was unreachable during the scan.' }
    FP05 = @{ Name = 'Permission granted directly to a user'
              Rec  = 'Grant access through a group so it can be reviewed and revoked centrally, then remove the user entry.' }
    FP06 = @{ Name = 'Non-admin can change permissions'
              Rec  = 'Downgrade to Modify. Full Control, Change Permissions and Take Ownership let the holder grant access to anyone, bypassing the access request process.' }
    FP07 = @{ Name = 'CREATOR OWNER has Full Control'
              Rec  = 'Set CREATOR OWNER to Modify (Subfolders and files only), so users cannot change permissions on what they create.' }
    FP08 = @{ Name = 'Explicit Deny entry'
              Rec  = 'Deny entries make effective access hard to predict and review. Prefer removing the Allow entry or group membership that grants the access.' }
    FP09 = @{ Name = 'Administrators/SYSTEM lack Full Control'
              Rec  = 'Add Administrators and SYSTEM with Full Control so the folder stays manageable and backup and antivirus keep working. Otherwise administrators must take ownership to recover access.' }
    FP10 = @{ Name = 'Folder could not be read'
              Rec  = 'The scan account had no access. Re-run with an account that can read permissions, and check whether administrators are locked out of this folder.' }
    FP11 = @{ Name = 'Empty or NULL DACL'
              Rec  = 'A NULL DACL grants everyone full access; an empty one denies everyone except the owner. Inspect with icacls and set an explicit ACL.' }
    FP12 = @{ Name = 'Owner is an orphaned SID'
              Rec  = 'Set the owner to Administrators, e.g. icacls "<folder>" /setowner Administrators.' }
    FP13 = @{ Name = 'Owner is a broad group'
              Rec  = 'Set the owner to Administrators. The owner can always change permissions, so every member of this group can grant themselves access.' }
    FP14 = @{ Name = 'Folder owned by a user account'
              Rec  = 'The owner can change permissions regardless of the ACL. Set the owner to Administrators, or add an OWNER RIGHTS entry to restrict what owners can do.' }
    FP15 = @{ Name = 'Inheritance disabled'
              Rec  = 'Confirm the break is intentional and documented. Undocumented breaks are where permissions drift away from the access model.' }
    FP16 = @{ Name = 'Permissions set deep in the tree'
              Rec  = 'Set permissions on the top levels only and let them inherit. Deep explicit entries are hard to find and review.' }
    FP17 = @{ Name = 'Too many explicit entries'
              Rec  = 'Consolidate the entries into a few role-based groups.' }
    FP18 = @{ Name = 'Redundant explicit entry'
              Rec  = 'Remove the explicit entry. The inherited entry already grants the same access.' }
}

# =============================================================================================
# Helpers
# =============================================================================================

function Get-NamePart {
    param([string]$Identity)
    $i = $Identity.LastIndexOf('\')
    if ($i -ge 0) { $Identity.Substring($i + 1) } else { $Identity }
}

function Test-Wildcard {
    param([string]$Value, [string[]]$Patterns)
    foreach ($p in $Patterns) { if ($Value -like $p) { return $true } }
    return $false
}

function Test-Admin {
    param([string]$Identity)
    if ($AdminNames.Contains((Get-NamePart $Identity))) { return $true }
    return (Test-Wildcard -Value $Identity -Patterns $AdminIdentity)
}

# Identity classification, computed once per distinct identity (the scan repeats the same few
# hundred identities hundreds of thousands of times)
$script:IdentityCache = @{}
function Get-IdentityInfo {
    param([string]$Identity)
    $name = Get-NamePart $Identity
    $info = [pscustomobject]@{
        IsAdmin        = Test-Admin $Identity
        IsBroad        = $BroadGroupNames.Contains($name)
        IsBuiltinUsers = $BuiltinUsersNames.Contains($name)
        IsCreator      = $CreatorOwnerNames.Contains($name)
        IsOwnerRights  = $OwnerRightsNames.Contains($name)
    }
    $script:IdentityCache[$Identity] = $info
    $info
}

$script:TierCache = @{}
function Get-RightsTier {
    # Control > Write > Read > Other, based on the strongest right in the entry
    param([string]$Rights)
    if ($script:TierCache.ContainsKey($Rights)) { return $script:TierCache[$Rights] }
    $parts = $Rights -split ',\s*'
    $tier = 'Other'
    if     (@($parts | Where-Object { $ControlRights.Contains($_) }).Count) { $tier = 'Control' }
    elseif (@($parts | Where-Object { $WriteRights.Contains($_) }).Count)   { $tier = 'Write' }
    elseif (@($parts | Where-Object { $ReadRights.Contains($_) }).Count)    { $tier = 'Read' }
    $script:TierCache[$Rights] = $tier
    $tier
}

function Get-ParentPath {
    param([string]$ChildPath)
    $trimmed = $ChildPath.TrimEnd('\', '/')
    $i = $trimmed.LastIndexOfAny([char[]]@('\', '/'))
    if ($i -lt 0) { return $null }
    $parent = $trimmed.Substring(0, $i)
    if ($parent -and $script:Folders.ContainsKey($parent)) { return $parent }
    $withSep = $parent + $trimmed[$i]                       # volume root such as D:\
    if ($script:Folders.ContainsKey($withSep)) { return $withSep }
    return $null
}

# --- Active Directory account classification (user / group / computer) -----------------------
$script:AccountTypeCache   = @{}
$script:AccountLookupOn    = $false
$script:AccountLookupState = 'Skipped (-SkipAccountLookup)'

if (-not $SkipAccountLookup) {
    try {
        Add-Type -AssemblyName System.DirectoryServices -ErrorAction SilentlyContinue
        $null = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
        $script:AccountLookupOn    = $true
        $script:AccountLookupState = 'Active Directory'
    }
    catch {
        $script:AccountLookupState = 'Unavailable - FP05 and FP14 skipped (' + $_.Exception.Message + ')'
    }
}

function Get-AccountType {
    param([string]$Identity)
    if (-not $script:AccountLookupOn) { return 'Unknown' }
    if ($script:AccountTypeCache.ContainsKey($Identity)) { return $script:AccountTypeCache[$Identity] }

    $type = 'Unknown'
    $i = $Identity.IndexOf('\')
    if ($i -gt 0 -and -not $LocalAuthorities.Contains($Identity.Substring(0, $i))) {
        try {
            $sid = ([System.Security.Principal.NTAccount]$Identity).Translate([System.Security.Principal.SecurityIdentifier]).Value
            $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://<SID=$sid>")
            $classes = @($entry.Properties['objectClass'])
            if     ($classes -contains 'computer') { $type = 'Computer' }
            elseif ($classes -contains 'group')    { $type = 'Group' }
            elseif ($classes -contains 'user')     { $type = 'User' }
            $entry.Dispose()
        }
        catch { $type = 'Unknown' }   # local account, foreign SID, or not found
    }
    $script:AccountTypeCache[$Identity] = $type
    $type
}

# --- Findings --------------------------------------------------------------------------------
$script:Findings         = [System.Collections.Generic.List[object]]::new()
$script:FindingsBySource = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$script:AffectedSets     = @{}   # "Severity|CheckId" -> distinct folders affected, for the summary

function Add-AffectedFolder {
    param([string]$GroupKey, [string]$FolderPath)
    if (-not $script:AffectedSets.ContainsKey($GroupKey)) {
        $script:AffectedSets[$GroupKey] = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    }
    [void]$script:AffectedSets[$GroupKey].Add($FolderPath)
}

function Add-Finding {
    param(
        [string]$CheckId,
        [string]$Severity,
        $Folder,
        $Ace = $null,
        [string]$Identity = '',
        [string]$Details = '',
        $FoldersAffected = ''
    )

    $finding = [pscustomobject]@{
        Severity        = $Severity
        CheckId         = $CheckId
        Check           = $CheckInfo[$CheckId].Name
        FolderPath      = $Folder.Path
        Depth           = $Folder.Depth
        Identity        = $Identity
        Rights          = ''
        AccessType      = ''
        AppliesTo       = ''
        FoldersAffected = $FoldersAffected
        Details         = $Details
        Recommendation  = $CheckInfo[$CheckId].Rec
        ImpactKey       = ''
    }

    if ($null -ne $Ace) {
        $finding.Identity   = $Ace.Identity
        $finding.Rights     = $Ace.Rights
        $finding.AccessType = $Ace.AccessType
        $finding.AppliesTo  = $Ace.AppliesTo
        if (-not $script:ExplicitOnlyScan) {
            # Counted up later: this folder + every folder below that inherits the same entry
            $finding.FoldersAffected = 1
            $finding.ImpactKey = '{0}|{1}|{2}' -f $Ace.Identity, $Ace.AccessType, $Ace.Rights
            $list = $null
            if (-not $script:FindingsBySource.TryGetValue($Folder.Path, [ref]$list)) {
                $list = [System.Collections.Generic.List[object]]::new()
                $script:FindingsBySource[$Folder.Path] = $list
            }
            $list.Add($finding)
            Add-AffectedFolder "$Severity|$CheckId" $Folder.Path
        }
    }
    $script:Findings.Add($finding)
}

function ConvertTo-HtmlSafe {
    param($Text)
    [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

# =============================================================================================
# Load the scan
# =============================================================================================

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "File not found: $Path" }
$inputFile = (Resolve-Path -LiteralPath $Path).ProviderPath

# Accept ; as delimiter too, in case the CSV was re-saved from Excel
$header    = Get-Content -LiteralPath $inputFile -TotalCount 1
$delimiter = if ($header -match ';' -and $header -notmatch ',') { ';' } else { ',' }

Write-Host "Reading $inputFile ..."
$rows = @(Import-Csv -LiteralPath $inputFile -Delimiter $delimiter)
if ($rows.Count -eq 0) { throw 'The CSV is empty.' }

$required = 'FolderPath', 'Depth', 'Owner', 'InheritanceDisabled', 'Identity', 'Rights',
            'AccessType', 'IsInherited', 'AppliesTo', 'UnresolvedSid', 'Note'
$missing  = @($required | Where-Object { $rows[0].PSObject.Properties.Name -notcontains $_ })
if ($missing.Count) {
    throw "This does not look like Get-FolderPermissions.ps1 output. Missing columns: $($missing -join ', ')"
}

# Build one object per folder, with its entries
$script:Folders = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$folderList = [System.Collections.Generic.List[object]]::new()
$script:ExplicitOnlyScan = $true
$aceCount = 0

foreach ($r in $rows) {
    $folder = $null
    if (-not $script:Folders.TryGetValue($r.FolderPath, [ref]$folder)) {
        $folder = [pscustomobject]@{
            Path                = $r.FolderPath
            Depth               = [int]$r.Depth
            Owner               = ''
            InheritanceDisabled = $false
            Aces                = [System.Collections.Generic.List[object]]::new()
            InheritedKeys       = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            InheritedFullKeys   = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            Notes               = [System.Collections.Generic.List[string]]::new()
        }
        $script:Folders[$r.FolderPath] = $folder
        $folderList.Add($folder)
    }

    if ($r.Owner -and -not $folder.Owner)  { $folder.Owner = $r.Owner }
    if ($r.InheritanceDisabled -eq 'True') { $folder.InheritanceDisabled = $true }
    if ($r.Note -and -not $folder.Notes.Contains($r.Note)) { $folder.Notes.Add($r.Note) }

    if (-not $r.Identity) { continue }
    if ($ExcludeIdentity.Count -and (Test-Wildcard -Value $r.Identity -Patterns $ExcludeIdentity)) { continue }

    $folder.Aces.Add($r)
    $aceCount++
    if ($r.IsInherited -eq 'True') {
        $script:ExplicitOnlyScan = $false
        [void]$folder.InheritedKeys.Add(('{0}|{1}|{2}' -f $r.Identity, $r.AccessType, $r.Rights))
        [void]$folder.InheritedFullKeys.Add(('{0}|{1}|{2}|{3}' -f $r.Identity, $r.AccessType, $r.Rights, $r.AppliesTo))
    }
}
$rows = $null

$explicitOnlyNote = 'Input is an -ExplicitOnly scan. Entries inherited from above the scanned folder are not ' +
                    'checked, FoldersAffected cannot be counted and FP18 cannot run. Re-scan without -ExplicitOnly for full results.'
if ($script:ExplicitOnlyScan) { Write-Warning $explicitOnlyNote }

$minDepth = ($folderList | Measure-Object -Property Depth -Minimum).Minimum
$scanRoot = @($folderList | Where-Object { $_.Depth -eq $minDepth })[0].Path
Write-Host ('{0:N0} folders and {1:N0} permission entries loaded. Account lookup: {2}' -f $folderList.Count, $aceCount, $script:AccountLookupState)

# =============================================================================================
# Analyze
# =============================================================================================

$ownerAgg = @{}
$progress = 0

foreach ($folder in $folderList) {
    $progress++
    if ($progress % 500 -eq 0) {
        Write-Progress -Activity 'Analyzing permissions' -Status ('{0:N0} of {1:N0} folders' -f $progress, $folderList.Count) `
            -PercentComplete ([int](100 * $progress / $folderList.Count))
    }

    $isRoot   = $folder.Depth -eq $minDepth
    $relDepth = $folder.Depth - $minDepth

    # --- Scan problems
    foreach ($note in $folder.Notes) {
        if ($note -like 'ERROR*') {
            Add-Finding FP10 Medium $folder -Details $note
        }
        elseif ($note -like 'No access rules*') {
            Add-Finding FP11 High $folder -Details 'Get-Acl returned no entries. Check with: icacls "<folder>"'
        }
    }

    # --- Entry-level checks
    $explicitCount  = 0
    $hasAdminFull   = $false
    $hasOwnerRights = $false

    foreach ($ace in $folder.Aces) {
        $inherited = $ace.IsInherited -eq 'True'
        $allow     = $ace.AccessType -eq 'Allow'
        $id        = $script:IdentityCache[$ace.Identity]
        if ($null -eq $id) { $id = Get-IdentityInfo $ace.Identity }

        if ($allow -and $id.IsAdmin -and $ace.Rights -like '*FullControl*') { $hasAdminFull = $true }
        if ($id.IsOwnerRights) { $hasOwnerRights = $true }
        if (-not $inherited) { $explicitCount++ }

        # Report each entry only where it is set: explicit entries anywhere, plus everything
        # the scanned top folder inherits from above. Inherited copies further down are counted
        # in FoldersAffected instead of being reported again.
        if ($inherited -and -not $isRoot) { continue }

        $tier       = Get-RightsTier $ace.Rights
        $isAdmin    = $id.IsAdmin
        $isBroad    = $id.IsBroad
        $isCreator  = $id.IsCreator
        $isOrphan   = $ace.UnresolvedSid -eq 'True'
        $detailBits = [System.Collections.Generic.List[string]]::new()
        if ($inherited) { $detailBits.Add('Inherited from above the scanned folder') }
        if ($id.IsBuiltinUsers) {
            $detailBits.Add('On a domain member server, BUILTIN\Users includes Domain Users')
        }
        $details = $detailBits -join '. '

        if ($allow -and $isBroad) {
            switch ($tier) {
                'Control' { Add-Finding FP01 Critical $folder -Ace $ace -Details $details }
                'Write'   { Add-Finding FP02 High     $folder -Ace $ace -Details $details }
                'Read'    {
                    $sev = if ($ace.AppliesTo -eq 'This folder only') { 'Low' } else { 'Medium' }
                    Add-Finding FP03 $sev $folder -Ace $ace -Details $details
                }
            }
        }

        if ($isOrphan -and $ace.Identity -notlike 'S-1-15-*') {
            Add-Finding FP04 Medium $folder -Ace $ace -Details $details
        }

        if ($allow -and $tier -eq 'Control' -and -not ($isAdmin -or $isBroad -or $isCreator)) {
            Add-Finding FP06 High $folder -Ace $ace -Details $details
        }

        if ($allow -and $isCreator -and $tier -eq 'Control') {
            Add-Finding FP07 Medium $folder -Ace $ace -Details $details
        }

        if (-not $allow) {
            Add-Finding FP08 Low $folder -Ace $ace -Details $details
        }

        if ($allow -and -not ($isAdmin -or $isBroad -or $isCreator -or $isOrphan) -and
            (Get-AccountType $ace.Identity) -eq 'User') {
            Add-Finding FP05 Medium $folder -Ace $ace -Details $details
        }

        if (-not $inherited -and
            $folder.InheritedFullKeys.Contains(('{0}|{1}|{2}|{3}' -f $ace.Identity, $ace.AccessType, $ace.Rights, $ace.AppliesTo))) {
            Add-Finding FP18 Low $folder -Ace $ace -Details 'The same entry is also inherited on this folder'
        }
    }

    # --- Folder-level checks
    # (an -ExplicitOnly scan has no inherited entries, so the top folder can't be judged there)
    if ($folder.Aces.Count -gt 0 -and -not $hasAdminFull -and
        ($folder.InheritanceDisabled -or ($isRoot -and -not $script:ExplicitOnlyScan))) {
        $why = if ($folder.InheritanceDisabled) { 'Inheritance is disabled, so nothing above restores admin access' } else { 'Scanned top folder' }
        Add-Finding FP09 Medium $folder -Details "No Full Control for Administrators, SYSTEM or admin groups. $why"
    }

    if ($folder.InheritanceDisabled) {
        Add-Finding FP15 Info $folder -Details ('{0} explicit entries' -f $explicitCount)
    }

    if ($explicitCount -gt 0 -and $relDepth -gt $MaxExplicitDepth) {
        Add-Finding FP16 Low $folder -Details ('{0} explicit entr{1} at {2} levels below the scanned folder (threshold {3})' -f `
            $explicitCount, $(if ($explicitCount -eq 1) { 'y' } else { 'ies' }), $relDepth, $MaxExplicitDepth)
    }

    if ($explicitCount -gt $MaxExplicitAces) {
        Add-Finding FP17 Low $folder -Details ('{0} explicit entries (threshold {1})' -f $explicitCount, $MaxExplicitAces)
    }

    # --- Owner checks: aggregated per owner, reported once at the shallowest folder
    $owner = $folder.Owner
    if ($owner -and -not ($ExcludeIdentity.Count -and (Test-Wildcard -Value $owner -Patterns $ExcludeIdentity))) {
        $oid = $script:IdentityCache[$owner]
        if ($null -eq $oid) { $oid = Get-IdentityInfo $owner }
        $ownerCheck = $null
        if ($owner -like 'S-1-*') { $ownerCheck = 'FP12' }
        elseif ($oid.IsBroad) { $ownerCheck = 'FP13' }
        elseif (-not $hasOwnerRights -and -not $oid.IsAdmin -and (Get-AccountType $owner) -eq 'User') { $ownerCheck = 'FP14' }

        if ($ownerCheck) {
            $k = "$ownerCheck|$owner"
            if (-not $ownerAgg.ContainsKey($k)) {
                $ownerAgg[$k] = [pscustomobject]@{ Check = $ownerCheck; Owner = $owner; Count = 0; Folder = $folder }
            }
            $agg = $ownerAgg[$k]
            $agg.Count++
            if ($folder.Depth -lt $agg.Folder.Depth) { $agg.Folder = $folder }
        }
    }
}

$ownerSeverity = @{ FP12 = 'Medium'; FP13 = 'High'; FP14 = 'Low' }
foreach ($agg in $ownerAgg.Values) {
    Add-Finding $agg.Check $ownerSeverity[$agg.Check] $agg.Folder -Identity $agg.Owner -FoldersAffected $agg.Count `
        -Details ('Owner of {0:N0} folder{1}; the shallowest is shown' -f $agg.Count, $(if ($agg.Count -eq 1) { '' } else { 's' }))
}

# --- Impact: for each reported entry, count the folders below that inherit it -----------------
if (-not $script:ExplicitOnlyScan -and $script:FindingsBySource.Count -gt 0) {
    Write-Progress -Activity 'Analyzing permissions' -Status 'Counting inherited impact'
    foreach ($folder in $folderList) {
        if ($folder.InheritedKeys.Count -eq 0) { continue }
        $credited = [System.Collections.Generic.HashSet[string]]::new()
        $current  = $folder
        while ($true) {
            $parentPath = Get-ParentPath $current.Path
            if (-not $parentPath) { break }
            $parent = $script:Folders[$parentPath]
            $list = $null
            if ($script:FindingsBySource.TryGetValue($parent.Path, [ref]$list)) {
                foreach ($fd in $list) {
                    # credit the nearest source only, once per check
                    if ($folder.InheritedKeys.Contains($fd.ImpactKey) -and $credited.Add("$($fd.CheckId)|$($fd.ImpactKey)")) {
                        $fd.FoldersAffected++
                        Add-AffectedFolder "$($fd.Severity)|$($fd.CheckId)" $folder.Path
                    }
                }
            }
            if ($parent.InheritanceDisabled) { break }   # nothing above this point reaches the folder
            $current = $parent
        }
    }
}
Write-Progress -Activity 'Analyzing permissions' -Completed

# =============================================================================================
# Output
# =============================================================================================

$sorted = @($script:Findings | Sort-Object `
    @{ Expression = { $SeverityRank[$_.Severity] } },
    @{ Expression = { $_.CheckId } },
    @{ Expression = { if ($_.FoldersAffected -is [int]) { $_.FoldersAffected } else { 0 } }; Descending = $true },
    @{ Expression = { $_.FolderPath } })

$columns = 'Severity', 'CheckId', 'Check', 'FolderPath', 'Depth', 'Identity', 'Rights', 'AccessType',
           'AppliesTo', 'FoldersAffected', 'Details', 'Recommendation'

if (-not $OutputFolder) { $OutputFolder = Split-Path -Parent $inputFile }
if (-not (Test-Path -LiteralPath $OutputFolder)) { $null = New-Item -ItemType Directory -Path $OutputFolder }
$baseName = [System.IO.Path]::GetFileNameWithoutExtension($inputFile) + '_findings'
$csvOut   = Join-Path $OutputFolder "$baseName.csv"
$htmlOut  = Join-Path $OutputFolder "$baseName.html"

$encoding = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }
$sorted | Select-Object $columns | Export-Csv -LiteralPath $csvOut -NoTypeInformation -Encoding $encoding

# Summary per severity + check
$summary = @($sorted | Group-Object Severity, CheckId | ForEach-Object {
    $first = $_.Group[0]
    $set   = $script:AffectedSets["$($first.Severity)|$($first.CheckId)"]
    if ($set) {
        $impact = $set.Count            # distinct folders reached by the entries behind this check
    }
    else {                              # owner checks: one owner per folder, so the counts add up
        $impact = [int](($_.Group | Where-Object { $_.FoldersAffected -is [int] } | Measure-Object -Property FoldersAffected -Sum).Sum)
    }
    [pscustomobject]@{
        Severity        = $first.Severity
        CheckId         = $first.CheckId
        Check           = $first.Check
        Findings        = $_.Count
        FoldersAffected = if ($impact) { $impact } else { '' }
    }
} | Sort-Object @{ Expression = { $SeverityRank[$_.Severity] } }, CheckId)

# --- HTML report
if (-not $NoHtml) {
    $sevColor = @{ Critical = '#a4161a'; High = '#d9480f'; Medium = '#b7791f'; Low = '#1c64b0'; Info = '#5f6b7a' }
    $maxRowsPerCheck = 200
    $sb = New-Object System.Text.StringBuilder

    [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Folder permission review</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1f2933;background:#fff;font-size:14px}
 h1{font-size:22px;margin:0 0 4px} h2{font-size:17px;margin:32px 0 8px} h3{font-size:15px;margin:28px 0 4px}
 .meta{color:#52606d;margin-bottom:16px} .meta td{padding:1px 12px 1px 0}
 table.data{border-collapse:collapse;width:100%;margin-top:6px}
 table.data th,table.data td{border-bottom:1px solid #e4e7eb;padding:5px 8px;text-align:left;vertical-align:top}
 table.data th{background:#f5f7fa;font-weight:600} table.data td.num,table.data th.num{text-align:right;white-space:nowrap}
 .sev{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:12px;font-weight:600}
 .rec{color:#3e4c59;margin:2px 0 6px;max-width:900px} .path{overflow-wrap:anywhere;min-width:240px} .more{color:#52606d;font-style:italic}
</style></head><body>
<h1>Folder permission review</h1>
"@)

    $metaRows = [ordered]@{
        'Scanned folder'   = $scanRoot
        'Input file'       = $inputFile
        'Folders analyzed' = '{0:N0}' -f $folderList.Count
        'Entries analyzed' = '{0:N0}' -f $aceCount
        'Account lookup'   = $script:AccountLookupState
        'Generated'        = (Get-Date).ToString('yyyy-MM-dd HH:mm')
    }
    if ($script:ExplicitOnlyScan) { $metaRows['Note'] = $explicitOnlyNote }
    if ($ExcludeIdentity.Count)   { $metaRows['Excluded identities'] = $ExcludeIdentity -join ', ' }
    [void]$sb.Append('<table class="meta">')
    foreach ($k in $metaRows.Keys) {
        [void]$sb.Append("<tr><td>$(ConvertTo-HtmlSafe $k)</td><td>$(ConvertTo-HtmlSafe $metaRows[$k])</td></tr>")
    }
    [void]$sb.Append('</table><p class="meta">NTFS permissions only. Effective network access is also limited by share permissions.</p>')

    [void]$sb.Append('<h2>Summary</h2><table class="data"><tr><th>Severity</th><th>Check</th><th class="num">Findings</th><th class="num">Folders affected</th></tr>')
    foreach ($s in $summary) {
        [void]$sb.Append(('<tr><td><span class="sev" style="background:{0}">{1}</span></td><td><a href="#{2}-{1}">{2} &middot; {3}</a></td><td class="num">{4:N0}</td><td class="num">{5}</td></tr>' -f `
            $sevColor[$s.Severity], $s.Severity, $s.CheckId, (ConvertTo-HtmlSafe $s.Check), $s.Findings,
            $(if ($s.FoldersAffected -ne '') { '{0:N0}' -f $s.FoldersAffected } else { '' })))
    }
    if ($summary.Count -eq 0) { [void]$sb.Append('<tr><td colspan="4">No findings.</td></tr>') }
    [void]$sb.Append('</table><h2>Findings</h2>')

    $groups = $sorted | Group-Object Severity, CheckId |
        Sort-Object @{ Expression = { $SeverityRank[$_.Group[0].Severity] } }, @{ Expression = { $_.Group[0].CheckId } }
    foreach ($group in $groups) {
        $first = $group.Group[0]
        [void]$sb.Append(('<h3 id="{0}-{1}"><span class="sev" style="background:{2}">{1}</span> {0} &middot; {3} ({4:N0})</h3><p class="rec">{5}</p>' -f `
            $first.CheckId, $first.Severity, $sevColor[$first.Severity], (ConvertTo-HtmlSafe $first.Check), $group.Count,
            (ConvertTo-HtmlSafe $first.Recommendation)))
        [void]$sb.Append('<table class="data"><tr><th>Folder</th><th>Identity</th><th>Rights</th><th>Applies to</th><th class="num">Folders affected</th><th>Details</th></tr>')
        foreach ($fd in ($group.Group | Select-Object -First $maxRowsPerCheck)) {
            [void]$sb.Append(('<tr><td class="path">{0}</td><td>{1}</td><td>{2}{3}</td><td>{4}</td><td class="num">{5}</td><td>{6}</td></tr>' -f `
                (ConvertTo-HtmlSafe $fd.FolderPath), (ConvertTo-HtmlSafe $fd.Identity),
                $(if ($fd.AccessType -eq 'Deny') { 'DENY ' } else { '' }), (ConvertTo-HtmlSafe $fd.Rights),
                (ConvertTo-HtmlSafe $fd.AppliesTo),
                $(if ($fd.FoldersAffected -is [int]) { '{0:N0}' -f $fd.FoldersAffected } else { '' }),
                (ConvertTo-HtmlSafe $fd.Details)))
        }
        [void]$sb.Append('</table>')
        if ($group.Count -gt $maxRowsPerCheck) {
            [void]$sb.Append(('<p class="more">Showing {0} of {1:N0}, largest impact first. The full list is in the CSV.</p>' -f $maxRowsPerCheck, $group.Count))
        }
    }
    [void]$sb.Append('</body></html>')
    [System.IO.File]::WriteAllText($htmlOut, $sb.ToString(), (New-Object System.Text.UTF8Encoding $true))
}

# --- Console summary
Write-Host ''
if ($summary.Count -eq 0) {
    Write-Host 'No findings.' -ForegroundColor Green
}
else {
    $summary | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
}
Write-Host "Findings CSV : $csvOut"
if (-not $NoHtml) { Write-Host "HTML report  : $htmlOut" }
if (-not $script:AccountLookupOn) { Write-Host "Account lookup: $($script:AccountLookupState)" -ForegroundColor Yellow }
