<#
.SYNOPSIS
    Builds an interactive, self-contained HTML graph of folder permissions from the CSV written by
    Get-FolderPermissions.ps1, optionally overlaid with findings and Active Directory group membership.

.DESCRIPTION
    The page shows the folder tree as a graph you can expand, collapse, pan and zoom.

      - Click a folder to see its owner, inheritance status, findings and full permission list.
      - Pick an identity (group or user) to highlight every folder it is granted on explicitly
        and every folder it reaches through inheritance; the paths to those folders open up.
      - Dashed links mark folders where inheritance is disabled.
      - With -FindingsPath, each folder carries a badge for its worst finding (C/H/M/L) and a
        Findings tab lists them all, each one jumping to its folder.
      - With -TeamPath (a One Identity department export: account, team, full path, location),
        each folder lists the teams that have access, with their location codes (CH1, ES1...),
        number of people, access level and the groups the access comes through; a Teams tab
        highlights everything a team can reach.
      - With -BusinessRolePath / -SystemRolePath (exports from One Identity Manager), each group
        shows the business roles (Org) and system roles (ESet) that assign it; clicking a role
        highlights every folder it gives access to through its groups.
      - With -IncludeGroupMembers, clicking a group opens a member graph: nested groups can be
        expanded, disabled accounts and members from trusted domains are marked, and clicking a
        member highlights every folder that member reaches through any of its groups.
        Groups, accounts and folders are also checked, marked in the graphs and listed in the
        Issues tab (red first, then yellow; the other lists on the left are ordered the same way):
          nested (violet)    the group is a member of another group
          empty (yellow)     no members, or only empty groups nested inside
          bad config (red)   group: circular nesting; Everyone, Authenticated Users, Domain Users
                             or Domain Computers inside a group that is not broad by design;
                             disabled accounts still members; members that no longer resolve
                             folder: an individual account (user, service account or computer; not
                             a group) has its own entry, with any rights, on a folder at level 0 to 3
                             (-DirectAccessLevels); Full Control is called out separately
          external (yellow)  account in an OU matching -ExternalOu ("Consultant Users"); folders
                             that external accounts can reach, directly or through groups

    Group membership is read when the page is built, not when the folders were scanned. It is
    read with ADSI (System.DirectoryServices), so the RSAT ActiveDirectory module is not needed.
    Run it on a domain-joined computer as an account that can read group membership.
      - Domain groups: the member attribute (ranged reads, so large groups are complete), plus
        accounts that have the group as their primary group (Domain Users, Domain Computers...).
      - Nested groups are followed to any depth; circular nesting is detected.
      - BUILTIN groups (Administrators, Users...) are read on the file server itself through the
        WinNT provider, because they are local to that server.
      - Everyone, Authenticated Users, SYSTEM, CREATOR OWNER and similar principals have no member
        list; the page explains what each one covers instead.

    The HTML has no external dependencies (no CDN, no fonts, no network calls), so it opens on
    isolated admin workstations and the data never leaves the file. Treat the file itself as
    sensitive: it contains the full permission map of the share and, with -IncludeGroupMembers,
    the names of the people in each group.

.PARAMETER Path
    CSV written by Get-FolderPermissions.ps1. A full scan works best; an -ExplicitOnly scan shows
    only explicit entries in the folder details.

.PARAMETER FindingsPath
    Optional findings CSV written by Find-PermissionIssues.ps1 for the same scan.

.PARAMETER OutputPath
    HTML file to write. Default: <scan name>_graph.html next to the scan CSV.

.PARAMETER Title
    Title shown at the top of the page. Default: "Folder permissions".

.PARAMETER IncludeGroupMembers
    Read the members of every group in the scan (and of the groups nested in them) and add a
    member graph to the page.

.PARAMETER FileServer
    Server whose local groups (BUILTIN\Administrators, BUILTIN\Users...) apply to the scanned
    folders. Default: the server in the scan path for a UNC path (\\server\share), otherwise this
    computer. Set it when the scan used a local path on another server, or a domain DFS path.

.PARAMETER MaxMembersPerGroup
    Members read per group, to keep the page small with very large groups such as Domain Users.
    Groups above the limit show how many members were not read. Default 5000.

.PARAMETER TeamPath
    Optional export of the One Identity department table: one row per person, with
        SAMAccountName   the person's AD account
        DepartmentName   the team
        FullPath         the team's full path (optional)
        LocationCode     the location code, e.g. CH1, ES1 (optional)
    Common alternative column names are recognised (CentralAccount, TeamName, Department,
    TeamPath, Ident_Locality, Location...); set the -Team*Column parameters to use others.
    People are matched to the members read with -IncludeGroupMembers and to accounts set directly
    on the folders. Comma, semicolon or tab separated; UTF-8 or UTF-16.

.PARAMETER TeamAccountColumn
    Column of the team file with the sAMAccountName. Default 'SAMAccountName'.

.PARAMETER TeamNameColumn
    Column of the team file with the team name. Default 'DepartmentName'.

.PARAMETER TeamFullPathColumn
    Column of the team file with the team's full path. Default 'FullPath'.

.PARAMETER TeamLocationColumn
    Column of the team file with the location code. Default 'LocationCode'.

.PARAMETER ExternalOu
    Accounts whose AD path contains an OU (or container) with this text are treated as external,
    and folders they can reach are flagged. Several values allowed. Default 'Consultant Users'.
    Needs -IncludeGroupMembers.

.PARAMETER DirectAccessLevels
    Folder levels, counted from the scanned folder (level 0, its subfolders level 1, ...), where an
    individual account with its own permission entry (any rights, not through a group) is flagged
    as bad config. Default 0, 1, 2, 3. Needs -IncludeGroupMembers: only AD can tell an account from a
    group. Also accepted as -UserFullControlLevels.

.PARAMETER BusinessRolePath
    Optional export of One Identity business roles (Org) and the AD groups they assign, one row per
    role and group, with two columns:
        Ident_Org   the business role
        cn          the common name of the AD group
    Other columns are ignored. Comma, semicolon or tab separated; UTF-8 or UTF-16.

.PARAMETER SystemRolePath
    Optional export of One Identity system roles (ESet) and the AD groups they contain, one row per
    role and group, with two columns:
        DisplayName the system role
        cn          the common name of the AD group
    Other columns are ignored. Comma, semicolon or tab separated; UTF-8 or UTF-16.

.PARAMETER BusinessRoleNameColumn
    Only needed if the business role export names the role column differently. Default 'Ident_Org'.

.PARAMETER BusinessRoleGroupColumn
    Only needed if the business role export names the group column differently. Default 'cn'.

.PARAMETER SystemRoleNameColumn
    Only needed if the system role export names the role column differently. Default 'DisplayName'.

.PARAMETER SystemRoleGroupColumn
    Only needed if the system role export names the group column differently. Default 'cn'.

.EXAMPLE
    .\New-PermissionGraph.ps1 -Path .\FolderPermissions_20261019_171500.csv

.EXAMPLE
    .\New-PermissionGraph.ps1 -Path .\scan.csv -FindingsPath .\scan_findings.csv -Title "Finance share - Oct 2026"

.EXAMPLE
    .\New-PermissionGraph.ps1 -Path .\scan.csv -FindingsPath .\scan_findings.csv -IncludeGroupMembers

.EXAMPLE
    .\New-PermissionGraph.ps1 -Path .\scan.csv -IncludeGroupMembers -FileServer FS01 -MaxMembersPerGroup 20000

.EXAMPLE
    .\New-PermissionGraph.ps1 -Path .\scan.csv -FindingsPath .\scan_findings.csv -IncludeGroupMembers `
        -BusinessRolePath .\oim_org_groups.csv -SystemRolePath .\oim_eset_groups.csv


.EXAMPLE
    .\New-PermissionGraph.ps1 -Path .\scan.csv -FindingsPath .\scan_findings.csv -IncludeGroupMembers `
        -BusinessRolePath .\org.csv -SystemRolePath .\eset.csv -TeamPath .\departments.csv
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = 'CSV written by Get-FolderPermissions.ps1')]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    [string]$FindingsPath,

    [string]$OutputPath,

    [string]$Title = 'Folder permissions',

    [switch]$IncludeGroupMembers,

    [string]$FileServer,

    [ValidateRange(1, 1000000)]
    [int]$MaxMembersPerGroup = 5000,

    [string]$BusinessRolePath,

    [string]$SystemRolePath,

    [string]$BusinessRoleNameColumn = 'Ident_Org',

    [string]$BusinessRoleGroupColumn = 'cn',

    [string]$SystemRoleNameColumn = 'DisplayName',

    [string]$SystemRoleGroupColumn = 'cn',

    [string[]]$ExternalOu = @('Consultant Users'),

    [string]$TeamPath,

    [string]$TeamAccountColumn = 'SAMAccountName',

    [string]$TeamNameColumn = 'DepartmentName',

    [string]$TeamFullPathColumn = 'FullPath',

    [string]$TeamLocationColumn = 'LocationCode',

    [Alias('UserFullControlLevels')]
    [string[]]$DirectAccessLevels = @('0', '1', '2', '3')
)

# Levels may arrive as a list (2,3 inside PowerShell) or as one text "2,3" (powershell -File, scheduled tasks)
$accessLevels = @(foreach ($v in $DirectAccessLevels) {
    foreach ($x in ($v -split '[,;\s]+')) {
        if ($x -eq '') { continue }
        $n = 0
        if (-not [int]::TryParse($x, [ref]$n) -or $n -lt 0 -or $n -gt 100) { throw "-DirectAccessLevels: '$x' is not a folder level (0 to 100)." }
        $n
    }
}) | Sort-Object -Unique

# =============================================================================================
# Helpers
# =============================================================================================

function Get-CsvEncoding {
    # Encoding to read a CSV with: the byte-order mark if there is one, else UTF-8 when the start of the
    # file is valid UTF-8, else the ANSI code page (a CSV re-saved from Excel). Without this, PS 7 reads
    # ANSI as UTF-8 and PS 5.1 reads UTF-8 without BOM as ANSI, and accented names break.
    param([string]$File)
    $buf = [byte[]]::new(1MB)
    $fs  = [System.IO.File]::OpenRead($File)
    try { $n = $fs.Read($buf, 0, $buf.Length) } finally { $fs.Dispose() }
    if ($n -ge 3 -and $buf[0] -eq 0xEF -and $buf[1] -eq 0xBB -and $buf[2] -eq 0xBF) { return 'UTF8' }
    if ($n -ge 2 -and $buf[0] -eq 0xFF -and $buf[1] -eq 0xFE) { return 'Unicode' }
    if ($n -ge 2 -and $buf[0] -eq 0xFE -and $buf[1] -eq 0xFF) { return 'BigEndianUnicode' }
    try {
        # A decoder without flush accepts a character cut off at the end of the buffer
        $null = [System.Text.UTF8Encoding]::new($false, $true).GetDecoder().GetChars($buf, 0, $n, [char[]]::new($n), 0)
        return 'UTF8'
    } catch [System.Text.DecoderFallbackException] { }
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        return [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage)
    }
    'Default'
}

function Import-DelimitedCsv {
    # Accepts ; as delimiter too, in case the CSV was re-saved from Excel
    param([string]$File)
    $encoding  = Get-CsvEncoding $File
    $header    = Get-Content -LiteralPath $File -TotalCount 1 -Encoding $encoding
    $delimiter = if ($header -match ';' -and $header -notmatch ',') { ';' } else { ',' }
    @(Import-Csv -LiteralPath $File -Delimiter $delimiter -Encoding $encoding)
}

function Assert-Columns {
    param($Rows, [string[]]$Columns, [string]$What)
    if ($Rows.Count -eq 0) { throw "$What is empty." }
    $missing = @($Columns | Where-Object { $Rows[0].PSObject.Properties.Name -notcontains $_ })
    if ($missing.Count) { throw "$What does not have the expected columns. Missing: $($missing -join ', ')" }
}

# JSON string encoding. HttpUtility escapes quotes, backslashes, control characters and also
# < > & ' as \u00XX, so the data can never close the <script> block it is embedded in.
try { Add-Type -AssemblyName System.Web -ErrorAction Stop } catch { }
$script:HttpUtility = $null
try { $null = [System.Web.HttpUtility]::JavaScriptStringEncode('x', $true); $script:HttpUtility = [System.Web.HttpUtility] } catch { }

function ConvertTo-JsonText {
    param([string]$Text)
    if ($script:HttpUtility) { return $script:HttpUtility::JavaScriptStringEncode($Text, $true) }
    # Fallback, same escaping rules
    $sb = [System.Text.StringBuilder]::new($Text.Length + 2)
    [void]$sb.Append('"')
    foreach ($ch in $Text.ToCharArray()) {
        $code = [int]$ch
        if     ($ch -eq '"')  { [void]$sb.Append('\"') }
        elseif ($ch -eq '\')  { [void]$sb.Append('\\') }
        elseif ($code -lt 32 -or $ch -eq '<' -or $ch -eq '>' -or $ch -eq '&' -or $ch -eq "'") {
            [void]$sb.Append(('\u{0:x4}' -f $code))
        }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"')
    $sb.ToString()
}

function Add-JsonStringArray {
    param([System.Text.StringBuilder]$Sb, [string]$Name, $Items)
    [void]$Sb.Append('"').Append($Name).Append('":[')
    $first = $true
    foreach ($s in $Items) {
        if (-not $first) { [void]$Sb.Append(',') }
        [void]$Sb.Append((ConvertTo-JsonText $s))
        $first = $false
    }
    [void]$Sb.Append(']')
}

# =============================================================================================
# Group membership: model
# =============================================================================================

$script:TypeCode = @{ user = 0; group = 1; computer = 2; service = 3; foreign = 4; wellknown = 5; contact = 6; unknown = 7 }
$script:MaxGroupsToRead = 5000

function New-PrincipalObject {
    param(
        [string]$Key, [string]$Name, [string]$Display = '', [string]$Type = 'unknown',
        [bool]$Disabled = $false, [bool]$Local = $false, [string]$Source = 'ad',
        [string]$Sid = '', [string]$Dn = '', [string]$Domain = '', [string]$Server = '', [string]$Note = ''
    )
    [pscustomobject]@{
        Key = $Key; Name = $Name; Display = $Display; Type = $Type; Disabled = $Disabled; Local = $Local
        Source = $Source; Sid = $Sid; Dn = $Dn; Domain = $Domain; Server = $Server; Note = $Note
        Members = $null; Total = 0; Error = ''; Expanded = $false
    }
}

# Principals without a member list, keyed by SID (language independent)
$script:WellKnownNotes = @{
    'S-1-1-0'  = 'Everyone: every account, including Guest. It has no member list; it covers anyone who reaches the share.'
    'S-1-5-11' = 'Authenticated Users: every account that has signed in, from this forest and trusted domains, including computer accounts. It has no member list.'
    'S-1-5-2'  = 'NETWORK: anyone accessing the folder over the network. Assigned at sign-in; it has no member list.'
    'S-1-5-4'  = 'INTERACTIVE: anyone signed in on the server locally or through Remote Desktop. Assigned at sign-in; it has no member list.'
    'S-1-5-18' = 'SYSTEM: the operating system and services running as Local System on the file server.'
    'S-1-5-19' = 'LOCAL SERVICE: services running as Local Service on the file server.'
    'S-1-5-20' = 'NETWORK SERVICE: services running as Network Service on the file server.'
    'S-1-5-7'  = 'ANONYMOUS LOGON: connections made without credentials.'
    'S-1-5-9'  = 'ENTERPRISE DOMAIN CONTROLLERS: every domain controller in the forest.'
    'S-1-5-10' = 'PRINCIPAL SELF: the account the object represents.'
    'S-1-3-0'  = 'CREATOR OWNER: a placeholder, replaced by the account that creates a file or subfolder.'
    'S-1-3-1'  = 'CREATOR GROUP: a placeholder, replaced by the primary group of the account that creates an item.'
    'S-1-3-4'  = 'OWNER RIGHTS: limits what the owner of a file or folder can do.'
}

function Test-ExternalDn {
    # True when one of the containers above the account (OU=... or CN=...) contains one of the patterns
    param([string]$Dn, [string[]]$Patterns)
    if (-not $Dn -or -not $Patterns) { return $false }
    $parts = @($Dn -split '(?<!\\),')
    for ($i = 1; $i -lt $parts.Count; $i++) {
        if ($parts[$i] -notmatch '^\s*(OU|CN)=(.*)$') { continue }
        $name = $Matches[2]
        foreach ($pat in $Patterns) { if ($pat -and $name -like "*$pat*") { return $true } }
    }
    return $false
}

function Test-BroadSid {
    # Principals that stand for (almost) everyone: Everyone, Authenticated Users, Anonymous, NETWORK,
    # INTERACTIVE, BUILTIN\Users, BUILTIN\Guests, and Domain Users / Guests / Computers of any domain
    param([string]$Sid)
    if (-not $Sid) { return $false }
    if (@('S-1-1-0', 'S-1-5-11', 'S-1-5-7', 'S-1-5-2', 'S-1-5-4', 'S-1-5-32-545', 'S-1-5-32-546') -contains $Sid) { return $true }
    return ($Sid -match '^S-1-5-21-\d+-\d+-\d+-(513|514|515)$')
}

function Get-WellKnownNote {
    param([string]$Sid)
    if (-not $Sid) { return $null }
    if ($script:WellKnownNotes.ContainsKey($Sid)) { return $script:WellKnownNotes[$Sid] }
    if ($Sid -like 'S-1-5-80-*') { return 'Windows service account (NT SERVICE) on the file server.' }
    if ($Sid -like 'S-1-15-*')   { return 'App package principal (Windows app containers).' }
    if (($Sid -match '^S-1-5-(\d+)$' -and [int]$Matches[1] -lt 21) -or $Sid -like 'S-1-2-*' -or
        $Sid -like 'S-1-5-64-*' -or $Sid -like 'S-1-16-*') {
        return 'Built-in Windows principal, assigned at sign-in. It has no member list.'
    }
    return $null
}

# Used when a name cannot be translated on this computer (e.g. a French scan read on an English
# workstation). Only applied to names without a domain or with a local authority as domain.
$script:KnownNameSids = @{
    'Everyone' = 'S-1-1-0'; 'Tout le monde' = 'S-1-1-0'; 'Jeder' = 'S-1-1-0'
    'Authenticated Users' = 'S-1-5-11'; 'Utilisateurs authentifiés' = 'S-1-5-11'; 'Authentifizierte Benutzer' = 'S-1-5-11'
    'SYSTEM' = 'S-1-5-18'; 'Système' = 'S-1-5-18'
    'INTERACTIVE' = 'S-1-5-4'; 'NETWORK' = 'S-1-5-2'; 'RESEAU' = 'S-1-5-2'; 'NETZWERK' = 'S-1-5-2'
    'CREATOR OWNER' = 'S-1-3-0'; 'CREATEUR PROPRIETAIRE' = 'S-1-3-0'; 'ERSTELLER-BESITZER' = 'S-1-3-0'
    'Administrators' = 'S-1-5-32-544'; 'Administrateurs' = 'S-1-5-32-544'; 'Administratoren' = 'S-1-5-32-544'
    'Users' = 'S-1-5-32-545'; 'Utilisateurs' = 'S-1-5-32-545'; 'Benutzer' = 'S-1-5-32-545'
    'Guests' = 'S-1-5-32-546'; 'Invités' = 'S-1-5-32-546'; 'Gäste' = 'S-1-5-32-546'
    'Backup Operators' = 'S-1-5-32-551'; 'Opérateurs de sauvegarde' = 'S-1-5-32-551'; 'Sicherungs-Operatoren' = 'S-1-5-32-551'
}
$script:LocalAuthorityNames = @('BUILTIN', 'NT AUTHORITY', 'AUTORITE NT', 'NT-AUTORITÄT')

# =============================================================================================
# Group membership: directory access (ADSI, no RSAT needed)
# ---- BEGIN DIRECTORY ACCESS ----
# =============================================================================================

$script:AdProps         = [string[]]@('distinguishedName', 'objectClass', 'objectSid', 'sAMAccountName', 'displayName', 'userAccountControl', 'cn')
$script:DomainRoots     = @{}
$script:NetbiosByDns    = @{}
$script:SidCache        = @{}
$script:LocalGroupCache = @{}
$script:ForestName      = ''
$script:HomeDomain      = ''

function Initialize-Directory {
    Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $script:HomeDomain = $domain.Name
    $script:ForestName = $domain.Forest.Name

    # NetBIOS name of every domain in the forest, so members show as CORP\name like the ACLs do
    try {
        $rootDse = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$($script:HomeDomain)/RootDSE")
        $config  = [string]$rootDse.psbase.Properties['configurationNamingContext'].Value
        $parts   = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$($script:HomeDomain)/CN=Partitions,$config")
        $ds = [System.DirectoryServices.DirectorySearcher]::new($parts, '(&(objectClass=crossRef)(nETBIOSName=*))', [string[]]@('nETBIOSName', 'dnsRoot'))
        $ds.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
        $results = $ds.FindAll()
        foreach ($r in $results) {
            $script:NetbiosByDns[[string]$r.Properties['dnsroot'][0]] = [string]$r.Properties['netbiosname'][0]
        }
        $results.Dispose(); $ds.Dispose()
    }
    catch { }
}

function ConvertTo-SidString {
    param([string]$Identity)
    try { ([System.Security.Principal.NTAccount]$Identity).Translate([System.Security.Principal.SecurityIdentifier]).Value }
    catch { $null }
}

function Resolve-SidName {
    param([string]$Sid)
    try { ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value }
    catch { $Sid }
}

function Get-DomainRoot {
    param([string]$Domain)
    if (-not $script:DomainRoots.ContainsKey($Domain)) {
        $script:DomainRoots[$Domain] = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$Domain")
    }
    $script:DomainRoots[$Domain]
}

function Get-DomainFromDn {
    param([string]$Dn)
    (@($Dn -split ',' | Where-Object { $_ -match '^\s*DC=' } | ForEach-Object { $_ -replace '^\s*DC=', '' }) -join '.')
}

function ConvertTo-LdapFilterValue {
    param([string]$Value)
    $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
}

function ConvertTo-LdapSid {
    param([string]$Sid)
    $s = [System.Security.Principal.SecurityIdentifier]::new($Sid)
    $b = [byte[]]::new($s.BinaryLength)
    $s.GetBinaryForm($b, 0)
    -join ($b | ForEach-Object { '\{0:x2}' -f $_ })
}

function ConvertFrom-AdResult {
    param($Result)
    $p  = $Result.Properties
    $dn = [string]$p['distinguishedname'][0]
    $classes = @($p['objectclass'])
    $type =
        if     ($classes -contains 'foreignSecurityPrincipal')        { 'foreign' }
        elseif ($classes -contains 'msDS-GroupManagedServiceAccount' -or
                $classes -contains 'msDS-ManagedServiceAccount')      { 'service' }
        elseif ($classes -contains 'computer')                        { 'computer' }
        elseif ($classes -contains 'group')                           { 'group' }
        elseif ($classes -contains 'user')                            { 'user' }
        elseif ($classes -contains 'contact')                         { 'contact' }
        else                                                          { 'unknown' }

    $sid = ''
    if ($p['objectsid'].Count) { $sid = [System.Security.Principal.SecurityIdentifier]::new([byte[]]$p['objectsid'][0], 0).Value }
    $domain  = Get-DomainFromDn $dn
    $sam     = if ($p['samaccountname'].Count) { [string]$p['samaccountname'][0] } else { '' }
    $netbios = $script:NetbiosByDns[$domain]
    $name =
        if ($type -eq 'foreign') { Resolve-SidName $sid }                    # member from a trusted domain
        elseif ($sam)            { if ($netbios) { "$netbios\$sam" } else { "$domain\$sam" } }
        else                     { [string]$p['cn'][0] }
    $display = if ($p['displayname'].Count) { [string]$p['displayname'][0] } else { '' }
    $uac     = if ($p['useraccountcontrol'].Count) { [int]$p['useraccountcontrol'][0] } else { 0 }
    $note    = if ($type -eq 'foreign') { 'Member from a trusted domain or forest; its own group memberships are not read.' } else { '' }

    New-PrincipalObject -Key $(if ($sid) { $sid } else { $dn }) -Name $name -Display $display -Type $type `
        -Disabled ([bool]($uac -band 2)) -Source 'ad' -Sid $sid -Dn $dn -Domain $domain -Note $note
}

function Get-AdObjectBySid {
    param([string]$Sid)
    if ($script:SidCache.ContainsKey($Sid)) { return $script:SidCache[$Sid] }
    $result = $null

    # 1) <SID=...> binding: resolves objects of this domain
    try {
        $entry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://<SID=$Sid>")
        $ds = [System.DirectoryServices.DirectorySearcher]::new($entry, '(objectClass=*)', $script:AdProps, [System.DirectoryServices.SearchScope]::Base)
        try { $r = $ds.FindOne(); if ($r) { $result = ConvertFrom-AdResult $r } } finally { $ds.Dispose() }
    }
    catch { }

    # 2) Global catalog: the other domains of the forest
    if (-not $result -and $script:ForestName) {
        try {
            $gc = [System.DirectoryServices.DirectoryEntry]::new("GC://$($script:ForestName)")
            $ds = [System.DirectoryServices.DirectorySearcher]::new($gc, "(objectSid=$(ConvertTo-LdapSid $Sid))", $script:AdProps)
            try { $r = $ds.FindOne(); if ($r) { $result = ConvertFrom-AdResult $r } } finally { $ds.Dispose() }
        }
        catch { }
    }

    $script:SidCache[$Sid] = $result
    $result
}

function Resolve-AdDns {
    # Looks up many DNs with few queries: one OR-filter per 40 DNs, per domain
    param([string[]]$Dns)
    $map = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($byDomain in ($Dns | Group-Object { Get-DomainFromDn $_ })) {
        $root = Get-DomainRoot $byDomain.Name
        $list = @($byDomain.Group)
        for ($i = 0; $i -lt $list.Count; $i += 40) {
            $chunk  = $list[$i..([Math]::Min($i + 39, $list.Count - 1))]
            $filter = '(|' + (($chunk | ForEach-Object { '(distinguishedName=' + (ConvertTo-LdapFilterValue $_) + ')' }) -join '') + ')'
            $ds = [System.DirectoryServices.DirectorySearcher]::new($root, $filter, $script:AdProps)
            $ds.PageSize = 500
            try {
                $results = $ds.FindAll()
                foreach ($r in $results) { $o = ConvertFrom-AdResult $r; $map[$o.Dn] = $o }
                $results.Dispose()
            }
            catch { }   # unresolved DNs are reported as 'unresolved' members
            finally { $ds.Dispose() }
        }
    }
    $map
}

function Get-AdPrimaryGroupMembers {
    # Accounts whose primary group is this group are not listed in its member attribute
    param([string]$Domain, [int]$Rid, [int]$Cap)
    $members = [System.Collections.Generic.List[object]]::new()
    $total = 0
    $ds = [System.DirectoryServices.DirectorySearcher]::new((Get-DomainRoot $Domain), "(primaryGroupID=$Rid)", $script:AdProps)
    $ds.PageSize = 1000
    try {
        $results = $ds.FindAll()
        foreach ($r in $results) {
            $total++
            if ($members.Count -lt $Cap) { $members.Add((ConvertFrom-AdResult $r)) }
        }
        $results.Dispose()
    }
    finally { $ds.Dispose() }
    [pscustomobject]@{ Members = $members; Total = $total }
}

function Get-AdGroupMembers {
    param($Group, [int]$Cap)
    $entry = [System.DirectoryServices.DirectoryEntry]::new('LDAP://' + $Group.Domain + '/' + $Group.Dn.Replace('/', '\/'))

    # Ranged retrieval: AD returns at most 1500 values of 'member' per read
    $dns = [System.Collections.Generic.List[string]]::new()
    while ($true) {
        $attr = 'member;range={0}-*' -f $dns.Count
        $ds = [System.DirectoryServices.DirectorySearcher]::new($entry, '(objectClass=*)', [string[]]@($attr), [System.DirectoryServices.SearchScope]::Base)
        try { $r = $ds.FindOne() } finally { $ds.Dispose() }
        if (-not $r) { break }
        $prop = @($r.Properties.PropertyNames | Where-Object { $_ -like 'member;range=*' })
        if ($prop.Count -eq 0) { break }                     # no members
        $vals = $r.Properties[$prop[0]]
        foreach ($v in $vals) { $dns.Add([string]$v) }
        if ($prop[0].EndsWith('-*') -or $vals.Count -eq 0) { break }
    }

    $members = [System.Collections.Generic.List[object]]::new()
    $take = [Math]::Min($Cap, $dns.Count)
    if ($take -gt 0) {
        $first = $dns.GetRange(0, $take).ToArray()
        $resolved = Resolve-AdDns $first
        foreach ($dn in $first) {
            $o = $null
            if ($resolved.TryGetValue($dn, [ref]$o)) { $members.Add($o) }
            else {
                $rdn = ($dn -split '(?<!\\),')[0] -replace '^[A-Za-z]+=', ''
                $members.Add((New-PrincipalObject -Key $dn -Name $rdn -Type 'unknown' -Dn $dn -Note "Could not be read: $dn"))
            }
        }
    }
    $total = $dns.Count

    $rid = [long](($Group.Sid -split '-')[-1])   # RIDs are unsigned 32-bit
    if ($Group.Sid -like 'S-1-5-21-*' -and @(513, 514, 515, 516, 521) -contains $rid) {
        $primary = Get-AdPrimaryGroupMembers -Domain $Group.Domain -Rid $rid -Cap ([Math]::Max(0, $Cap - $members.Count))
        $total += $primary.Total
        foreach ($m in $primary.Members) { $members.Add($m) }
    }
    [pscustomobject]@{ Members = $members; Total = $total }
}

function Get-LocalGroupPath {
    # Local groups are matched by SID, so localized names (Administrateurs, Benutzer...) don't matter
    param([string]$Server, [string]$Sid, [string]$Fallback)
    if (-not $script:LocalGroupCache.ContainsKey($Server)) {
        $map = @{}
        try {
            $computer = [System.DirectoryServices.DirectoryEntry]::new("WinNT://$Server,computer")
            $children = $computer.psbase.Children
            [void]$children.SchemaFilter.Add('group')
            foreach ($g in $children) {
                try {
                    $s = [System.Security.Principal.SecurityIdentifier]::new([byte[]]$g.psbase.Properties['objectSid'].Value, 0).Value
                    $map[$s] = $g.psbase.Name
                }
                catch { }
            }
        }
        catch { }
        $script:LocalGroupCache[$Server] = $map
    }
    $name = $script:LocalGroupCache[$Server][$Sid]
    if (-not $name) { $name = $Fallback }
    "WinNT://$Server/$name,group"
}

function Get-LocalGroupMembers {
    param($Group, [int]$Cap)
    $fallback = $Group.Name
    $k = $fallback.IndexOf('\')
    if ($k -ge 0) { $fallback = $fallback.Substring($k + 1) }

    $entry = [System.DirectoryServices.DirectoryEntry]::new((Get-LocalGroupPath $Group.Server $Group.Sid $fallback))
    $raw = @($entry.psbase.Invoke('Members'))
    $members = [System.Collections.Generic.List[object]]::new()
    foreach ($m in $raw) {
        if ($members.Count -ge $Cap) { break }
        $t     = $m.GetType()
        $path  = [string]$t.InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
        $class = [string]$t.InvokeMember('Class', 'GetProperty', $null, $m, $null)
        $sid   = ''
        try { $sid = [System.Security.Principal.SecurityIdentifier]::new([byte[]]$t.InvokeMember('objectSid', 'GetProperty', $null, $m, $null), 0).Value } catch { }
        $parts = @(($path -replace '^WinNT://', '') -split '/')
        $members.Add((ConvertFrom-LocalMember -Parts $parts -Class $class -Sid $sid -Server $Group.Server))
    }
    [pscustomobject]@{ Members = $members; Total = $raw.Count }
}

function Find-LocalPrincipal {
    # Accounts local to the file server (FS01\Something), looked up by name
    param([string]$Server, [string]$Name)
    $short = ($Server -split '\.')[0]
    foreach ($class in 'group', 'user') {
        try {
            $e = [System.DirectoryServices.DirectoryEntry]::new("WinNT://$Server/$Name,$class")
            $sid = [System.Security.Principal.SecurityIdentifier]::new([byte[]]$e.psbase.Properties['objectSid'].Value, 0).Value
            return (New-PrincipalObject -Key "$Server|$sid" -Name "$short\$Name" -Type $class -Source 'local' -Local $true -Server $Server -Sid $sid)
        }
        catch { }
    }
    $null
}

# ---- END DIRECTORY ACCESS ----

function ConvertFrom-LocalMember {
    # One member of a local group, from its WinNT path (DOMAIN/name or DOMAIN/COMPUTER/name)
    param([string[]]$Parts, [string]$Class, [string]$Sid, [string]$Server)
    $label = $Parts -join '\'
    $note = Get-WellKnownNote $Sid
    if ($note) { return (New-PrincipalObject -Key "wk|$Sid" -Name $label -Type 'wellknown' -Source 'none' -Sid $Sid -Note $note) }

    if ($Parts.Count -ge 3) {
        $type = if ($Class -eq 'Group') { 'group' } else { 'user' }
        $key  = if ($Sid) { "$Server|$Sid" } else { "$Server|$($Parts[-1])" }
        return (New-PrincipalObject -Key $key -Name "$($Parts[-2])\$($Parts[-1])" -Type $type -Source 'local' -Local $true -Server $Server -Sid $Sid)
    }
    if ($Sid) {
        $ad = Get-AdObjectBySid $Sid
        if ($ad) { return $ad }
        $why = if ($Parts.Count -le 1) { 'Orphaned SID: the account no longer exists.' } else { 'Not found in Active Directory.' }
        return (New-PrincipalObject -Key $Sid -Name $label -Type 'unknown' -Sid $Sid -Note $why)
    }
    New-PrincipalObject -Key "$Server|$label" -Name $label -Type 'unknown' -Note 'Could not be resolved.'
}

function Resolve-IdentityPrincipal {
    # Maps an identity as written in the scan (CORP\GG-Finance, BUILTIN\Users, Everyone...) to a principal
    param([string]$Identity, [string]$FileServer)
    $domainPart = ''
    $namePart   = $Identity
    $k = $Identity.IndexOf('\')
    if ($k -ge 0) { $domainPart = $Identity.Substring(0, $k); $namePart = $Identity.Substring($k + 1) }

    $sid = ConvertTo-SidString $Identity
    if (-not $sid -and ($domainPart -eq '' -or $script:LocalAuthorityNames -contains $domainPart) -and
        $script:KnownNameSids.ContainsKey($namePart)) {
        $sid = $script:KnownNameSids[$namePart]
    }

    if ($sid) {
        $note = Get-WellKnownNote $sid
        if ($note) { return (New-PrincipalObject -Key "wk|$sid" -Name $Identity -Type 'wellknown' -Source 'none' -Sid $sid -Note $note) }
        if ($sid -like 'S-1-5-32-*') {
            return (New-PrincipalObject -Key "$FileServer|$sid" -Name $Identity -Type 'group' -Source 'local' -Local $true -Server $FileServer -Sid $sid)
        }
        $ad = Get-AdObjectBySid $sid
        if ($ad) { return $ad }
    }

    $short = ($FileServer -split '\.')[0]
    if ($domainPart -and $short -and $domainPart -eq $short) {
        $local = Find-LocalPrincipal -Server $FileServer -Name $namePart
        if ($local) { return $local }
    }
    if ($sid) { return (New-PrincipalObject -Key $sid -Name $Identity -Type 'unknown' -Sid $sid -Note 'Not found in Active Directory.') }
    return $null
}

function Get-GroupMembershipModel {
    param([System.Collections.Generic.List[string]]$Identities, [string]$FileServer, [int]$Cap)

    $principals = [System.Collections.Generic.List[object]]::new()
    $byKey      = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::OrdinalIgnoreCase)
    $queue      = [System.Collections.Generic.Queue[int]]::new()
    $add = {
        param($o)
        $i = 0
        if ($byKey.TryGetValue($o.Key, [ref]$i)) { return $i }
        $i = $principals.Count
        $byKey[$o.Key] = $i
        $principals.Add($o)
        if ($o.Type -eq 'group') { $queue.Enqueue($i) }
        $i
    }

    # 1) The identities in the scan
    $map = [int[]]::new($Identities.Count)
    for ($id = 0; $id -lt $Identities.Count; $id++) {
        $map[$id] = -1
        $name = $Identities[$id]
        if (-not $name -or $name -like 'S-1-*') { continue }      # orphaned SID: nothing to resolve
        Write-Progress -Activity 'Reading group membership' -Status "Resolving $name" -PercentComplete ([int](100 * $id / [Math]::Max(1, $Identities.Count)))
        $o = $null
        try { $o = Resolve-IdentityPrincipal -Identity $name -FileServer $FileServer } catch { }
        if ($o) { $map[$id] = & $add $o }
    }

    # 2) Their members, following nested groups. Each group is read once, so circular nesting ends.
    $groupsRead = 0
    $errors     = 0
    while ($queue.Count -gt 0) {
        $gi = $queue.Dequeue()
        $g  = $principals[$gi]
        if ($g.Expanded) { continue }
        $g.Expanded = $true
        $g.Members  = [System.Collections.Generic.List[int]]::new()
        if ($groupsRead -ge $script:MaxGroupsToRead) {
            $g.Error = "Not read: more than $($script:MaxGroupsToRead) groups are nested under the groups in this scan."
            continue
        }
        $groupsRead++
        Write-Progress -Activity 'Reading group membership' -Status ('{0:N0} groups read, {1:N0} queued: {2}' -f $groupsRead, $queue.Count, $g.Name)
        try {
            $res = if ($g.Source -eq 'local') { Get-LocalGroupMembers -Group $g -Cap $Cap } else { Get-AdGroupMembers -Group $g -Cap $Cap }
            $g.Total = [int]$res.Total
            $seen = [System.Collections.Generic.HashSet[int]]::new()
            foreach ($m in $res.Members) {
                $mi = & $add $m
                if ($mi -ne $gi -and $seen.Add($mi)) { $g.Members.Add($mi) }
            }
        }
        catch {
            $g.Error = $_.Exception.Message
            $errors++
        }
    }
    Write-Progress -Activity 'Reading group membership' -Completed

    [pscustomobject]@{ Principals = $principals; Map = $map; GroupsRead = $groupsRead; Errors = $errors }
}

# =============================================================================================
# Load the scan
# =============================================================================================

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "File not found: $Path" }
$inputFile = (Resolve-Path -LiteralPath $Path).ProviderPath

Write-Host "Reading $inputFile ..."
$rows = Import-DelimitedCsv $inputFile
Assert-Columns $rows @('FolderPath', 'Depth', 'Owner', 'InheritanceDisabled', 'Identity', 'Rights',
                       'AccessType', 'IsInherited', 'AppliesTo', 'Note') 'The scan CSV'

$ci = [StringComparer]::OrdinalIgnoreCase

# String pools: every identity / rights text / "applies to" text / note is stored once
$idMap      = [System.Collections.Generic.Dictionary[string,int]]::new($ci)
$idList     = [System.Collections.Generic.List[string]]::new()
$rightsMap  = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::Ordinal)
$rightsList = [System.Collections.Generic.List[string]]::new()
$appMap     = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::Ordinal)
$appList    = [System.Collections.Generic.List[string]]::new()
$noteMap    = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::Ordinal)
$noteList   = [System.Collections.Generic.List[string]]::new()

# Each distinct entry (identity + rights + allow/deny + applies-to) is stored once
$aceMap  = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::Ordinal)
$aceJson = [System.Collections.Generic.List[string]]::new()

$folderMap  = [System.Collections.Generic.Dictionary[string,int]]::new($ci)
$folders    = [System.Collections.Generic.List[object]]::new()
$entryCount = 0

foreach ($r in $rows) {
    $fi = 0
    if (-not $folderMap.TryGetValue($r.FolderPath, [ref]$fi)) {
        $fi = $folders.Count
        $folderMap[$r.FolderPath] = $fi
        $folders.Add([pscustomobject]@{
            Path      = $r.FolderPath
            Depth     = [int]$r.Depth
            Name      = $r.FolderPath
            Parent    = -1
            Owner     = -1
            Flags     = 0
            Explicit  = [System.Collections.Generic.List[int]]::new()
            Inherited = [System.Collections.Generic.List[int]]::new()
            Notes     = [System.Collections.Generic.List[string]]::new()
        })
    }
    $f = $folders[$fi]

    if ($r.Owner -and $f.Owner -lt 0) {
        $oi = 0
        if (-not $idMap.TryGetValue($r.Owner, [ref]$oi)) { $oi = $idList.Count; $idMap[$r.Owner] = $oi; $idList.Add($r.Owner) }
        $f.Owner = $oi
    }
    if ($r.InheritanceDisabled -eq 'True') { $f.Flags = $f.Flags -bor 1 }
    if ($r.Note -and -not $f.Notes.Contains($r.Note)) {
        $f.Notes.Add($r.Note)
        if     ($r.Note -like 'ERROR*')            { $f.Flags = $f.Flags -bor 2 }
        elseif ($r.Note -like 'No access rules*')  { $f.Flags = $f.Flags -bor 4 }
        elseif ($r.Note -like '*not scanned*')     { $f.Flags = $f.Flags -bor 8 }
    }

    if (-not $r.Identity) { continue }

    $aceKey = $r.Identity + "`t" + $r.Rights + "`t" + $r.AccessType + "`t" + $r.AppliesTo
    $ai = 0
    if (-not $aceMap.TryGetValue($aceKey, [ref]$ai)) {
        $id = 0
        if (-not $idMap.TryGetValue($r.Identity, [ref]$id)) { $id = $idList.Count; $idMap[$r.Identity] = $id; $idList.Add($r.Identity) }
        $rt = 0
        if (-not $rightsMap.TryGetValue($r.Rights, [ref]$rt)) { $rt = $rightsList.Count; $rightsMap[$r.Rights] = $rt; $rightsList.Add($r.Rights) }
        $ap = 0
        if (-not $appMap.TryGetValue($r.AppliesTo, [ref]$ap)) { $ap = $appList.Count; $appMap[$r.AppliesTo] = $ap; $appList.Add($r.AppliesTo) }
        $ai = $aceJson.Count
        $aceMap[$aceKey] = $ai
        $aceJson.Add(('[{0},{1},{2},{3}]' -f $id, $rt, $(if ($r.AccessType -eq 'Deny') { 1 } else { 0 }), $ap))
    }
    if ($r.IsInherited -eq 'True') { $f.Inherited.Add($ai) } else { $f.Explicit.Add($ai) }
    $entryCount++
}
$rows = $null
Write-Host ('{0:N0} folders, {1:N0} permission entries, {2:N0} identities.' -f $folders.Count, $entryCount, $idList.Count)

# --- Parent links and display names ------------------------------------------------------------
foreach ($f in $folders) {
    $trimmed = $f.Path.TrimEnd('\', '/')
    $k = $trimmed.LastIndexOfAny([char[]]@('\', '/'))
    if ($k -lt 0) { continue }
    $parentPath = $trimmed.Substring(0, $k)
    $pi = -1
    $found = 0   # TryGetValue sets this to 0 on a miss, so only trust it when it returns $true
    if ($parentPath -and $folderMap.TryGetValue($parentPath, [ref]$found)) { $pi = $found }
    elseif ($folderMap.TryGetValue($parentPath + $trimmed[$k], [ref]$found)) { $pi = $found }   # volume root such as D:\
    if ($pi -ge 0 -and $folders[$pi] -ne $f) {
        $f.Parent = $pi
        $f.Name   = $trimmed.Substring($k + 1)
    }
}

$minDepth = ($folders | Measure-Object -Property Depth -Minimum).Minimum
$rootPath = @($folders | Where-Object { $_.Depth -eq $minDepth })[0].Path

# =============================================================================================
# Findings (optional)
# =============================================================================================

$findingsJson = [System.Collections.Generic.List[string]]::new()
$findingsFile = ''
if ($FindingsPath) {
    if (-not (Test-Path -LiteralPath $FindingsPath -PathType Leaf)) { throw "File not found: $FindingsPath" }
    $findingsFile = (Resolve-Path -LiteralPath $FindingsPath).ProviderPath
    $findRows = Import-DelimitedCsv $findingsFile
    Assert-Columns $findRows @('Severity', 'CheckId', 'Check', 'FolderPath', 'Identity', 'Rights', 'Details') 'The findings CSV'

    $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $skipped = 0
    foreach ($fr in $findRows) {
        $fi = -1
        if (-not $folderMap.TryGetValue($fr.FolderPath, [ref]$fi) -or -not $sevRank.ContainsKey($fr.Severity)) { $skipped++; continue }
        $findingsJson.Add(('[{0},{1},{2},{3},{4},{5},{6}]' -f $fi, $sevRank[$fr.Severity],
            (ConvertTo-JsonText $fr.CheckId), (ConvertTo-JsonText $fr.Check), (ConvertTo-JsonText $fr.Identity),
            (ConvertTo-JsonText $fr.Rights), (ConvertTo-JsonText $fr.Details)))
    }
    Write-Host ('{0:N0} findings loaded.' -f $findingsJson.Count)
    if ($skipped) { Write-Warning "$skipped findings refer to folders that are not in this scan and were skipped. Are both files from the same scan?" }
}

# =============================================================================================
# Group membership (optional)
# =============================================================================================

$membershipJson = ''
$model = $null
if ($IncludeGroupMembers) {
    $directoryReady = $false
    try { Initialize-Directory; $directoryReady = $true }
    catch {
        Write-Warning ("Group membership skipped: Active Directory cannot be reached from this computer ({0}). The graph is built without it." -f $_.Exception.Message)
    }

    if ($directoryReady) {
        if (-not $FileServer) {
            if ($rootPath -match '^\\\\([^\\?]+)\\') { $FileServer = $Matches[1] }
            else {
                $FileServer = [Environment]::MachineName
                Write-Warning "The scan used a local path, so BUILTIN groups are read on this computer ($FileServer). If the scan ran on another server, add -FileServer <server>."
            }
        }
        if ($FileServer -eq $script:HomeDomain -or $script:NetbiosByDns.ContainsKey($FileServer)) {
            Write-Warning "'$FileServer' is a domain name (domain DFS path?). BUILTIN groups would be read on a domain controller. Add -FileServer <actual file server>."
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $model = Get-GroupMembershipModel -Identities $idList -FileServer $FileServer -Cap $MaxMembersPerGroup
        $timer.Stop()

        $txtMap  = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::Ordinal)
        $txtList = [System.Collections.Generic.List[string]]::new()
        $textIndex = {
            param([string]$t)
            $i = 0
            if (-not $txtMap.TryGetValue($t, [ref]$i)) { $i = $txtList.Count; $txtMap[$t] = $i; $txtList.Add($t) }
            $i
        }

        $pJson = [System.Collections.Generic.List[string]]::new($model.Principals.Count)
        $gJson = [System.Collections.Generic.List[string]]::new()
        $accounts = 0
        $externals = 0
        for ($i = 0; $i -lt $model.Principals.Count; $i++) {
            $p = $model.Principals[$i]
            $flags = 0
            if ($p.Disabled) { $flags = $flags -bor 1 }
            if ($p.Local)    { $flags = $flags -bor 2 }
            if (Test-BroadSid $p.Sid) { $flags = $flags -bor 4 }
            if ($p.Type -ne 'group' -and $p.Type -ne 'wellknown' -and (Test-ExternalDn $p.Dn $ExternalOu)) { $flags = $flags -bor 8; $externals++ }
            $tc = $script:TypeCode[$p.Type]
            if ($null -eq $tc) { $tc = 7 }
            if ($tc -ne 1 -and $tc -ne 5) { $accounts++ }
            $noteIdx = if ($p.Note) { & $textIndex $p.Note } else { -1 }
            $sidOut  = if ($p.Type -eq 'wellknown') { $p.Sid } else { '' }
            $pJson.Add(('[{0},{1},{2},{3},{4},{5}]' -f (ConvertTo-JsonText $p.Name), (ConvertTo-JsonText $p.Display), $tc, $flags, $noteIdx, (ConvertTo-JsonText $sidOut)))
            if ($p.Type -eq 'group') {
                $members = if ($p.Members) { [string]::Join(',', $p.Members) } else { '' }
                $errIdx  = if ($p.Error) { & $textIndex $p.Error } else { -1 }
                $gJson.Add(('[{0},[{1}],{2},{3}]' -f $i, $members, $p.Total, $errIdx))
            }
        }

        $source = "Active Directory ($($script:ForestName)) and local groups on $FileServer"
        $msb = [System.Text.StringBuilder]::new()
        [void]$msb.Append('{"src":').Append((ConvertTo-JsonText $source))
        [void]$msb.Append(',"at":').Append((ConvertTo-JsonText (Get-Date).ToString('yyyy-MM-dd HH:mm')))
        [void]$msb.Append(',"cap":').Append($MaxMembersPerGroup)
        [void]$msb.Append(',"p":[').Append([string]::Join(',', $pJson)).Append(']')
        [void]$msb.Append(',"g":[').Append([string]::Join(',', $gJson)).Append(']')
        [void]$msb.Append(',"idp":[').Append([string]::Join(',', $model.Map)).Append(']')
        [void]$msb.Append(',')
        Add-JsonStringArray $msb 'txt' $txtList
        [void]$msb.Append('}')
        $membershipJson = $msb.ToString()

        Write-Host ('Group membership: {0:N0} groups read, {1:N0} accounts, {2:N0} external (OU matching {3}) ({4:mm\:ss}).' -f `
            $model.GroupsRead, $accounts, $externals, ((@($ExternalOu | ForEach-Object { "'$_'" })) -join ' or '), $timer.Elapsed)
        if ($model.Errors) {
            Write-Warning ('{0:N0} group(s) could not be read. They are marked "not readable" in the page, with the reason.' -f $model.Errors)
        }
    }
}

# =============================================================================================
# One Identity role assignments (optional)
# =============================================================================================

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

function Get-GroupKey {
    # Group name as matched between the role files, the scan and AD: the bare name, lower case.
    # Accepts name, DOMAIN\name, CN=name,OU=...,DC=... and name@domain.
    param([string]$Value)
    if (-not $Value) { return '' }
    $v = $Value.Trim().Trim('"')
    if ($v -match '^(?i)CN=((?:[^,\\]|\\.)+),') { $v = $Matches[1] -replace '\\(.)', '$1' }
    elseif ($v.Contains('\')) { $v = $v.Substring($v.LastIndexOf('\') + 1) }
    elseif ($v -match '^([^@\s]+)@[^@\s]+$') { $v = $Matches[1] }
    $v.Trim().ToLowerInvariant()
}

function Split-GroupCell {
    param([string]$Value)
    @(($Value -split '\r?\n|\|') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Assert-RoleColumns {
    # The role files are read from two fixed columns; any other column is ignored
    param($Rows, [string]$GroupColumn, [string]$NameColumn, [string]$What, [string]$Param)
    $headers = @($Rows[0].PSObject.Properties.Name)
    $missing = @(@($NameColumn, $GroupColumn) | Where-Object { $headers -notcontains $_ })
    if ($missing.Count) {
        throw ("{0}: column(s) {1} not found. Columns in the file: {2}. Expected '{3}' (role) and '{4}' (group); if your export names them differently, use {5}NameColumn / {5}GroupColumn." -f `
            $What, (($missing | ForEach-Object { "'$_'" }) -join ', '), ($headers -join ', '), $NameColumn, $GroupColumn, $Param)
    }
}

$roleJson = ''
if ($BusinessRolePath -or $SystemRolePath) {
    # What the role files are matched against: the groups in the scan and, with -IncludeGroupMembers,
    # every group read from AD (so roles that assign nested groups are found too).
    $keyIds = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $keyPs  = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $addKey = {
        param($Dict, [string]$Key, [int]$Value)
        if (-not $Key) { return }
        $l = $null
        if (-not $Dict.TryGetValue($Key, [ref]$l)) { $l = [System.Collections.Generic.List[int]]::new(); $Dict[$Key] = $l }
        if (-not $l.Contains($Value)) { $l.Add($Value) }
    }
    for ($i = 0; $i -lt $idList.Count; $i++) {
        $n = $idList[$i]
        $k = $n.IndexOf('\')
        # BUILTIN, NT AUTHORITY and Everyone are never assigned by One Identity roles
        if ($n -like 'S-1-*' -or $k -lt 0 -or $script:LocalAuthorityNames -contains $n.Substring(0, $k)) { continue }
        & $addKey $keyIds (Get-GroupKey $n) $i
    }
    if ($model) {
        for ($i = 0; $i -lt $model.Principals.Count; $i++) {
            $pr = $model.Principals[$i]
            if ($pr.Type -ne 'group' -or $pr.Source -ne 'ad') { continue }
            & $addKey $keyPs (Get-GroupKey $pr.Name) $i
            if ($pr.Dn)      { & $addKey $keyPs (Get-GroupKey $pr.Dn) $i }
            if ($pr.Display) { & $addKey $keyPs (Get-GroupKey $pr.Display) $i }
        }
    }

    $roles       = [System.Collections.Generic.List[object]]::new()
    $roleIndex   = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::OrdinalIgnoreCase)
    $roleSources = [System.Collections.Generic.List[string]]::new()
    $specs = @(
        @{ Path = $BusinessRolePath; Kind = 0; What = 'Business roles'; G = $BusinessRoleGroupColumn; N = $BusinessRoleNameColumn; P = '-BusinessRole' },
        @{ Path = $SystemRolePath;   Kind = 1; What = 'System roles';   G = $SystemRoleGroupColumn;   N = $SystemRoleNameColumn;   P = '-SystemRole' }
    )
    $hintShown = $false
    foreach ($spec in $specs) {
        if (-not $spec.Path) { continue }
        if (-not (Test-Path -LiteralPath $spec.Path -PathType Leaf)) { throw "File not found: $($spec.Path)" }
        $file = (Resolve-Path -LiteralPath $spec.Path).ProviderPath
        $roleRows = Import-AnyCsv $file
        if ($roleRows.Count -eq 0) { Write-Warning "$($spec.What): $file is empty."; continue }
        Assert-RoleColumns -Rows $roleRows -GroupColumn $spec.G -NameColumn $spec.N -What $spec.What -Param $spec.P
        $cols = [pscustomobject]@{ Group = $spec.G; Name = $spec.N }
        $roleSources.Add([System.IO.Path]::GetFileName($file))

        $matched   = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $unmatched = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $seen      = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($row in $roleRows) {
            $roleName = ([string]$row.PSObject.Properties[$cols.Name].Value).Trim()
            $cell     = [string]$row.PSObject.Properties[$cols.Group].Value
            if (-not $roleName -or -not $cell.Trim()) { continue }
            [void]$seen.Add($roleName)
            $rk = '{0}|{1}' -f $spec.Kind, $roleName
            $ri = 0
            if (-not $roleIndex.TryGetValue($rk, [ref]$ri)) {
                $ri = $roles.Count
                $roleIndex[$rk] = $ri
                $roles.Add([pscustomobject]@{
                    Name  = $roleName; Kind = $spec.Kind
                    Ids   = [System.Collections.Generic.HashSet[int]]::new()
                    Ps    = [System.Collections.Generic.HashSet[int]]::new()
                    Other = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                })
            }
            $role = $roles[$ri]
            foreach ($gv in (Split-GroupCell $cell)) {
                $gk = Get-GroupKey $gv
                if (-not $gk) { continue }
                $l = $null; $hit = $false
                if ($keyIds.TryGetValue($gk, [ref]$l)) { foreach ($x in $l) { [void]$role.Ids.Add($x) }; $hit = $true }
                if ($keyPs.TryGetValue($gk, [ref]$l))  { foreach ($x in $l) { [void]$role.Ps.Add($x) };  $hit = $true }
                if ($hit) { [void]$matched.Add($gk) } else { [void]$unmatched.Add($gv); [void]$role.Other.Add($gv) }
            }
        }
        $kept = @($roles | Where-Object { $_.Kind -eq $spec.Kind -and ($_.Ids.Count + $_.Ps.Count) -gt 0 }).Count
        Write-Host ("{0} ({1}: role '{2}', group '{3}'): {4:N0} role(s), {5:N0} assign groups used here; {6:N0} group(s) matched, {7:N0} not related to these folders." -f `
            $spec.What, [System.IO.Path]::GetFileName($file), $cols.Name, $cols.Group, $seen.Count, $kept, $matched.Count, $unmatched.Count)
        if ($unmatched.Count -and -not $model -and -not $hintShown) {
            $hintShown = $true
            Write-Host '  Without -IncludeGroupMembers, groups are matched by name only to groups that are directly on the folders; nested groups and groups whose cn differs from the sAMAccountName are not found.'
        }
        if ($matched.Count -eq 0) {
            Write-Warning ("{0}: no group in column '{1}' matches a group in the scan{2} (values such as: {3})." -f $spec.What, $cols.Group,
                $(if ($model) { ' or in AD membership' } else { '' }),
                ((@($roleRows | Select-Object -First 3 | ForEach-Object { [string]$_.PSObject.Properties[$cols.Group].Value })) -join '; '))
        }
    }

    $rj = [System.Collections.Generic.List[string]]::new()
    foreach ($role in $roles) {
        if (($role.Ids.Count + $role.Ps.Count) -eq 0) { continue }    # roles unrelated to these folders are left out
        $other = @($role.Other | Sort-Object | Select-Object -First 50 | ForEach-Object { ConvertTo-JsonText $_ })
        $rj.Add(('[{0},{1},[{2}],[{3}],[{4}],{5}]' -f (ConvertTo-JsonText $role.Name), $role.Kind,
            (@($role.Ids) -join ','), (@($role.Ps) -join ','), ($other -join ','), $role.Other.Count))
    }
    $roleJson = '{"src":[' + ((@($roleSources | ForEach-Object { ConvertTo-JsonText $_ })) -join ',') + '],"roles":[' + ($rj -join ',') + ']}'
}

# =============================================================================================
# Teams from the One Identity department table (optional)
# =============================================================================================

function Select-TeamColumn {
    # The named column, or (when the default name is not in the file) a usual alternative
    param([string[]]$Headers, [string]$Wanted, [string[]]$Aliases, [bool]$Explicit, [bool]$Optional, [string]$Param, [string]$What)
    $hit = @($Headers | Where-Object { $_ -eq $Wanted })
    if ($hit.Count) { return $hit[0] }
    if (-not $Explicit) {
        foreach ($a in $Aliases) { $hit = @($Headers | Where-Object { $_ -eq $a }); if ($hit.Count) { return $hit[0] } }
    }
    if ($Optional -and -not $Explicit) { return $null }
    throw "Team file: column '$Wanted' ($What) not found. Columns in the file: $($Headers -join ', '). Use $Param to name the column."
}

$teamJson = ''
if ($TeamPath) {
    if (-not (Test-Path -LiteralPath $TeamPath -PathType Leaf)) { throw "File not found: $TeamPath" }
    $teamFile = (Resolve-Path -LiteralPath $TeamPath).ProviderPath
    $teamRows = Import-AnyCsv $teamFile
    if ($teamRows.Count -eq 0) { Write-Warning "Team file $teamFile is empty." }
    else {
        $headers = @($teamRows[0].PSObject.Properties.Name)
        $cAcc  = Select-TeamColumn $headers $TeamAccountColumn @('sAMAccountName', 'CentralAccount', 'AccountName', 'Account', 'UserName', 'Login') `
                     $PSBoundParameters.ContainsKey('TeamAccountColumn') $false '-TeamAccountColumn' 'the sAMAccountName'
        $cName = Select-TeamColumn $headers $TeamNameColumn @('Department', 'TeamName', 'Team', 'Ident_Department', 'Name') `
                     $PSBoundParameters.ContainsKey('TeamNameColumn') $false '-TeamNameColumn' 'the team name'
        $cPath = Select-TeamColumn $headers $TeamFullPathColumn @('TeamPath', 'DepartmentPath', 'TeamFullPath', 'Path') `
                     $PSBoundParameters.ContainsKey('TeamFullPathColumn') $true '-TeamFullPathColumn' 'the full team path'
        $cLoc  = Select-TeamColumn $headers $TeamLocationColumn @('Location', 'Ident_Locality', 'Locality', 'LocationCode', 'Site', 'SiteCode') `
                     $PSBoundParameters.ContainsKey('TeamLocationColumn') $true '-TeamLocationColumn' 'the location code'
        Write-Host ("Teams ({0}): account '{1}', team '{2}', full path {3}, location {4}." -f [System.IO.Path]::GetFileName($teamFile), $cAcc, $cName,
            $(if ($cPath) { "'$cPath'" } else { 'not in the file' }), $(if ($cLoc) { "'$cLoc'" } else { 'not in the file' }))

        $teamIndex = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::OrdinalIgnoreCase)
        $teamList  = [System.Collections.Generic.List[object]]::new()
        $locIndex  = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::OrdinalIgnoreCase)
        $locList   = [System.Collections.Generic.List[string]]::new()
        $bySam     = [System.Collections.Generic.Dictionary[string,int[]]]::new([StringComparer]::OrdinalIgnoreCase)
        $dupes = 0
        foreach ($r in $teamRows) {
            $sam  = ([string]$r.PSObject.Properties[$cAcc].Value).Trim()
            $team = ([string]$r.PSObject.Properties[$cName].Value).Trim()
            if (-not $sam -or -not $team) { continue }
            if ($sam.Contains('\')) { $sam = $sam.Substring($sam.LastIndexOf('\') + 1) }
            elseif ($sam -match '^([^@]+)@') { $sam = $Matches[1] }
            $path = if ($cPath) { ([string]$r.PSObject.Properties[$cPath].Value).Trim() } else { '' }
            $loc  = if ($cLoc)  { ([string]$r.PSObject.Properties[$cLoc].Value).Trim() } else { '' }
            if ($bySam.ContainsKey($sam)) { $dupes++; continue }        # first row wins
            $key = if ($path) { $path } else { $team }
            $ti = 0
            if (-not $teamIndex.TryGetValue($key, [ref]$ti)) { $ti = $teamList.Count; $teamIndex[$key] = $ti; $teamList.Add(@($team, $path)) }
            $li = -1
            if ($loc -and -not $locIndex.TryGetValue($loc, [ref]$li)) { $li = $locList.Count; $locIndex[$loc] = $li; $locList.Add($loc) }
            $bySam[$sam] = @($ti, $li)
        }

        # Match: members read from AD (-IncludeGroupMembers) and accounts set directly on the folders
        $usedTeams = [System.Collections.Generic.Dictionary[int,int]]::new()
        $usedLocs  = [System.Collections.Generic.Dictionary[int,int]]::new()
        $remap = {
            param([int[]]$tl)
            $nt = 0; if (-not $usedTeams.TryGetValue($tl[0], [ref]$nt)) { $nt = $usedTeams.Count; $usedTeams[$tl[0]] = $nt }
            $nl = -1
            if ($tl[1] -ge 0) { if (-not $usedLocs.TryGetValue($tl[1], [ref]$nl)) { $nl = $usedLocs.Count; $usedLocs[$tl[1]] = $nl } }
            '{0},{1}' -f $nt, $nl
        }
        $people = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $pRows  = [System.Collections.Generic.List[string]]::new()
        $idRows = [System.Collections.Generic.List[string]]::new()
        if ($model) {
            for ($i = 0; $i -lt $model.Principals.Count; $i++) {
                $pr = $model.Principals[$i]
                if (@('user', 'service', 'computer', 'foreign') -notcontains $pr.Type) { continue }
                $k = $pr.Name.LastIndexOf('\')
                $sam = if ($k -ge 0) { $pr.Name.Substring($k + 1) } else { $pr.Name }
                $tl = $null
                if ($bySam.TryGetValue($sam, [ref]$tl)) { $pRows.Add(('[{0},{1}]' -f $i, (& $remap $tl))); [void]$people.Add($sam) }
            }
        }
        for ($i = 0; $i -lt $idList.Count; $i++) {
            $n = $idList[$i]
            $k = $n.IndexOf('\')
            if ($n -like 'S-1-*' -or $k -lt 0 -or $script:LocalAuthorityNames -contains $n.Substring(0, $k)) { continue }
            $sam = $n.Substring($k + 1)
            $tl = $null
            if ($bySam.TryGetValue($sam, [ref]$tl)) { $idRows.Add(('[{0},{1}]' -f $i, (& $remap $tl))); [void]$people.Add($sam) }
        }

        $tOut = [string[]]::new($usedTeams.Count)
        foreach ($kv in $usedTeams.GetEnumerator()) { $tOut[$kv.Value] = '[{0},{1}]' -f (ConvertTo-JsonText $teamList[$kv.Key][0]), (ConvertTo-JsonText $teamList[$kv.Key][1]) }
        $lOut = [string[]]::new($usedLocs.Count)
        foreach ($kv in $usedLocs.GetEnumerator()) { $lOut[$kv.Value] = ConvertTo-JsonText $locList[$kv.Key] }
        $teamJson = '{"src":' + (ConvertTo-JsonText ([System.IO.Path]::GetFileName($teamFile))) + ',"teams":[' + ($tOut -join ',') + '],"locs":[' + ($lOut -join ',') +
                    '],"p":[' + ($pRows -join ',') + '],"id":[' + ($idRows -join ',') + ']}'

        $n = { param([int]$c, [string]$one, [string]$many) '{0:N0} {1}' -f $c, $(if ($c -eq 1) { $one } else { $many }) }
        Write-Host ('Teams: {0} in the file ({1}, {2}); {3} found here, in {4} and {5}.' -f (& $n $bySam.Count 'person' 'people'),
            (& $n $teamList.Count 'team' 'teams'), (& $n $locList.Count 'location' 'locations'), ('{0:N0}' -f $people.Count),
            (& $n $usedTeams.Count 'team' 'teams'), (& $n $usedLocs.Count 'location' 'locations'))
        if ($dupes) { Write-Warning "$dupes account(s) are listed more than once in the team file; the first row is used." }
        if (-not $model) { Write-Host '  Without -IncludeGroupMembers only people set directly on folders are found; group members need the AD lookup.' }
        if ($people.Count -eq 0) { Write-Warning "No account of the team file was found in the scan$(if ($model) { ' or in the group members' }). Check column '$cAcc'." }
    }
}

# =============================================================================================
# Build the data block
# =============================================================================================

$setMap  = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::Ordinal)
$setJson = [System.Collections.Generic.List[string]]::new()

$sb = [System.Text.StringBuilder]::new(4MB)
[void]$sb.Append('{"meta":{')
[void]$sb.Append('"root":').Append((ConvertTo-JsonText $rootPath))
[void]$sb.Append(',"source":').Append((ConvertTo-JsonText ([System.IO.Path]::GetFileName($inputFile))))
[void]$sb.Append(',"findingsSource":').Append((ConvertTo-JsonText $(if ($findingsFile) { [System.IO.Path]::GetFileName($findingsFile) } else { '' })))
[void]$sb.Append(',"generated":').Append((ConvertTo-JsonText (Get-Date).ToString('yyyy-MM-dd HH:mm')))
[void]$sb.Append(',"entries":').Append($entryCount)
[void]$sb.Append(',"accLevels":[').Append((@($accessLevels) -join ',')).Append(']')
[void]$sb.Append(',"extOu":[').Append((@($ExternalOu | Where-Object { $_ } | ForEach-Object { ConvertTo-JsonText $_ }) -join ',')).Append(']')
[void]$sb.Append('},')

Add-JsonStringArray $sb 'ids' $idList;        [void]$sb.Append(',')
Add-JsonStringArray $sb 'rights' $rightsList; [void]$sb.Append(',')
Add-JsonStringArray $sb 'applies' $appList;   [void]$sb.Append(',')

# Folders: [name, parent, owner, flags, [explicit entries], inherited list, note]
# Inherited entry lists: thousands of folders share the same few, so each list is stored once
$folderJson = [System.Collections.Generic.List[string]]::new($folders.Count)
foreach ($f in $folders) {
    $set = -1
    if ($f.Inherited.Count) {
        $key = [string]::Join(',', $f.Inherited)
        if (-not $setMap.TryGetValue($key, [ref]$set)) {
            $set = $setJson.Count
            $setMap[$key] = $set
            $setJson.Add("[$key]")
        }
    }
    $note = -1
    if ($f.Notes.Count) {
        $noteText = $f.Notes -join ' | '
        if (-not $noteMap.TryGetValue($noteText, [ref]$note)) { $note = $noteList.Count; $noteMap[$noteText] = $note; $noteList.Add($noteText) }
    }
    $folderJson.Add(('[{0},{1},{2},{3},[{4}],{5},{6}]' -f (ConvertTo-JsonText $f.Name), $f.Parent, $f.Owner, $f.Flags,
        [string]::Join(',', $f.Explicit), $set, $note))
}

Add-JsonStringArray $sb 'notes' $noteList
[void]$sb.Append(',"aces":[').Append([string]::Join(',', $aceJson)).Append(']')
[void]$sb.Append(',"sets":[').Append([string]::Join(',', $setJson)).Append(']')
[void]$sb.Append(',"f":[').Append([string]::Join(',', $folderJson)).Append(']')
[void]$sb.Append(',"findings":[').Append([string]::Join(',', $findingsJson)).Append(']')
if ($membershipJson) { [void]$sb.Append(',"m":').Append($membershipJson) }
if ($roleJson)       { [void]$sb.Append(',"r":').Append($roleJson) }
if ($teamJson)       { [void]$sb.Append(',"t":').Append($teamJson) }
[void]$sb.Append('}')

# =============================================================================================
# Page template
# =============================================================================================

$template = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{
  color-scheme:light;
  --page:#f9f9f7; --surface:#fcfcfb; --ink:#0b0b0b; --ink2:#52514e; --muted:#898781;
  --line:#e1e0d9; --edge:#c3c2b7; --border:rgba(11,11,11,.10); --chip:#f0efec; --hover:rgba(11,11,11,.05);
  --accent:#2a78d6; --grant:#256abf; --grant-ink:#ffffff; --reach:#cde2fb; --reach-ink:#0b0b0b; --deny:#e34948;
  --sev0:#d03b3b; --sev1:#ec835a; --sev2:#fab219; --sev3:#898781;
  --sev0-ink:#ffffff; --sev1-ink:#0b0b0b; --sev2-ink:#0b0b0b; --sev3-ink:#0b0b0b;
  --nest:#6250d6; --nest-fill:#edebf7;
  --rk0:#12a5a8; --rk0-fill:#e0f4f4; --rk1:#c63fb8; --rk1-fill:#f8e7f5;
  --shadow:0 4px 16px rgba(11,11,11,.12);
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    color-scheme:dark;
    --page:#0d0d0d; --surface:#1a1a19; --ink:#f0efec; --ink2:#c3c2b7; --muted:#898781;
    --line:#2c2c2a; --edge:#55544f; --border:rgba(255,255,255,.10); --chip:#2c2c2a; --hover:rgba(255,255,255,.06);
    --accent:#3987e5; --grant:#3987e5; --grant-ink:#0b0b0b; --reach:#104281; --reach-ink:#f0efec; --deny:#e66767;
    --nest:#9085e9; --nest-fill:#322f43;
    --rk0:#1fb5b8; --rk0-fill:#173336; --rk1:#d55cc8; --rk1-fill:#3e2540;
    --shadow:0 4px 16px rgba(0,0,0,.5);
  }
}
:root[data-theme="dark"]{
  color-scheme:dark;
  --page:#0d0d0d; --surface:#1a1a19; --ink:#f0efec; --ink2:#c3c2b7; --muted:#898781;
  --line:#2c2c2a; --edge:#55544f; --border:rgba(255,255,255,.10); --chip:#2c2c2a; --hover:rgba(255,255,255,.06);
  --accent:#3987e5; --grant:#3987e5; --grant-ink:#0b0b0b; --reach:#104281; --reach-ink:#f0efec; --deny:#e66767;
  --nest:#9085e9; --nest-fill:#322f43;
  --rk0:#1fb5b8; --rk0-fill:#173336; --rk1:#d55cc8; --rk1-fill:#3e2540;
  --shadow:0 4px 16px rgba(0,0,0,.5);
}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{font:13px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--page);color:var(--ink);display:flex;flex-direction:column;overflow:hidden}
button,input{font:inherit;color:inherit}
button{cursor:pointer}
header{display:flex;align-items:center;gap:12px 20px;padding:10px 16px;background:var(--surface);border-bottom:1px solid var(--border);flex-wrap:wrap}
.ttl{min-width:0;flex:1 1 320px}
.ttl h1{font-size:16px;margin:0;font-weight:600}
.ttl .sub{color:var(--ink2);font-size:12px;overflow-wrap:anywhere}
.tools{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.field{height:30px;padding:0 10px;border:1px solid var(--border);border-radius:6px;background:var(--page);min-width:0}
.field:focus{outline:2px solid var(--accent);outline-offset:-1px}
#fq{width:220px}
#fqinfo,#mqinfo{color:var(--muted);font-size:12px;min-width:56px}
.btn{height:30px;padding:0 10px;border:1px solid var(--border);border-radius:6px;background:var(--surface)}
.btn:hover{background:var(--hover)}
.seg{display:inline-flex;align-items:center;border:1px solid var(--border);border-radius:6px;overflow:hidden;height:30px}
.seg span{padding:0 8px;color:var(--ink2);font-size:12px}
.seg button{border:0;border-left:1px solid var(--border);background:var(--surface);width:30px;height:100%}
.seg button:hover{background:var(--hover)}
.chk{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--ink2)}
.app{flex:1;display:grid;grid-template-columns:320px minmax(0,1fr) 370px;min-height:0}
aside{background:var(--surface);overflow:auto;min-height:0}
#left{border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden}
#right{border-left:1px solid var(--border);padding:16px}
#graph{position:relative;overflow:hidden;min-height:0;display:flex;flex-direction:column}
#mainview{position:relative;flex:1;min-height:0;overflow:hidden;display:flex;flex-direction:column}
.gwrap{position:relative;flex:1;min-height:0;overflow:hidden}
#canvas,#mcanvas{position:absolute;inset:0;width:100%;height:100%;display:block;cursor:grab;touch-action:none;user-select:none}
#canvas.panning,#mcanvas.panning{cursor:grabbing}
.tabs{display:flex;border-bottom:1px solid var(--border);flex:none;overflow-x:auto;scrollbar-width:none}
.tabs button{flex:1 1 auto;border:0;background:none;padding:7px 3px 5px;font-size:12px;color:var(--ink2);border-bottom:2px solid transparent;font-weight:600;white-space:nowrap;display:flex;flex-direction:column;align-items:center;line-height:1.25}
.tabs button.on{color:var(--ink);border-bottom-color:var(--ink)}
.tabs button span{font-weight:400;color:var(--muted);font-size:11px;font-variant-numeric:tabular-nums;min-height:14px}
.scroll{overflow:auto;flex:1;min-height:0}
.pane{padding:10px 10px 16px}
.pane .field{width:100%;margin-bottom:8px}
.idrow,.frow,.prow,.grow{display:block;width:100%;text-align:left;border:0;background:none;padding:7px 8px;border-radius:6px}
.idrow:hover,.frow:hover,.prow:hover,.grow:hover{background:var(--hover)}
.why{display:block;font-size:12px;color:var(--ink2);margin-top:2px}
.st{display:inline-block;font-size:11px;font-weight:600;padding:0 6px;border-radius:8px;margin-left:4px;line-height:16px;white-space:nowrap;vertical-align:1px}
.st.bad{background:var(--sev0);color:var(--sev0-ink)}
.st.empty,.st.warn{background:var(--sev2);color:var(--sev2-ink)}
.sect{display:flex;justify-content:space-between;align-items:baseline;font-size:12px;font-weight:600;color:var(--ink2);text-transform:uppercase;letter-spacing:.04em;margin:14px 8px 4px;border-bottom:1px solid var(--line);padding-bottom:3px}
.sect span{font-weight:400;text-transform:none;letter-spacing:0;color:var(--muted)}
.st.nest{background:var(--nest-fill);color:var(--ink);box-shadow:inset 0 0 0 1px var(--nest);font-weight:500}
.st.acct{background:var(--chip);color:var(--ink2);box-shadow:inset 0 0 0 1px var(--edge);font-weight:500}
.st.acct.dis{box-shadow:none;border:1px dashed var(--muted);line-height:14px;background:transparent}
.gsum{color:var(--ink2);font-size:12px;margin:0 0 6px;line-height:1.9}
.st.rk0{background:var(--rk0-fill);color:var(--ink);box-shadow:inset 0 0 0 1px var(--rk0);font-weight:500}
.st.rk1{background:var(--rk1-fill);color:var(--ink);box-shadow:inset 0 0 0 1px var(--rk1);font-weight:500}
.rrow{display:block;width:100%;text-align:left;border:0;background:none;padding:6px 8px;border-radius:6px}
.rrow:hover{background:var(--hover)}
.rrow.on{background:var(--reach);color:var(--reach-ink)}
.rrow.on .meta{color:var(--reach-ink)}
.rrow .st,.grow .st:first-child{margin-left:0}
#rolecard{border:1px solid var(--border);border-radius:8px;padding:10px;background:var(--page);margin-bottom:10px}
.rsec{margin-top:6px}
.idrow.on{background:var(--reach);color:var(--reach-ink)}
.idrow.on .meta{color:var(--reach-ink)}
.nm{display:block;overflow-wrap:anywhere}
.meta{display:block;color:var(--muted);font-size:12px;overflow-wrap:anywhere}
.tag{display:inline-block;font-size:11px;padding:0 6px;border-radius:8px;background:var(--chip);color:var(--ink2);margin-left:4px}
.more{color:var(--muted);font-size:12px;padding:8px}
#idcard{margin:10px 10px 0;border:1px solid var(--border);border-radius:8px;padding:10px;background:var(--page)}
.cardhead{display:flex;flex-wrap:wrap;gap:6px 8px;align-items:flex-start;justify-content:space-between}
.cardhead .idname{flex:1 1 150px;min-width:0}
.cardbtns{display:flex;gap:6px;flex:none}
.idname{font-weight:600;overflow-wrap:anywhere}
.ghost{border:1px solid var(--border);background:var(--surface);border-radius:6px;padding:2px 8px;font-size:12px;flex:none}
.ghost:hover{background:var(--hover)}
/* right-click menu and copy buttons */
.cmenu{position:fixed;z-index:50;min-width:210px;max-width:360px;background:var(--surface);border:1px solid var(--border);border-radius:8px;box-shadow:var(--shadow);padding:4px}
.chead{font-size:11px;color:var(--muted);padding:5px 10px 3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.citem{display:block;width:100%;text-align:left;border:0;background:none;padding:6px 10px;border-radius:5px;font-size:12.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--ink)}
.citem:hover,.citem:focus{background:var(--hover);outline:none}
.csep{height:1px;background:var(--line);margin:4px 2px}
.cbtn{border:1px solid var(--border);background:var(--surface);border-radius:5px;padding:0 6px;font-size:11px;line-height:18px;color:var(--ink2);margin-left:6px;vertical-align:1px;font-weight:400}
.cbtn:hover{background:var(--hover);color:var(--ink)}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin:10px 0 6px}
.stats div{display:flex;flex-direction:column}
.stats b{font-size:18px;font-weight:600}
.stats span{color:var(--muted);font-size:11px}
.cardnote{color:var(--muted);font-size:12px;margin:4px 0}
.plist{max-height:240px;overflow:auto;margin:0 -4px}
.pn{display:block;font-size:12px;overflow-wrap:anywhere}
.pr{display:block;font-size:11.5px;color:var(--ink2)}
.deny{color:var(--deny);font-weight:600}
.sevb{display:inline-block;font-size:11px;font-weight:600;padding:0 7px;border-radius:9px;line-height:17px}
.sevb.s0{background:var(--sev0);color:var(--sev0-ink)} .sevb.s1{background:var(--sev1);color:var(--sev1-ink)}
.sevb.s2{background:var(--sev2);color:var(--sev2-ink)} .sevb.s3{background:var(--sev3);color:var(--sev3-ink)}
.sevb.s4{background:var(--chip);color:var(--ink2)}
.fc{display:block;margin-top:2px}
#details h2{font-size:16px;margin:0;overflow-wrap:anywhere}
#details h3{font-size:13px;margin:18px 0 6px}
#details h3 .muted{font-weight:400}
.path{color:var(--ink2);font-size:12px;overflow-wrap:anywhere;margin-top:2px}
.muted{color:var(--muted)}
.warn{color:var(--deny)}
.facts{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;margin:12px 0 0}
.facts dt{color:var(--muted)} .facts dd{margin:0;overflow-wrap:anywhere}
.idb{border:0;background:none;padding:0;text-align:left;color:var(--ink);text-decoration:underline;text-decoration-color:var(--edge);text-underline-offset:2px;overflow-wrap:break-word}
.idb:hover{text-decoration-color:var(--ink)}
.hint{display:block;font-size:11px;color:var(--muted)}
.linkbtn{border:0;background:none;padding:0;color:var(--accent);text-decoration:underline;text-underline-offset:2px;font-size:12px}
.acl{width:100%;border-collapse:collapse;font-size:12.5px;table-layout:fixed}
.acl th:nth-child(1){width:38%} .acl th:nth-child(2){width:30%}
.acl th{text-align:left;color:var(--muted);font-weight:500;padding:4px 6px;border-bottom:1px solid var(--line)}
.acl td{padding:5px 6px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:break-word}
.acl tr.grp td{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.04em;padding-top:10px;border-bottom:0}
.acl tr.hl td{background:var(--reach);color:var(--reach-ink)}
.acl tr.hl .idb,.acl tr.hl .hint{color:var(--reach-ink)}
.flist{list-style:none;padding:0;margin:0}
.flist li{padding:6px 0;border-bottom:1px solid var(--line)}
.empty h2{font-size:15px;margin:0 0 6px}
.empty p,.empty li{color:var(--ink2)}
.empty ul{padding-left:18px;margin:8px 0}
/* folder graph */
.n .box{fill:var(--surface);stroke:var(--edge);stroke-width:1}
.n .lbl{font-size:12.5px;fill:var(--ink)}
.n:hover .box{stroke:var(--ink2)}
.n.err .box{stroke-dasharray:3 3;stroke:var(--deny)}
.n.fext .box{stroke:var(--sev2);stroke-width:2}
.n.fbad .box{stroke:var(--sev0);stroke-width:2}
.fb rect{stroke:var(--surface);stroke-width:2}
.fb text{font-size:10px;font-weight:700}
.fb.bad rect{fill:var(--sev0)} .fb.bad text{fill:var(--sev0-ink)}
.fb.ext rect{fill:var(--sev2)} .fb.ext text{fill:var(--sev2-ink)}
.n.sel .box{stroke:var(--ink);stroke-width:2}
.n.gx .box{fill:var(--grant);stroke:var(--grant)}
.n.gx .lbl{fill:var(--grant-ink)}
.n.gx.sel .box{stroke:var(--ink)}
.n.gd .box{stroke:var(--deny);stroke-width:2;stroke-dasharray:5 3}
.n.gr .box{fill:var(--reach);stroke:var(--accent)}
.n.gr .lbl{fill:var(--reach-ink)}
.n.dim{opacity:.38}
.pill{fill:var(--chip)}
.pilltx{font-size:11px;fill:var(--ink2);font-variant-numeric:tabular-nums}
.tg .hit{fill:transparent;cursor:pointer}
.tg .knob{fill:var(--surface);stroke:var(--edge);pointer-events:none}
.tg .glyph{stroke:var(--ink2);stroke-width:1.6;pointer-events:none}
.tg:hover .knob{stroke:var(--ink)}
.n.hasr .tg .knob{stroke:var(--accent);stroke-width:2}
.cnt{font-size:11px;fill:var(--muted)}
.n.hasr .cnt{fill:var(--accent)}
.sv rect{stroke:var(--surface);stroke-width:2}
.sv text{font-size:10px;font-weight:700}
.sv.s0 rect{fill:var(--sev0)} .sv.s0 text{fill:var(--sev0-ink)}
.sv.s1 rect{fill:var(--sev1)} .sv.s1 text{fill:var(--sev1-ink)}
.sv.s2 rect{fill:var(--sev2)} .sv.s2 text{fill:var(--sev2-ink)}
.sv.s3 rect{fill:var(--sev3)} .sv.s3 text{fill:var(--sev3-ink)}
.e{fill:none;stroke:var(--edge);stroke-width:1.5}
.e.brk{stroke-dasharray:6 4}
.e.on{stroke:var(--accent)}
/* legends sit in a strip under each graph, so they never cover a node */
.legend,.dlegend{flex:none;display:flex;flex-wrap:wrap;gap:3px 14px;align-items:center;background:var(--surface);border-top:1px solid var(--border);padding:5px 12px;font-size:11.5px;color:var(--ink2)}
.legend span,.dlegend span{display:inline-flex;align-items:center;gap:5px}
.legend .sw,.dlegend .sw{width:18px;height:11px}
.sw{width:22px;height:12px;border-radius:3px;border:1px solid var(--edge);background:var(--surface);display:inline-block}
.sw.g{background:var(--grant);border-color:var(--grant)} .sw.r{background:var(--reach);border-color:var(--accent)}
.lp{display:inline-block;min-width:18px;text-align:center;font-size:11px;border-radius:8px;background:var(--chip);padding:0 5px}
.lb{display:inline-block;width:15px;height:15px;border-radius:4px;font-size:10px;font-weight:700;text-align:center;line-height:15px}
.lb.s0{background:var(--sev0);color:var(--sev0-ink)} .lb.s1{background:var(--sev1);color:var(--sev1-ink)} .lb.s2{background:var(--sev2);color:var(--sev2-ink)} .lb.s3{background:var(--sev3);color:var(--sev3-ink)}
.tipbox{position:absolute;pointer-events:none;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:8px 10px;font-size:12px;box-shadow:var(--shadow);max-width:380px;z-index:5;color:var(--ink2)}
.tipbox .tp{color:var(--ink);font-weight:600;overflow-wrap:anywhere;margin-bottom:2px}
#toast{position:absolute;top:12px;left:50%;transform:translateX(-50%);background:var(--ink);color:var(--surface);padding:7px 12px;border-radius:8px;font-size:12px;z-index:6;max-width:80%}
/* member graph */
#drawer{flex:0 0 50%;min-height:200px;display:flex;flex-direction:column;border-top:1px solid var(--border);background:var(--surface)}
.dgrip{flex:none;height:7px;margin-top:-1px;cursor:ns-resize;background:linear-gradient(var(--edge),var(--edge)) center/36px 3px no-repeat;opacity:.55;touch-action:none}
.dgrip:hover{opacity:1;background-color:var(--hover)}
.dhead{display:flex;flex-direction:column;gap:2px;padding:2px 12px 6px;border-bottom:1px solid var(--border)}
.drow{display:flex;flex-wrap:wrap;align-items:center;gap:4px 12px}
.drow .dtitle{flex:1 1 200px;min-width:0}
.dline{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dtitle{overflow-wrap:anywhere}
.dstats{color:var(--ink2);font-size:12px}
.dtools{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.dtools .field,.dtools .btn{height:28px}
#mq{width:150px}
#mqinfo{min-width:0}
.dfocus{margin-top:3px;font-size:12px;color:var(--ink2);background:var(--reach);color:var(--reach-ink);border-radius:6px;padding:5px 8px}
.dfocus .linkbtn{color:var(--reach-ink)}
.dbody{position:relative;flex:1;min-height:0;overflow:hidden;background:var(--page)}
.dnote{position:absolute;top:10px;right:12px;max-width:min(460px,60%);background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:8px 10px;font-size:12px;color:var(--ink2);box-shadow:var(--shadow);z-index:2}
.mn .box{fill:var(--surface);stroke:var(--edge);stroke-width:1}
.mn .lbl{font-size:12.5px;fill:var(--ink)}
.mn.t1 .box{stroke:var(--ink2)}
.mn.t1 .lbl{font-weight:600}
.mn:hover .box{stroke:var(--ink)}
.mn.dis .lbl{fill:var(--muted)}
.mn.dis .box{stroke-dasharray:4 3}
.mn.t4 .box,.mn.t7 .box,.mn.cyc .box{stroke-dasharray:2 3}
.mn.nest .box{fill:var(--nest-fill);stroke:var(--nest)}
.mn.empty .box{stroke:var(--sev2);stroke-width:2}
.mn.bad .box{stroke:var(--sev0);stroke-width:2}
.mn.xext .box{stroke:var(--sev2);stroke-width:2}
.mn.ufc .box{stroke:var(--sev0);stroke-width:2}
.gb.ext rect{fill:var(--sev2)} .gb.ext text{fill:var(--sev2-ink)}
.gb rect{stroke:var(--surface);stroke-width:2}
.gb text{font-size:11px;font-weight:700}
.gb.bad rect{fill:var(--sev0)} .gb.bad text{fill:var(--sev0-ink)}
.gb.empty rect{fill:var(--sev2)} .gb.empty text{fill:var(--sev2-ink)}
.sw.nest{background:var(--nest-fill);border-color:var(--nest)}
.sw.dash{border-style:dashed} .sw.dot{border-style:dotted}
.sw.rk0{background:var(--rk0-fill);border-color:var(--rk0);border-radius:6px} .sw.rk1{background:var(--rk1-fill);border-color:var(--rk1);border-radius:6px}
.rn .box{stroke-width:1.5}
.rn.k0 .box{fill:var(--rk0-fill);stroke:var(--rk0)}
.rn.k1 .box{fill:var(--rk1-fill);stroke:var(--rk1)}
.rn .lbl{font-size:12.5px;fill:var(--ink)}
.rn:hover .box{stroke:var(--ink)}
.rn.sel .box{stroke:var(--ink);stroke-width:2.5}
.rt rect{stroke-width:1}
.rt.k0 rect{fill:var(--rk0-fill);stroke:var(--rk0)} .rt.k1 rect{fill:var(--rk1-fill);stroke:var(--rk1)}
.rt text{font-size:9.5px;font-weight:600;fill:var(--ink)}
.mn.hit .box{fill:var(--reach);stroke:var(--accent)}
.mn.hit .lbl{fill:var(--reach-ink)}
.mn.sel .box{stroke:var(--ink);stroke-width:2.5}
.moretx{font-size:12px;fill:var(--muted);font-style:italic}
/* teams (One Identity departments) and locations */
.st.loc{background:var(--surface);color:var(--ink);box-shadow:inset 0 0 0 1px var(--edge);font-weight:600;font-variant-numeric:tabular-nums;letter-spacing:.02em}
.st.loc i{font-style:normal;font-weight:400;color:var(--muted);margin-left:4px}
.tlocs{display:flex;flex-wrap:wrap;gap:4px;margin:2px 0 6px}
.tlocs .st{margin-left:0}
.locbar{display:flex;flex-wrap:wrap;gap:4px;margin:0 0 8px}
.lchip{border:1px solid var(--border);background:var(--surface);border-radius:12px;padding:1px 9px;font-size:12px;font-weight:600;font-variant-numeric:tabular-nums}
.lchip span{font-weight:400;color:var(--muted);margin-left:5px}
.lchip:hover{background:var(--hover)}
.lchip.on{background:var(--ink);color:var(--surface);border-color:var(--ink)}
.lchip.on span{color:var(--surface)}
#teamcard{border:1px solid var(--border);border-radius:8px;padding:10px;background:var(--page);margin-bottom:10px}
.trow{display:block;width:100%;text-align:left;border:0;background:none;padding:6px 8px;border-radius:6px}
.trow:hover{background:var(--hover)}
.trow.on{background:var(--reach);color:var(--reach-ink)}
.trow.on .meta,.trow.on .tier{color:var(--reach-ink)}
.trow .nm{display:flex;flex-wrap:wrap;align-items:baseline;gap:3px 4px}
.trow .nm .st{margin-left:0}
.trow .tname{font-weight:600;margin-right:2px;overflow-wrap:anywhere}
.trow .tier{margin-left:auto;font-size:12px;color:var(--ink2);white-space:nowrap;padding-left:6px}
.people{display:flex;flex-wrap:wrap;gap:3px 4px;max-height:180px;overflow:auto;margin:2px 0 4px}
.pchip{font-size:11.5px;padding:0 6px;border-radius:8px;background:var(--chip);color:var(--ink2);line-height:18px}
[hidden]{display:none !important}
@media (max-width:1100px){ .app{grid-template-columns:270px minmax(0,1fr) 320px} }
@media (max-width:860px){
  body{overflow:auto}
  .app{display:flex;flex-direction:column}
  #left{max-height:45vh;border-right:0;border-bottom:1px solid var(--border)}
  #graph{height:65vh;flex:none}
  #graph.dopen{height:95vh}
  #right{border-left:0;border-top:1px solid var(--border)}
  #fq{width:160px}
}
</style>
</head>
<body>
<header>
  <div class="ttl"><h1>__TITLE__</h1><div class="sub" id="subtitle"></div></div>
  <div class="tools">
    <input id="fq" class="field" type="search" placeholder="Find folder, then Enter" aria-label="Find folder">
    <span id="fqinfo" aria-live="polite"></span>
    <div class="seg" role="group" aria-label="Expand to level"><span>Expand</span><button data-lv="1">1</button><button data-lv="2">2</button><button data-lv="3">3</button><button data-lv="4">4</button></div>
    <button class="btn" id="fit">Fit</button>
    <label class="chk" id="findtoggle"><input type="checkbox" id="showfind" checked> Findings</label>
  </div>
</header>
<div class="app">
  <aside id="left">
    <div class="tabs" role="tablist">
      <button data-tab="ids" class="on" role="tab">Identities<span id="idcount"></span></button>
      <button data-tab="find" id="findtab" role="tab">Findings<span id="findcount"></span></button>
      <button data-tab="groups" id="grouptab" role="tab" hidden>Issues<span id="groupcount"></span></button>
      <button data-tab="roles" id="roletab" role="tab" hidden>Roles<span id="rolecount"></span></button>
      <button data-tab="teams" id="teamtab" role="tab" hidden>Teams<span id="teamcount"></span></button>
    </div>
    <div class="scroll">
      <div id="idcard" hidden></div>
      <div class="pane" id="pane-ids">
        <input id="idq" class="field" type="search" placeholder="Filter identities" aria-label="Filter identities">
        <div id="idlist"></div>
      </div>
      <div class="pane" id="pane-find" hidden><div id="findlist"></div></div>
      <div class="pane" id="pane-groups" hidden><div id="grouplist"></div></div>
      <div class="pane" id="pane-roles" hidden>
        <div id="rolecard" hidden></div>
        <input id="rq" class="field" type="search" placeholder="Filter roles or groups" aria-label="Filter roles">
        <div id="rolelist"></div>
      </div>
      <div class="pane" id="pane-teams" hidden>
        <div id="teamcard" hidden></div>
        <input id="tq" class="field" type="search" placeholder="Filter teams, paths or a location code" aria-label="Filter teams">
        <div class="locbar" id="locbar"></div>
        <div id="teamlist"></div>
      </div>
    </div>
  </aside>
  <main id="graph">
    <div id="mainview">
      <div class="gwrap" id="gwrap">
        <svg id="canvas" role="img" aria-label="Folder tree"><g id="vp"></g></svg>
        <div id="tip" class="tipbox" hidden></div>
        <div id="toast" hidden></div>
      </div>
      <div class="legend" id="legend"></div>
    </div>
    <section id="drawer" hidden aria-label="Group members">
      <div class="dgrip" id="dgrip" title="Drag to resize the member graph" role="separator" aria-orientation="horizontal"></div>
      <div class="dhead">
        <div class="drow">
          <div class="dtitle" id="dtitle"></div>
          <div class="dtools">
            <input id="mq" class="field" type="search" placeholder="Find member" aria-label="Find member">
            <span id="mqinfo" aria-live="polite"></span>
            <label class="chk"><input type="checkbox" id="missues"> Issues only</label>
            <button class="btn" id="mfit">Fit</button>
            <button class="btn" id="mclose">Close</button>
          </div>
        </div>
        <div class="dstats" id="dstats"></div>
        <div class="dstats dline" id="dmember"></div>
        <div class="dfocus" id="dfocus" hidden></div>
      </div>
      <div class="dbody" id="dbody">
        <svg id="mcanvas" role="img" aria-label="Group members"><g id="mvp"></g></svg>
        <div class="dnote" id="dnote" hidden></div>
        <div id="mtip" class="tipbox" hidden></div>
      </div>
      <div class="dlegend" id="dlegend"></div>
    </section>
  </main>
  <aside id="right"><div id="details"></div></aside>
</div>
<script type="application/json" id="perm-data">__PERMISSION_DATA__</script>
<script>
(() => {
"use strict";
const D = JSON.parse(document.getElementById("perm-data").textContent);
const F = D.f, N = F.length, IDS = D.ids, RIGHTS = D.rights, APPLIES = D.applies,
      NOTES = D.notes, ACES = D.aces, SETS = D.sets, FIND = D.findings || [], M = D.m || null;
const NODE_W = 196, NODE_H = 30, COL_W = 250, ROW_H = 40, ROLE_W = 150, ROLE_GAP = 44;
const LEVEL_LIMIT = 6000, AUTO_EXPAND_CAP = 400, MEMBER_CAP = 150, MATCH_LIMIT = 300;
const SEV_NAME = ["Critical", "High", "Medium", "Low", "Info"], SEV_LETTER = ["C", "H", "M", "L", "I"];
const TIER = ["Special", "Read", "Write", "Full control"];
const PTYPE = ["user", "group", "computer", "service account", "account from a trusted domain", "built-in", "contact", "unresolved"];
const PSHORT = ["user", "group", "computer", "service", "other domain", "built-in", "contact", "unresolved"];
const $ = (id) => document.getElementById(id);
const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ESC[c]);
const fmt = (n) => n.toLocaleString();
const trunc = (s, n) => (s.length > n ? s.slice(0, Math.max(1, n - 1)) + "\u2026" : s);
const truncLeft = (s, n) => (s.length > n ? "\u2026" + s.slice(s.length - n + 1) : s);
const plural = (n, one, many) => fmt(n) + " " + (n === 1 ? one : many);
const namePart = (s) => { const k = s.lastIndexOf("\\"); return k >= 0 ? s.slice(k + 1) : s; };
const cap1 = (s) => s.charAt(0).toUpperCase() + s.slice(1);
// let long DOMAIN\name identities wrap after the backslash instead of mid-word
const escId = (s) => esc(s).replace(/\\/g, "\\<wbr>");
const listNames = (a) => (a.length <= 4 ? a.join(", ") : a.slice(0, 3).join(", ") + ` and ${fmt(a.length - 3)} more`);

// ---------------------------------------------------------------- folder tree
const parent = new Int32Array(N), depth = new Int32Array(N), roots = [];
const kids = Array.from({ length: N }, () => []);
for (let i = 0; i < N; i++) {
  const p = F[i][1];
  if (p >= 0 && p < N && p !== i) { parent[i] = p; kids[p].push(i); } else { parent[i] = -1; roots.push(i); }
}
const order = roots.slice();
for (let q = 0; q < order.length; q++) {
  const i = order[q];
  for (const c of kids[i]) { depth[c] = depth[i] + 1; order.push(c); }
}
const desc = new Int32Array(N);
for (let q = order.length - 1; q >= 0; q--) { const i = order[q], p = parent[i]; if (p >= 0) desc[p] += desc[i] + 1; }
const perDepth = [];
for (const i of order) perDepth[depth[i]] = (perDepth[depth[i]] || 0) + 1;
const rootName = roots.length ? F[roots[0]][0] : "";
const SEP = rootName.includes("/") && !rootName.includes("\\") ? "/" : "\\";
function fullPath(i) {
  const parts = [];
  for (let c = i; c >= 0; c = parent[c]) parts.push(F[c][0]);
  parts.reverse();
  let s = parts[0];
  for (let q = 1; q < parts.length; q++) s += (s.endsWith(SEP) ? "" : SEP) + parts[q];
  return s;
}

// ---------------------------------------------------------------- findings
const worst = new Int8Array(N).fill(9), findBy = new Map();
FIND.forEach((f, k) => {
  const i = f[0];
  if (i < 0 || i >= N) return;
  if (f[1] < worst[i]) worst[i] = f[1];
  let l = findBy.get(i); if (!l) findBy.set(i, (l = [])); l.push(k);
});

// ---------------------------------------------------------------- identities on the ACLs
// "Placements": where an identity's entry is set - explicit entries anywhere, plus the entries
// the top folder inherits from above the scan.
const place = new Map();
const addPlace = (id, i, a, above) => { let l = place.get(id); if (!l) place.set(id, (l = [])); l.push([i, a, above]); };
for (let i = 0; i < N; i++) for (const a of F[i][4]) addPlace(ACES[a][0], i, a, false);
for (const r of roots) if (F[r][5] >= 0) for (const a of SETS[F[r][5]]) addPlace(ACES[a][0], r, a, true);
const owned = new Map();
for (let i = 0; i < N; i++) { const o = F[i][2]; if (o >= 0) owned.set(o, (owned.get(o) || 0) + 1); }
const idByName = new Map(IDS.map((n, i) => [n.toLowerCase(), i]));
const tierOf = (r) =>
  /FullControl|ChangePermissions|TakeOwnership/.test(r) ? 3 :
  /Modify|Write|CreateFiles|AppendData|CreateDirectories|Delete/.test(r) ? 2 :
  /Read|ListDirectory/.test(r) ? 1 : 0;

// ---------------------------------------------------------------- group membership
// P: [name, display, type, flags (1 disabled, 2 local), note, well-known SID]
const P = M ? M.p : [], PTXT = M ? M.txt : [];
const PG = new Map();   // group principal -> { m: members, total, err }
if (M) for (const g of M.g) PG.set(g[0], { m: g[1], total: g[2], err: g[3] >= 0 ? PTXT[g[3]] : "", sorted: null });
const pOf = (id) => (M && id >= 0 && id < M.idp.length ? M.idp[id] : -1);
const pIds = new Map();   // principal -> identities in the scan that resolve to it
if (M) M.idp.forEach((p, id) => { if (p >= 0) { let l = pIds.get(p); if (!l) pIds.set(p, (l = [])); l.push(id); } });
const parentsOf = new Map();
for (const [g, v] of PG) for (const c of v.m) { let l = parentsOf.get(c); if (!l) parentsOf.set(c, (l = [])); l.push(g); }
const EVERYONE = P.findIndex((r) => r[5] === "S-1-1-0"), AUTHUSERS = P.findIndex((r) => r[5] === "S-1-5-11");
const pLabel = (p) => P[p][1] || namePart(P[p][0]);
const pNote = (p) => (P[p][4] >= 0 ? PTXT[P[p][4]] : "");
const isAccount = (p) => { const t = P[p][2]; return t === 0 || t === 2 || t === 3 || t === 4; };

const statMemo = new Map();
function groupStats(g) {   // transitive
  if (statMemo.has(g)) return statMemo.get(g);
  const seenG = new Set([g]), seenP = new Set(), stack = [g], wk = [], extList = [];
  let users = 0, dis = 0, groups = 0, other = 0, notLoaded = 0, errs = 0;
  while (stack.length) {
    const v = PG.get(stack.pop());
    if (!v) continue;
    notLoaded += Math.max(0, v.total - v.m.length);
    if (v.err) errs++;
    for (const c of v.m) {
      const t = P[c][2];
      if (t === 1) { if (!seenG.has(c)) { seenG.add(c); groups++; stack.push(c); } continue; }
      if (seenP.has(c)) continue;
      seenP.add(c);
      if (t === 0) { users++; if (P[c][3] & 1) dis++; }
      else if (t === 5) wk.push(c);
      else other++;
      if (P[c][3] & 8) extList.push(c);
    }
  }
  const s = { users, dis, groups, other, notLoaded, errs, wk, ext: extList.length, extList };
  statMemo.set(g, s);
  return s;
}
function groupShort(g) {
  const v = PG.get(g);
  if (!v) return "members not read";
  if (v.err && !v.m.length) return "members not readable";
  const s = groupStats(g);
  let t = plural(s.users, "user", "users");
  if (s.wk.length) t += " + " + s.wk.map((w) => namePart(P[w][0])).join(", ");
  return t;
}
function principalHint(id) {
  const p = pOf(id), tl = TD ? idTeam(id) : null, team = tl ? " \u00b7 " + teamLabel(tl) : "";
  if (p < 0) return tl ? teamLabel(tl) : "";
  const r = P[p];
  if (r[2] === 1) return "group \u00b7 " + groupShort(p);
  if (r[2] === 0) return "user" + team;
  return PTYPE[r[2]] + team;
}
// Identities in the scan through which principal p gets access: its own, those of every group it
// is nested in, and Everyone / Authenticated Users for accounts.
function accessIds(p) {
  const seen = new Set([p]), stack = [p];
  if (isAccount(p)) for (const w of [EVERYONE, AUTHUSERS]) if (w >= 0 && !seen.has(w)) { seen.add(w); stack.push(w); }
  while (stack.length) {
    for (const g of parentsOf.get(stack.pop()) || []) if (!seen.has(g)) { seen.add(g); stack.push(g); }
  }
  const ids = new Map();
  for (const x of seen) for (const id of pIds.get(x) || []) ids.set(id, x);
  return ids;
}

// ---------------------------------------------------------------- group checks
// GH: group -> { st: 0 ok | 1 empty | 2 bad config, why: [reasons], short: pill text }
const gKids = new Map();
for (const [g, v] of PG) gKids.set(g, v.m.filter((c) => PG.has(c)));
const inCycle = new Set();
{ // circular nesting = strongly connected components of the group graph (Tarjan, iterative)
  let next = 0;
  const index = new Map(), low = new Map(), onStack = new Set(), stack = [];
  const open = (v, work) => { index.set(v, next); low.set(v, next); next++; stack.push(v); onStack.add(v); work.push({ v, i: 0 }); };
  for (const s0 of PG.keys()) {
    if (index.has(s0)) continue;
    const work = [];
    open(s0, work);
    while (work.length) {
      const fr = work[work.length - 1], ks = gKids.get(fr.v);
      if (fr.i < ks.length) {
        const w = ks[fr.i++];
        if (!index.has(w)) open(w, work);
        else if (onStack.has(w)) low.set(fr.v, Math.min(low.get(fr.v), index.get(w)));
      } else {
        work.pop();
        if (work.length) { const up = work[work.length - 1].v; low.set(up, Math.min(low.get(up), low.get(fr.v))); }
        if (low.get(fr.v) === index.get(fr.v)) {
          const comp = [];
          let w;
          do { w = stack.pop(); onStack.delete(w); comp.push(w); } while (w !== fr.v);
          if (comp.length > 1) for (const c of comp) inCycle.add(c);
        }
      }
    }
  }
}
// A group "has content" when it, or a group nested in it, has any non-group member. Unreadable or
// truncated groups count as having content, so they are never reported as empty by mistake.
const hasContent = new Set();
{
  const q = [];
  for (const [g, v] of PG) if (v.err || v.total > v.m.length || v.m.some((c) => P[c][2] !== 1 || !PG.has(c))) { hasContent.add(g); q.push(g); }
  while (q.length) for (const up of parentsOf.get(q.pop()) || []) if (!hasContent.has(up)) { hasContent.add(up); q.push(up); }
}
const GH = new Map();
for (const [g, v] of PG) {
  const why = [], shorts = [];
  const broadByDesign = !!(P[g][3] & 4);   // Domain Users, BUILTIN\Users...: being broad is their purpose
  if (inCycle.has(g)) { why.push("Circular nesting: the group ends up as a member of itself."); shorts.push("circular"); }
  if (!broadByDesign) {
    const broad = v.m.filter((c) => P[c][3] & 4);
    if (broad.length) {
      why.push(`Contains ${listNames(broad.map((c) => P[c][0]))}, so practically everyone gets this group's access.`);
      shorts.push("has " + namePart(P[broad[0]][0]));
    }
    const dis = v.m.filter((c) => P[c][2] !== 1 && P[c][3] & 1).length;
    if (dis) { why.push(plural(dis, "disabled account is still a member.", "disabled accounts are still members.")); shorts.push(fmt(dis) + " disabled"); }
  }
  const unres = v.m.filter((c) => P[c][2] === 7).length;
  if (unres) { why.push(`${plural(unres, "member does", "members do")} not resolve (deleted account or unreachable domain).`); shorts.push(fmt(unres) + " unresolved"); }
  let st = why.length ? 2 : 0;
  if (!hasContent.has(g)) {
    why.push(v.m.length ? "Empty: it only contains groups that are empty themselves." : "Empty: the group has no members.");
    shorts.push("empty");
    if (!st) st = 1;
  }
  GH.set(g, { st, why, shorts, short: shorts[0] || "" });
}
const statusChip = (p) => {
  const h = GH.get(p);
  if (!h || !h.st) return "";
  return h.st === 2 ? `<span class="st bad" title="${esc(h.why.join(" "))}">! bad config</span>` : `<span class="st empty" title="${esc(h.why.join(" "))}">\u2205 empty</span>`;
};
const nestChip = (p) => (PG.has(p) && parentsOf.has(p) ? `<span class="st nest" title="Member of ${esc(listNames(parentsOf.get(p).map((x) => P[x][0])))}">nested</span>` : "");
const extChip = (p) => {
  if (p < 0 || !PG.has(p)) return "";
  const s = groupStats(p);
  return s.ext ? `<span class="st warn" title="${esc(plural(s.ext, "external account", "external accounts") + " (all levels): " + listNames(s.extList.map((x) => P[x][0])))}">E ${fmt(s.ext)} external</span>` : "";
};
const groupChips = (p) => (p >= 0 && P[p][2] === 1 ? statusChip(p) + extChip(p) + nestChip(p) : "");
// Individual accounts: disabled, from a trusted domain, local to the file server, or no longer resolvable
function accountChips(id) {
  if (/^S-1-/.test(IDS[id])) return `<span class="st acct" title="The SID no longer resolves to an account (deleted, or from an unreachable domain).">unresolved SID</span>`;
  const p = pOf(id);
  if (p < 0 || P[p][2] === 1 || P[p][2] === 5) return "";
  let h = "";
  const f = idFlag.get(id);
  if (f && f.fc.length) h += `<span class="st bad" title="${esc(f.fc.join(" "))}">! ${f.full ? "full control" : "direct access"}</span>`;
  if (P[p][3] & 8) h += `<span class="st warn" title="External account: its AD path contains ${esc(EXT_OU.map((o) => "'" + o + "'").join(" or "))}.">E external</span>`;
  if (P[p][3] & 1) h += `<span class="st acct dis" title="The account is disabled in AD.">disabled</span>`;
  if (P[p][2] === 4) h += `<span class="st acct" title="Account from a trusted domain or forest.">other domain</span>`;
  if (P[p][3] & 2) h += `<span class="st acct" title="Account local to the file server.">local</span>`;
  if (P[p][2] === 7) h += `<span class="st acct" title="${esc(pNote(p) || "Not found in Active Directory.")}">unresolved</span>`;
  return h;
}

// ---------------------------------------------------------------- One Identity roles
// ROLES: [name, kind (0 business role / 1 system role), [identities], [principals], [other groups], other group count]
const RD = D.r || null, ROLES = RD ? RD.roles : [];
const RKIND = ["Business role", "System role"], RTAG = ["BR", "SR"];
const rolesOfId = new Map(), rolesOfP = new Map();
const pushUnique = (m, k, v) => { let l = m.get(k); if (!l) m.set(k, (l = [])); if (!l.includes(v)) l.push(v); };
ROLES.forEach((r, ri) => { for (const id of r[2]) pushUnique(rolesOfId, id, ri); for (const p of r[3]) pushUnique(rolesOfP, p, ri); });
const byRole = (a, b) => ROLES[a][1] - ROLES[b][1] || ROLES[a][0].localeCompare(ROLES[b][0]);
function rolesForP(p) {
  const s = new Set(rolesOfP.get(p) || []);
  for (const id of pIds.get(p) || []) for (const r of rolesOfId.get(id) || []) s.add(r);
  return [...s].sort(byRole);
}
function rolesForId(id) {
  const s = new Set(rolesOfId.get(id) || []), p = pOf(id);
  if (p >= 0) for (const r of rolesOfP.get(p) || []) s.add(r);
  return [...s].sort(byRole);
}
function roleChips(rs) {
  let h = "";
  for (const k of [0, 1]) {
    const names = rs.filter((r) => ROLES[r][1] === k).map((r) => ROLES[r][0]);
    if (names.length) h += `<span class="st rk${k}" title="${esc(RKIND[k] + (names.length > 1 ? "s" : "") + ": " + names.join(", "))}">${RTAG[k]}${names.length > 1 ? " " + fmt(names.length) : ""}</span>`;
  }
  return h;
}
// The groups a role assigns: AD groups when membership was read, otherwise the identities in the scan
function roleGroups(ri) {
  const r = ROLES[ri], out = [], seenP = new Set(r[3]);
  for (const p of r[3]) out.push({ p, id: -1, name: P[p][0] });
  for (const id of r[2]) { const p = pOf(id); if (p >= 0 && seenP.has(p)) continue; out.push({ p, id, name: IDS[id] }); }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}
// Identities in the scan through which the members of a role get access (incl. groups above its groups)
function roleAccess(ri) {
  const r = ROLES[ri], ids = new Map();
  for (const p of r[3]) for (const [id, via] of accessIds(p)) if (!ids.has(id)) ids.set(id, via);
  for (const id of r[2]) if (!ids.has(id)) ids.set(id, -1);
  return ids;
}
// A role is red when it assigns a bad-config group, yellow when it assigns an empty group or one with external accounts
const roleFlagMemo = new Map();
function roleFlag(ri) {
  if (roleFlagMemo.has(ri)) return roleFlagMemo.get(ri);
  const f = { st: 0, bad: [], empty: [], ext: [] };
  for (const g of roleGroups(ri)) {
    const p = g.p, gh = p >= 0 ? GH.get(p) : null;
    if (gh && gh.st === 2) f.bad.push(g.name);
    else if (gh && gh.st === 1) f.empty.push(g.name);
    if (p >= 0 && PG.has(p) && groupStats(p).ext) f.ext.push(`${g.name} (${plural(groupStats(p).ext, "external account", "external accounts")})`);
  }
  f.st = f.bad.length ? 2 : f.empty.length || f.ext.length ? 1 : 0;
  roleFlagMemo.set(ri, f);
  return f;
}
const roleFlagChip = (ri) => {
  const f = roleFlag(ri);
  let h = "";
  if (f.bad.length) h += `<span class="st bad" title="${esc("Assigns groups with a bad config: " + f.bad.join(", "))}">! bad config group</span>`;
  if (f.empty.length) h += `<span class="st warn" title="${esc("Assigns empty groups: " + f.empty.join(", "))}">\u2205 empty group</span>`;
  if (f.ext.length) h += `<span class="st warn" title="${esc("Assigns groups with external accounts: " + f.ext.join(", "))}">E externals</span>`;
  return h;
};
const roleFolderMemo = new Map();
function roleFolders(ri) {
  if (!roleFolderMemo.has(ri)) {
    const fs = new Set();
    for (const id of roleAccess(ri).keys()) for (const pl of place.get(id) || []) fs.add(pl[0]);
    roleFolderMemo.set(ri, fs.size);
  }
  return roleFolderMemo.get(ri);
}

// ---------------------------------------------------------------- flags: individual Full Control, external access
// Folder levels count from the scanned folder (level 0). Needs the AD data from -IncludeGroupMembers.
const FC_LEVELS = new Set(D.meta.accLevels || [0, 1, 2, 3]);
const EXT_OU = D.meta.extOu || [];
const levelText = (() => {   // "0\u20133" for a range, "1, 3 or 5" otherwise
  const l = [...FC_LEVELS].sort((a, b) => a - b);
  if (l.length > 2 && l[l.length - 1] - l[0] === l.length - 1) return `${l[0]}\u2013${l[l.length - 1]}`;
  return l.length > 1 ? l.slice(0, -1).join(", ") + " or " + l[l.length - 1] : String(l[0]);
})();
const isExtAcct = (p) => p >= 0 && P[p][2] !== 1 && (P[p][3] & 8) !== 0;
const anyExternal = P.some((r, i) => isExtAcct(i));
// Which external accounts an identity on the ACLs lets in: itself, its (nested) members, or all of them
function extReach(p) {
  if (p < 0 || !anyExternal) return null;
  if (isExtAcct(p)) return { short: "external", text: `${P[p][0]} is an external account`, list: [p] };
  if (p === EVERYONE || p === AUTHUSERS) return { short: "incl. externals", text: `${P[p][0]} includes every external account`, list: [] };
  if (P[p][2] === 1 && PG.has(p)) {
    const s = groupStats(p);
    if (s.ext) return { short: `${fmt(s.ext)} external`, text: `${plural(s.ext, "external account", "external accounts")} through ${P[p][0]}`, list: s.extList };
    const w = s.wk.find((x) => x === EVERYONE || x === AUTHUSERS);
    if (w !== undefined) return { short: "incl. externals", text: `${P[p][0]} contains ${P[w][0]}, so every external account`, list: [] };
  }
  return null;
}
const folderFlags = new Map();   // folder -> { bad: [reasons], ext: [reasons] } at the folders where the entry is set
const idFlag = new Map();        // identity -> { fc: [reasons], ext: [reasons] }
const extAccess = new Map();     // external account -> { ids: Set (directly on ACLs), via: Set (group principals) }
{
  const ff = (i) => { let f = folderFlags.get(i); if (!f) folderFlags.set(i, (f = { bad: [], ext: [] })); return f; };
  const fi = (id) => { let f = idFlag.get(id); if (!f) idFlag.set(id, (f = { fc: [], ext: [] })); return f; };
  if (M) for (const [id, pl] of place) {
    const p = pOf(id);
    if (p < 0) continue;
    const t = P[p][2];
    if (t === 0 || t === 2 || t === 3 || t === 4) {
      // an individual account (user, computer, service account, other domain; not a group) with its own
      // entry, any rights, on a folder at level 2 / 3
      const hits = pl.filter(([i, a, above]) => !above && !ACES[a][2] && FC_LEVELS.has(depth[i]));
      const kind = PTYPE[t] + (P[p][3] & 2 ? " on the file server" : "");
      for (const [i, a] of hits) {
        const full = tierOf(RIGHTS[ACES[a][1]]) === 3, f = ff(i);
        f.bad.push(`${IDS[id]} (${kind}, not a group) has its own ${full ? "Full Control" : RIGHTS[ACES[a][1]]} entry on this level-${depth[i]} folder.`);
        if (full) f.badFull = true;
      }
      if (hits.length) {
        const full = hits.some(([, a]) => tierOf(RIGHTS[ACES[a][1]]) === 3), f = fi(id);
        f.fc.push(`Has its own entries, not through a group, on ${plural(new Set(hits.map((x) => x[0])).size, "folder", "folders")} at level ${levelText}` +
          `${full ? ", including Full Control" : ""}. Grant access through a group${full ? " and keep Full Control for administrators" : ""}.`);
        if (full) f.full = true;
      }
    }
    const x = extReach(p);
    if (!x) continue;
    const allow = pl.filter(([, a]) => !ACES[a][2]);
    if (!allow.length) continue;
    for (const [i, a, above] of allow) ff(i).ext.push(`${cap1(x.text)} (${RIGHTS[ACES[a][1]]}${above ? ", inherited from above the scan" : ""}).`);
    fi(id).ext.push(cap1(x.text) + ".");
    fi(id).extShort = x.short;
    for (const e of x.list) {
      let r = extAccess.get(e); if (!r) extAccess.set(e, (r = { ids: new Set(), via: new Set() }));
      if (e === p) r.ids.add(id); else r.via.add(p);
    }
  }
}
const folderSt = (i) => { const f = folderFlags.get(i); return !f ? 0 : f.bad.length ? 2 : f.ext.length ? 1 : 0; };
const flagRank = (st) => (st === 2 ? 0 : st === 1 ? 1 : 2);
// red: bad config group or individual Full Control; yellow: empty group, external account or external access
function idSt(id) {
  const p = pOf(id), h = p >= 0 ? GH.get(p) : null, f = idFlag.get(id);
  if ((h && h.st === 2) || (f && f.fc.length)) return 2;
  if ((h && h.st === 1) || (f && f.ext.length) || isExtAcct(p)) return 1;
  return 0;
}
// External access not already shown by the account or group chips: Everyone / Authenticated Users,
// or groups that contain them (e.g. BUILTIN\Users)
const identityExtChip = (id) => {
  const f = idFlag.get(id), p = pOf(id);
  if (!f || !f.ext.length || p < 0 || isExtAcct(p) || (P[p][2] === 1 && PG.has(p) && groupStats(p).ext)) return "";
  return `<span class="st warn" title="${esc(f.ext.join(" "))}">E ${esc(f.extShort)}</span>`;
};

// ---------------------------------------------------------------- One Identity teams (department table)
// TD: { src, teams: [[name, full path]], locs: [code], p: [[principal, team, loc]], id: [[identity, team, loc]] }
const TD = D.t || null, TEAMS = TD ? TD.teams : [], LOCS = TD ? TD.locs : [];
const teamOfP = new Map(), teamOfId = new Map();
if (TD) { for (const r of TD.p) teamOfP.set(r[0], [r[1], r[2]]); for (const r of TD.id) teamOfId.set(r[0], [r[1], r[2]]); }
// A person is a principal (>= 0) when group membership was read, otherwise -(identity + 1)
function personTeam(k) {
  if (k < 0) return teamOfId.get(-k - 1) || null;
  const t = teamOfP.get(k);
  if (t) return t;
  for (const id of pIds.get(k) || []) if (teamOfId.has(id)) return teamOfId.get(id);
  return null;
}
const personName = (k) => (k >= 0 ? P[k][0] : IDS[-k - 1]);
const idTeam = (id) => { const p = pOf(id); return p >= 0 ? personTeam(p) : teamOfId.get(id) || null; };
const isPersonId = (id) => { const p = pOf(id); return p >= 0 ? isAccount(p) : teamOfId.has(id); };
const teamName = (t) => TEAMS[t][0];
const teamPathOnly = (t) => (TEAMS[t][1] && TEAMS[t][1] !== TEAMS[t][0] ? TEAMS[t][1] : "");
const locName = (l) => (l >= 0 ? LOCS[l] : "");
const teamLabel = (tl) => teamName(tl[0]) + (tl[1] >= 0 ? " · " + LOCS[tl[1]] : "");
// Access everyone has (Everyone, Authenticated Users, Domain Users, BUILTIN\Users and groups that contain
// them) is not counted per team: it would put every team on every folder.
const BROADP = new Set();
{
  const q = [];
  P.forEach((r, p) => { if (p === EVERYONE || p === AUTHUSERS || r[3] & 4) { BROADP.add(p); q.push(p); } });
  while (q.length) for (const up of parentsOf.get(q.pop()) || []) if (!BROADP.has(up)) { BROADP.add(up); q.push(up); }
}
const BROAD_RX = /^(everyone|tout le monde|jeder|todos|nt authority\\authenticated users|builtin\\users|[^\\]+\\domain users|[^\\]+\\domain computers)$/i;
const isBroadId = (id) => { const p = pOf(id); return p >= 0 ? BROADP.has(p) : BROAD_RX.test(IDS[id]); };
const acctMemo = new Map();
function accountsOf(g) {   // every account in the group, all levels
  let r = acctMemo.get(g);
  if (r) return r;
  const out = new Set(), seen = new Set([g]), stack = [g];
  while (stack.length) {
    const v = PG.get(stack.pop());
    if (v) for (const c of v.m) {
      if (P[c][2] === 1) { if (!seen.has(c)) { seen.add(c); stack.push(c); } }
      else if (isAccount(c)) out.add(c);
    }
  }
  r = [...out];
  acctMemo.set(g, r);
  return r;
}
const viaMemo = new Map();
function peopleVia(id) {   // the people an entry for this identity gives access to
  let r = viaMemo.get(id);
  if (r) return r;
  const p = pOf(id);
  if (isBroadId(id)) r = { broad: true, people: [] };
  else if (p >= 0) r = { broad: false, people: isAccount(p) ? [p] : PG.has(p) ? accountsOf(p) : [] };
  else r = { broad: false, people: teamOfId.has(id) ? [-id - 1] : [] };
  viaMemo.set(id, r);
  return r;
}
// Teams with access to a folder: Allow entries, explicit and inherited
const ftMemo = new Map();
function folderTeams(i) {
  let r = ftMemo.get(i);
  if (r) return r;
  const f = F[i], aces = f[4].concat(f[5] >= 0 ? SETS[f[5]] : []);
  const byT = new Map(), broad = new Map(), none = new Set();
  let deny = 0;
  for (const a of aces) {
    const ac = ACES[a];
    if (ac[2]) { deny++; continue; }
    const id = ac[0], tier = tierOf(RIGHTS[ac[1]]), pv = peopleVia(id);
    if (pv.broad) { broad.set(id, Math.max(broad.has(id) ? broad.get(id) : -1, tier)); continue; }
    for (const k of pv.people) {
      const tl = personTeam(k);
      if (!tl) { none.add(k); continue; }
      let e = byT.get(tl[0]);
      if (!e) byT.set(tl[0], (e = { t: tl[0], people: new Map(), pt: new Map(), tier: -1, via: new Set() }));
      e.people.set(k, tl[1]);
      if (!(e.pt.get(k) >= tier)) e.pt.set(k, tier);
      if (tier > e.tier) e.tier = tier;
      e.via.add(id);
    }
  }
  const teams = [...byT.values()], locs = new Map();
  for (const e of teams) {
    e.n = e.people.size; e.locs = new Map();
    for (const l of e.people.values()) if (l >= 0) { e.locs.set(l, (e.locs.get(l) || 0) + 1); locs.set(l, (locs.get(l) || 0) + 1); }
  }
  teams.sort((a, b) => b.tier - a.tier || b.n - a.n || teamName(a.t).localeCompare(teamName(b.t)));
  r = { teams, broad: [...broad].sort((a, b) => b[1] - a[1]), none: [...none], deny, locs: [...locs].sort((a, b) => b[1] - a[1] || LOCS[a[0]].localeCompare(LOCS[b[0]])) };
  ftMemo.set(i, r);
  return r;
}
// Per team and per location: the identities on the ACLs that give its people access
let TIX = null;
function teamIndex() {
  if (TIX) return TIX;
  const known = new Map(), tIds = new Map(), lIds = new Map(), tPeople = new Map(), tLocAcc = new Map(), tLocKnown = new Map(), lTeams = new Map();
  const addSet = (m, k, v) => { let s = m.get(k); if (!s) m.set(k, (s = new Set())); s.add(v); };
  const addCount = (m, k, l) => { let x = m.get(k); if (!x) m.set(k, (x = new Map())); x.set(l, (x.get(l) || 0) + 1); };
  const addId = (m, k, id, person) => { let x = m.get(k); if (!x) m.set(k, (x = new Map())); let s = x.get(id); if (!s) x.set(id, (s = new Set())); s.add(person); };
  for (const [p, tl] of teamOfP) addSet(known, tl[0], p);
  for (const [id, tl] of teamOfId) { const p = pOf(id); if (p < 0 || !teamOfP.has(p)) addSet(known, tl[0], p >= 0 ? p : -id - 1); }
  for (const [t, ks] of known) for (const k of ks) { const l = personTeam(k)[1]; if (l >= 0) { addCount(tLocKnown, t, l); addSet(lTeams, l, t); } }
  const aclIds = new Set();
  for (const a of ACES) if (!a[2]) aclIds.add(a[0]);
  for (const id of aclIds) {
    const pv = peopleVia(id);
    if (pv.broad) continue;
    for (const k of pv.people) {
      const tl = personTeam(k);
      if (!tl) continue;
      addId(tIds, tl[0], id, k);
      if (tl[1] >= 0) addId(lIds, tl[1], id, k);
      const s = tPeople.get(tl[0]);
      if (!s || !s.has(k)) { addSet(tPeople, tl[0], k); if (tl[1] >= 0) addCount(tLocAcc, tl[0], tl[1]); }
    }
  }
  const tFolders = new Map();
  for (const [t, ids] of tIds) { const fs = new Set(); for (const id of ids.keys()) for (const pl of place.get(id) || []) fs.add(pl[0]); tFolders.set(t, fs); }
  // red: a person of the team has own entries on level 0-3 folders; yellow: a person is an external account
  const tFlag = new Map();
  for (const [t, ps] of tPeople) {
    const f = { st: 0, fc: [], ext: [] };
    for (const k of ps) {
      if ((k >= 0 ? pIds.get(k) || [] : [-k - 1]).some((id) => { const x = idFlag.get(id); return x && x.fc.length; })) f.fc.push(personName(k));
      if (k >= 0 && isExtAcct(k)) f.ext.push(personName(k));
    }
    f.st = f.fc.length ? 2 : f.ext.length ? 1 : 0;
    tFlag.set(t, f);
  }
  TIX = { known, tIds, lIds, tPeople, tLocAcc, tLocKnown, lTeams, tFolders, tFlag };
  return TIX;
}
const tigMemo = new Map();
function teamsInGroup(g) {   // the teams of a group's accounts, all levels
  let r = tigMemo.get(g);
  if (r) return r;
  const m = new Map();
  let none = 0;
  for (const k of accountsOf(g)) {
    const tl = personTeam(k);
    if (!tl) { none++; continue; }
    let e = m.get(tl[0]);
    if (!e) m.set(tl[0], (e = { t: tl[0], n: 0, locs: new Set() }));
    e.n++;
    if (tl[1] >= 0) e.locs.add(tl[1]);
  }
  r = { teams: [...m.values()].sort((a, b) => b.n - a.n || teamName(a.t).localeCompare(teamName(b.t))), none };
  tigMemo.set(g, r);
  return r;
}
const locChip = (l, n, what) => `<span class="st loc" title="${esc(LOCS[l] + (n !== undefined ? ": " + plural(n, "person", "people") + (what || "") : ""))}">${esc(LOCS[l])}${n !== undefined ? `<i>${fmt(n)}</i>` : ""}</span>`;
const sortLocs = (m) => [...m].sort((a, b) => b[1] - a[1] || LOCS[a[0]].localeCompare(LOCS[b[0]]));
function teamFlagChips(t) {
  const f = teamIndex().tFlag.get(t);
  if (!f) return "";
  let h = "";
  if (f.fc.length) h += `<span class="st bad" title="${esc(`With their own entries on level ${levelText} folders (not through a group): ` + listNames(f.fc))}">! direct access</span>`;
  if (f.ext.length) h += `<span class="st warn" title="${esc("External accounts: " + listNames(f.ext))}">E external</span>`;
  return h;
}
function teamFolderList(t) {
  const fs = teamIndex().tFolders.get(t);
  return fs ? [...fs].sort((a, b) => depth[a] - depth[b] || a - b) : [];
}
function teamsTsv(i) {
  const ft = folderTeams(i), rows = [["Team", "Full path", "Location", "People", "Access", "Through"].join("\t")];
  for (const e of ft.teams) rows.push([teamName(e.t), TEAMS[e.t][1], [...e.locs.keys()].map(locName).join(", "), e.n, TIER[e.tier], [...e.via].map((id) => IDS[id]).join(", ")].join("\t"));
  return rows.join("\n");
}
function peopleTsv(i) {
  const ft = folderTeams(i), rows = [["Account", "Name", "Team", "Location", "Access"].join("\t")];
  for (const e of ft.teams) {
    const ks = [...e.people.keys()].sort((a, b) => personName(a).localeCompare(personName(b)));
    for (const k of ks) rows.push([personName(k), k >= 0 ? P[k][1] : "", teamName(e.t), locName(e.people.get(k)), TIER[e.pt.get(k)]].join("\t"));
  }
  return rows.join("\n");
}

const idRows = [];
for (let id = 0; id < IDS.length; id++) {
  const pl = place.get(id) || [];
  const fs = new Set(pl.map((p) => p[0]));
  let t = -1, deny = false;
  for (const p of pl) { const a = ACES[p[1]]; if (a[2]) deny = true; else t = Math.max(t, tierOf(RIGHTS[a[1]])); }
  const own = owned.get(id) || 0;
  if (!fs.size && !own) continue;
  idRows.push({ id, n: fs.size, t, deny, own, name: IDS[id], lc: IDS[id].toLowerCase() });
}
// red first, then yellow, then the rest by number of folders
idRows.sort((a, b) => flagRank(idSt(a.id)) - flagRank(idSt(b.id)) || b.n - a.n || b.own - a.own || a.name.localeCompare(b.name));

// ---------------------------------------------------------------- state
const expanded = new Uint8Array(N);
const X = new Float32Array(N), Y = new Float32Array(N);
let vis = [], selF = -1, selId = -1, focusP = -1, selRole = -1, focusRole = -1, ownAny = 0, activeTab = "ids", showFind = FIND.length > 0;
let HL = null, G = null, GL = null, GV = null, SUB = null, hlName = "";   // folder highlight
const mainV = { tx: 40, ty: 40, k: 1 };
const svg = $("canvas"), vp = $("vp"), mainEl = $("gwrap"), graph = $("graph"), tip = $("tip");

// HL: identity -> principal it comes through (-1 for a direct identity selection)
function setHighlight(map, name, selfP, alwaysVia = false) {
  if (!map) { HL = G = GL = GV = SUB = null; hlName = ""; return; }
  HL = map; hlName = name;
  G = new Int8Array(N); GL = new Map(); GV = new Map();
  const setHit = SETS.map((s) => s.some((a) => HL.has(ACES[a][0])));
  for (let i = 0; i < N; i++) { const s = F[i][5]; if (s >= 0 && setHit[s]) G[i] = 1; }
  for (const [id, via] of HL) {
    for (const [i, a, above] of place.get(id) || []) {
      const ac = ACES[a], deny = ac[2] === 1;
      G[i] = Math.max(G[i], deny ? 3 : 2);
      const t = (deny ? "Deny " : "") + RIGHTS[ac[1]];
      GL.set(i, GL.has(i) ? GL.get(i) + ", " + t : t);
      let v = (alwaysVia || (via >= 0 && via !== selfP) ? t + " via " + IDS[id] : t) + (above ? " (from above the scan)" : "");
      GV.set(i, GV.has(i) ? GV.get(i) + "; " + v : v);
    }
  }
  SUB = new Int32Array(N);
  for (let q = order.length - 1; q >= 0; q--) {
    const i = order[q];
    if (G[i]) SUB[i]++;
    const p = parent[i]; if (p >= 0) SUB[p] += SUB[i];
  }
}
function highlightFolders() {
  const fs = new Set();
  if (HL) for (const id of HL.keys()) for (const pl of place.get(id) || []) fs.add(pl[0]);
  return [...fs].sort((a, b) => depth[a] - depth[b] || a - b);
}
function revealHighlight() {
  const list = highlightFolders();
  let changed = false;
  for (const i of list.slice(0, AUTO_EXPAND_CAP)) for (let c = parent[i]; c >= 0; c = parent[c]) if (!expanded[c]) { expanded[c] = 1; changed = true; }
  if (changed) relayout();
  if (list.length > AUTO_EXPAND_CAP) notify(`Opened the paths to the first ${AUTO_EXPAND_CAP} of ${fmt(list.length)} folders.`);
  if (list.length) centerOn(list[0]);
}

// ---------------------------------------------------------------- shared pan / zoom
function attachPanZoom(el, view, onChange, onTap, onHover, onLeave) {
  let drag = null;
  el.addEventListener("pointerdown", (e) => {
    if (e.button !== 0) return;
    drag = { x: e.clientX, y: e.clientY, tx: view.tx, ty: view.ty, moved: false, target: e.target };
    el.setPointerCapture(e.pointerId);
  });
  el.addEventListener("pointermove", (e) => {
    if (drag) {
      const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
      if (!drag.moved && Math.abs(dx) + Math.abs(dy) > 4) { drag.moved = true; el.classList.add("panning"); onLeave(); }
      if (drag.moved) { view.tx = drag.tx + dx; view.ty = drag.ty + dy; onChange(); }
      return;
    }
    onHover(e);
  });
  el.addEventListener("pointerleave", onLeave);
  el.addEventListener("pointerup", (e) => {
    if (!drag) return;
    const d = drag; drag = null;
    el.classList.remove("panning");
    try { el.releasePointerCapture(e.pointerId); } catch (_) { /* ignore */ }
    if (!d.moved && d.target instanceof Element) onTap(d.target);
  });
  el.addEventListener("pointercancel", () => { drag = null; el.classList.remove("panning"); });
  el.addEventListener("wheel", (e) => {
    e.preventDefault();
    const r = el.getBoundingClientRect(), mx = e.clientX - r.left, my = e.clientY - r.top;
    const nk = Math.min(2.5, Math.max(0.06, view.k * Math.exp(-e.deltaY * 0.0015)));
    view.tx = mx - (mx - view.tx) * (nk / view.k); view.ty = my - (my - view.ty) * (nk / view.k); view.k = nk;
    onChange();
  }, { passive: false });
}
function placeTip(t, host, e) {
  const r = host.getBoundingClientRect();
  let x = e.clientX - r.left + 14, y = e.clientY - r.top + 14;
  if (x + t.offsetWidth > r.width - 8) x = e.clientX - r.left - t.offsetWidth - 14;
  if (y + t.offsetHeight > r.height - 8) y = e.clientY - r.top - t.offsetHeight - 14;
  t.style.left = Math.max(8, x) + "px"; t.style.top = Math.max(8, y) + "px";
}
function pillSvg(text, right) {
  const pw = Math.round(12 + text.length * 6.3);
  return { w: pw, svg: `<rect class="pill" x="${right - pw}" y="7" width="${pw}" height="16" rx="8"/><text class="pilltx" x="${right - pw / 2}" y="19" text-anchor="middle">${esc(text)}</text>` };
}
function toggleSvg(attr, idx, open) {
  const cy = NODE_H / 2;
  return `<g class="tg" ${attr}="${idx}"><circle class="hit" cx="${NODE_W}" cy="${cy}" r="14"/><circle class="knob" cx="${NODE_W}" cy="${cy}" r="8"/><path class="glyph" d="M${NODE_W - 4} ${cy}h8${open ? "" : `M${NODE_W} ${cy - 4}v8`}"/></g>`;
}

// ---------------------------------------------------------------- folder graph
function relayout() {
  vis = [];
  let row = 0;
  const placeNode = (i) => {
    X[i] = depth[i] * COL_W;
    const ch = kids[i];
    if (expanded[i] && ch.length) {
      for (const c of ch) placeNode(c);
      Y[i] = (Y[ch[0]] + Y[ch[ch.length - 1]]) / 2;
    } else {
      Y[i] = row++ * ROW_H;
    }
    vis.push(i);
  };
  for (const r of roots) { placeNode(r); row++; }
}

let raf = 0;
const schedule = () => { if (!raf) raf = requestAnimationFrame(() => { raf = 0; draw(); }); };
function applyT() { vp.setAttribute("transform", `translate(${mainV.tx} ${mainV.ty}) scale(${mainV.k})`); schedule(); }

function nodeSvg(i, lod) {
  const f = F[i];
  let c = "n", pill = f[4].length ? String(f[4].length) : "";
  if (i === selF) c += " sel";
  if (f[3] & 6) c += " err";
  const fst = folderSt(i);
  if (fst === 2) c += " fbad"; else if (fst === 1) c += " fext";
  if (G) {
    const g = G[i];
    if (g === 3) c += " gx gd"; else if (g === 2) c += " gx"; else if (g === 1) c += " gr";
    else if (!expanded[i] && SUB[i] > 0) c += " hasr"; else c += " dim";
    if (g >= 2) pill = trunc(GL.get(i) || "", 18);
  }
  let s = `<g class="${c}" data-i="${i}" transform="translate(${X[i]} ${Y[i]})"><rect class="box" width="${NODE_W}" height="${NODE_H}" rx="6"/>`;
  if (!lod) {
    const pl = pill ? pillSvg(pill, NODE_W - 12) : null;
    const room = pl ? Math.max(6, Math.floor((NODE_W - pl.w - 26) / 7)) : 26;
    s += `<text class="lbl" x="10" y="19">${esc(trunc(f[0], room))}</text>`;
    if (pl) s += pl.svg;
    if (showFind && worst[i] <= 3) s += `<g class="sv s${worst[i]}"><rect x="-8" y="-8" width="17" height="17" rx="4"/><text x="0.5" y="4.5" text-anchor="middle">${SEV_LETTER[worst[i]]}</text></g>`;
    const ff = folderFlags.get(i);
    if (ff) {   // red ! = individual Full Control, yellow E = external access
      let x = NODE_W - 26;
      if (ff.bad.length) { s += `<g class="fb bad"><rect x="${x}" y="-8" width="17" height="17" rx="4"/><text x="${x + 8.5}" y="4.5" text-anchor="middle">!</text></g>`; x -= 20; }
      if (ff.ext.length) s += `<g class="fb ext"><rect x="${x}" y="-8" width="17" height="17" rx="4"/><text x="${x + 8.5}" y="4.5" text-anchor="middle">E</text></g>`;
    }
  }
  if (kids[i].length) {
    s += toggleSvg("data-t", i, expanded[i]);
    if (!expanded[i] && !lod) {
      let t = plural(desc[i], "subfolder", "subfolders");
      if (G) { const hidden = SUB[i] - (G[i] ? 1 : 0); if (hidden) t += ` \u00b7 ${fmt(hidden)} with access`; }
      s += `<text class="cnt" x="${NODE_W + 14}" y="${NODE_H / 2 + 4}">${t}</text>`;
    }
  }
  return s + "</g>";
}

function draw() {
  const w = mainEl.clientWidth, h = mainEl.clientHeight, k = mainV.k;
  const x0 = -mainV.tx / k - 40, x1 = (w - mainV.tx) / k + 40, y0 = -mainV.ty / k - 40, y1 = (h - mainV.ty) / k + 40;
  const lod = k < 0.42;
  const edges = [], nodes = [];
  for (const i of vis) {
    const p = parent[i];
    if (p >= 0) {
      const ax = X[p] + NODE_W, ay = Y[p] + NODE_H / 2, bx = X[i], by = Y[i] + NODE_H / 2;
      if (bx >= x0 && ax <= x1 && Math.max(ay, by) >= y0 && Math.min(ay, by) <= y1) {
        const mx = (ax + bx) / 2;
        let c = "e";
        if (F[i][3] & 1) c += " brk";
        if (G && G[i]) c += " on";
        edges.push(`<path class="${c}" d="M${ax} ${ay}C${mx} ${ay} ${mx} ${by} ${bx} ${by}"/>`);
      }
    }
    if (X[i] > x1 || X[i] + NODE_W + 160 < x0 || Y[i] > y1 || Y[i] + NODE_H < y0) continue;
    nodes.push(nodeSvg(i, lod));
  }
  vp.innerHTML = edges.join("") + nodes.join("");
}

function centerOn(i) {
  mainV.tx = mainEl.clientWidth / 2 - (X[i] + NODE_W / 2) * mainV.k;
  mainV.ty = mainEl.clientHeight / 2 - (Y[i] + NODE_H / 2) * mainV.k;
  applyT();
}
function home() {
  if (!roots.length) return;
  mainV.k = 1; mainV.tx = 40;
  mainV.ty = mainEl.clientHeight / 2 - (Y[roots[0]] + NODE_H / 2);
  applyT();
}
function fitView(view, el, items, minK = 0.06) {
  if (!items.length) return;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const [x, y] of items) {
    minX = Math.min(minX, x); maxX = Math.max(maxX, x + NODE_W + 120);
    minY = Math.min(minY, y); maxY = Math.max(maxY, y + NODE_H);
  }
  const w = el.clientWidth, h = el.clientHeight;
  view.k = Math.max(minK, Math.min(1.2, (w - 60) / (maxX - minX), (h - 60) / (maxY - minY)));
  // centre what fits; when it doesn't (zoom floor reached), start from the top-left
  const cw = (maxX - minX) * view.k, ch = (maxY - minY) * view.k;
  view.tx = cw <= w ? (w - cw) / 2 - minX * view.k : 30 - minX * view.k;
  view.ty = ch <= h ? (h - ch) / 2 - minY * view.k : 20 - minY * view.k;
}
function fit() { fitView(mainV, mainEl, vis.map((i) => [X[i], Y[i]])); applyT(); }
// After opening a node, pan left just enough that the new column is on screen
function showColumn(view, el, xRight) {
  const over = xRight * view.k + view.tx - (el.clientWidth - 16);
  if (over > 0) view.tx -= over;
}
function toggle(i) {
  const sx = X[i] * mainV.k + mainV.tx, sy = Y[i] * mainV.k + mainV.ty;   // keep the clicked folder in place
  expanded[i] ^= 1;
  relayout();
  mainV.tx = sx - X[i] * mainV.k; mainV.ty = sy - Y[i] * mainV.k;
  if (expanded[i]) showColumn(mainV, mainEl, X[i] + COL_W + NODE_W + 24);
  applyT();
}
function reveal(i) {
  let changed = false;
  for (let c = parent[i]; c >= 0; c = parent[c]) if (!expanded[c]) { expanded[c] = 1; changed = true; }
  if (changed) relayout();
}
function levelCount(L) { let t = 0; for (let d = 0; d <= L && d < perDepth.length; d++) t += perDepth[d]; return t; }
function expandLevel(L) {
  const total = levelCount(L);
  if (total > LEVEL_LIMIT) { notify(`Level ${L} would show ${fmt(total)} folders. Expand branches one by one instead.`); return; }
  for (let i = 0; i < N; i++) expanded[i] = depth[i] < L ? 1 : 0;
  if (selF >= 0) reveal(selF);
  relayout();
  home();
}
let toastTimer = 0;
function notify(msg) {
  const t = $("toast");
  t.textContent = msg; t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, 4500);
}

// ---------------------------------------------------------------- member graph
const drawerEl = $("drawer"), msvg = $("mcanvas"), mvp = $("mvp"), mtip = $("mtip"), dbody = $("dbody");
const mv = { tx: 30, ty: 20, k: 1 };
let mRootP = -1, mRoot = null, mQuery = "", mIssuesOnly = false, mVis = [], mRoles = [], mMatches = 0;

function sortedMembers(g) {
  const v = PG.get(g);
  if (!v) return [];
  if (!v.sorted) v.sorted = v.m.slice().sort((a, b) => (P[a][2] === 1 ? 0 : 1) - (P[b][2] === 1 ? 0 : 1) || pLabel(a).localeCompare(pLabel(b)));
  return v.sorted;
}
const onPath = (n, p) => { for (let c = n; c; c = c.par) if (c.p === p) return true; return false; };
const mkNode = (p, par) => ({ p, par, kids: null, open: false, cyc: !!par && onPath(par, p), match: false, x: 0, y: 0 });
const expandable = (n) => n.p >= 0 && !n.cyc && PG.has(n.p) && PG.get(n.p).m.length > 0;
function ensureKids(n) {
  if (n.kids || !expandable(n)) { if (!n.kids) n.kids = []; return; }
  const v = PG.get(n.p), list = sortedMembers(n.p);
  n.kids = list.slice(0, MEMBER_CAP).map((c) => mkNode(c, n));
  const hidden = Math.max(0, list.length - MEMBER_CAP), notRead = Math.max(0, v.total - v.m.length);
  if (hidden || notRead) n.kids.push({ p: -1, par: n, hidden, notRead, x: 0, y: 0 });
}
function buildMemberTree() {
  mRoot = null; mMatches = 0;
  if (mRootP < 0) return;
  const q = mQuery.trim().toLowerCase();
  if (!q && !mIssuesOnly) { mRoot = mkNode(mRootP, null); ensureKids(mRoot); mRoot.open = true; return; }
  // Only the paths from the group to matching members (name match and/or empty / bad config groups)
  const matchP = (p) => (!q || P[p][0].toLowerCase().includes(q) || P[p][1].toLowerCase().includes(q)) &&
                        (!mIssuesOnly || (GH.has(p) && GH.get(p).st > 0));
  const state = new Map();
  const hasMatch = (g) => {
    if (state.has(g)) return state.get(g) === true;
    state.set(g, 0);
    let r = false;
    const v = PG.get(g);
    if (v) for (const c of v.m) if (matchP(c) || (PG.has(c) && hasMatch(c))) { r = true; break; }
    state.set(g, r);
    return r;
  };
  const visit = (p, par) => {
    const n = mkNode(p, par);
    n.match = !!par && matchP(p);
    if (n.match) mMatches++;
    if (!n.cyc && PG.has(p) && hasMatch(p) && mMatches < MATCH_LIMIT) {
      n.kids = [];
      for (const c of sortedMembers(p)) {
        if (mMatches >= MATCH_LIMIT) break;
        if (matchP(c) || (PG.has(c) && hasMatch(c))) n.kids.push(visit(c, n));
      }
      n.open = n.kids.length > 0;
    }
    return n;
  };
  mRoot = visit(mRootP, null);
}
function mLayout() {
  mVis = [];
  let row = 0;
  const placeN = (n, d) => {
    n.x = d * COL_W;
    if (n.open && n.kids && n.kids.length) {
      const first = row;
      for (const c of n.kids) placeN(c, d + 1);
      n.y = first * ROW_H;   // parents line up with their first member, so long lists read top-down
    } else {
      n.y = row++ * ROW_H;
    }
    mVis.push(n);
  };
  if (mRoot) placeN(mRoot, 0);
  // One Identity roles that assign the group, to the left of it
  mRoles = mRootP >= 0 ? rolesForP(mRootP).map((r, i) => ({ r, x: -(ROLE_W + ROLE_GAP), y: i * ROW_H })) : [];
}
const mItems = () => mVis.map((n) => [n.x, n.y]).concat(mRoles.map((rn) => [rn.x, rn.y]));
function roleNodeSvg(rn, i, lod) {
  const r = ROLES[rn.r];
  let s = `<g class="rn k${r[1]}${rn.r === focusRole ? " sel" : ""}" data-mr="${i}" transform="translate(${rn.x} ${rn.y})"><rect class="box" width="${ROLE_W}" height="${NODE_H}" rx="15"/>`;
  if (!lod) {
    s += `<text class="lbl" x="14" y="19">${esc(trunc(r[0], Math.floor((ROLE_W - 24) / 7)))}</text>`;
    s += `<g class="rt k${r[1]}"><rect x="${ROLE_W - 32}" y="-7" width="20" height="13" rx="6"/><text x="${ROLE_W - 22}" y="3" text-anchor="middle">${RTAG[r[1]]}</text></g>`;
  }
  return s + "</g>";
}
let mraf = 0;
const mSchedule = () => { if (!mraf) mraf = requestAnimationFrame(() => { mraf = 0; mDraw(); }); };
function mApply() { mvp.setAttribute("transform", `translate(${mv.tx} ${mv.ty}) scale(${mv.k})`); mSchedule(); }
function memberPill(n) {
  const r = P[n.p], t = r[2];
  if (n.cyc) return "circular";
  if (t === 1) {
    const v = PG.get(n.p);
    if (!v) return "not read";
    if (v.err && !v.m.length) return "not readable";
    const h = GH.get(n.p);
    if (h && h.st) return h.short;
    return plural(groupStats(n.p).users, "user", "users");
  }
  if (r[3] & 8) return "external";
  if (r[3] & 1) return "disabled";
  if (t === 0) { if (r[3] & 2) return "local"; const tl = TD ? personTeam(n.p) : null; return tl && tl[1] >= 0 ? LOCS[tl[1]] : ""; }
  return PSHORT[t];
}
const userFc = (p) => (pIds.get(p) || []).some((id) => { const f = idFlag.get(id); return f && f.fc.length; });
function mNodeSvg(n, idx, lod) {
  if (n.p < 0) {
    const parts = [];
    if (n.hidden) parts.push(`+ ${fmt(n.hidden)} more \u00b7 use Find member`);
    if (n.notRead) parts.push(`${fmt(n.notRead)} not read (limit ${fmt(M.cap)})`);
    return `<g class="mn more" transform="translate(${n.x} ${n.y})"><text class="moretx" x="4" y="19">${esc(parts.join(" \u00b7 "))}</text></g>`;
  }
  const r = P[n.p], h = r[2] === 1 ? GH.get(n.p) : null;
  let c = "mn t" + r[2];
  if (r[2] === 1 && parentsOf.has(n.p)) c += " nest";
  if (h && h.st === 2) c += " bad"; else if (h && h.st === 1) c += " empty";
  const ext = isExtAcct(n.p), fc = r[2] === 0 && userFc(n.p), gext = r[2] === 1 && PG.has(n.p) && groupStats(n.p).ext > 0;
  if (fc) c += " ufc"; else if (ext) c += " xext";
  if (r[3] & 1) c += " dis";
  if (n.cyc) c += " cyc";
  if (n.match) c += " hit";
  if (n.p === focusP) c += " sel";
  let s = `<g class="${c}" data-m="${idx}" transform="translate(${n.x} ${n.y})"><rect class="box" width="${NODE_W}" height="${NODE_H}" rx="6"/>`;
  if (!lod) {
    const pill = memberPill(n), pl = pill ? pillSvg(pill, NODE_W - 12) : null;
    const room = pl ? Math.max(6, Math.floor((NODE_W - pl.w - 26) / 7)) : 26;
    s += `<text class="lbl" x="10" y="19">${esc(trunc(pLabel(n.p), room))}</text>`;
    if (pl) s += pl.svg;
    let bx = -8;
    const badge = (cls, ch) => { s += `<g class="gb ${cls}"><rect x="${bx}" y="-8" width="17" height="17" rx="4"/><text x="${bx + 8.5}" y="4.5" text-anchor="middle">${ch}</text></g>`; bx += 20; };
    if (h && h.st) badge(h.st === 2 ? "bad" : "empty", h.st === 2 ? "!" : "\u2205");
    if (fc) badge("bad", "!");
    if (ext || gext) badge("ext", "E");
    if (n.par && r[2] === 1 && ROLES.length) {   // assigned by One Identity roles
      const rs = rolesForP(n.p);
      let x = NODE_W - 10;
      for (const k of [1, 0]) {
        if (!rs.some((ri) => ROLES[ri][1] === k)) continue;
        x -= 22;
        s += `<g class="rt k${k}"><rect x="${x}" y="-7" width="20" height="13" rx="6"/><text x="${x + 10}" y="3" text-anchor="middle">${RTAG[k]}</text></g>`;
        x -= 3;
      }
    }
  }
  if (expandable(n)) {
    s += toggleSvg("data-mt", idx, n.open);
    if (!n.open && !lod) s += `<text class="cnt" x="${NODE_W + 14}" y="${NODE_H / 2 + 4}">${plural(PG.get(n.p).m.length, "member", "members")}</text>`;
  }
  return s + "</g>";
}
function mDraw() {
  if (drawerEl.hidden || !mRoot) { mvp.innerHTML = ""; return; }
  const w = msvg.clientWidth, h = msvg.clientHeight, k = mv.k;
  const x0 = -mv.tx / k - 40, x1 = (w - mv.tx) / k + 40, y0 = -mv.ty / k - 40, y1 = (h - mv.ty) / k + 40;
  const lod = k < 0.42, hot = new Set();
  if (focusP >= 0) for (const n of mVis) if (n.p === focusP) for (let c = n; c; c = c.par) hot.add(c);
  const edges = [], nodes = [];
  mRoles.forEach((rn, i) => {
    const ax = rn.x + ROLE_W, ay = rn.y + NODE_H / 2, bx = mRoot.x, by = mRoot.y + NODE_H / 2, mx = (ax + bx) / 2;
    edges.push(`<path class="e${rn.r === focusRole ? " on" : ""}" d="M${ax} ${ay}C${mx} ${ay} ${mx} ${by} ${bx} ${by}"/>`);
    nodes.push(roleNodeSvg(rn, i, lod));
  });
  mVis.forEach((n, idx) => {
    const p = n.par;
    if (p) {
      const ax = p.x + NODE_W, ay = p.y + NODE_H / 2, bx = n.x, by = n.y + NODE_H / 2;
      if (bx >= x0 && ax <= x1 && Math.max(ay, by) >= y0 && Math.min(ay, by) <= y1) {
        const mx = (ax + bx) / 2;
        edges.push(`<path class="e${hot.has(n) ? " on" : ""}" d="M${ax} ${ay}C${mx} ${ay} ${mx} ${by} ${bx} ${by}"/>`);
      }
    }
    if (n.x > x1 || n.x + NODE_W + 160 < x0 || n.y > y1 || n.y + NODE_H < y0) return;
    nodes.push(mNodeSvg(n, idx, lod));
  });
  mvp.innerHTML = edges.join("") + nodes.join("");
}
function mHome() {
  // start at the top-left; zoom out a little (not below 75 %) when the tree is taller than the view
  let bottom = NODE_H;
  for (const n of mVis) if (n.y + NODE_H > bottom) bottom = n.y + NODE_H;
  if (mRoles.length) bottom = Math.max(bottom, mRoles[mRoles.length - 1].y + NODE_H);
  const h = msvg.clientHeight - 24;
  mv.k = bottom > h && h > 0 ? Math.max(0.75, h / bottom) : 1;
  mv.tx = 24 + (mRoles.length ? (ROLE_W + ROLE_GAP) * mv.k : 0);
  mv.ty = 14;
  mApply();
}
function mToggle(n) {
  if (!expandable(n)) return;
  const sx = n.x * mv.k + mv.tx, sy = n.y * mv.k + mv.ty;
  if (!n.open) ensureKids(n);
  n.open = !n.open;
  mLayout();
  mv.tx = sx - n.x * mv.k; mv.ty = sy - n.y * mv.k;
  if (n.open) showColumn(mv, msvg, n.x + COL_W + NODE_W + 24);
  mApply();
}
function openDrawer(p) {
  mRootP = p; mQuery = ""; $("mq").value = ""; $("mqinfo").textContent = "";
  $("dlegend").innerHTML = (ROLES.length ? `<span><span class="sw rk0"></span>business role</span><span><span class="sw rk1"></span>system role</span>` : "") +
    `<span><span class="sw nest"></span>nested group</span><span><span class="lb s0">!</span>bad config</span><span><span class="lb s2">\u2205</span>empty group</span><span><span class="lb s2">E</span>external account / has externals</span><span><span class="sw dash"></span>disabled account</span><span><span class="sw dot"></span>other domain, unresolved or repeated</span>`;
  drawerEl.hidden = false; graph.classList.add("dopen");
  buildMemberTree(); mLayout(); renderDrawerHead();
  requestAnimationFrame(() => { mHome(); schedule(); });
}
function closeDrawer() {
  if (drawerEl.hidden) return;
  drawerEl.hidden = true; graph.classList.remove("dopen");
  mRoot = null; mVis = []; mtip.hidden = true;
  schedule();
}
function renderDrawerHead() {
  if (mRootP < 0) return;
  const r = P[mRootP];
  $("dtitle").innerHTML = (r[2] === 1 ? "Members of " : "") + `<b>${esc(r[0])}</b><button class="cbtn" data-copy="${esc(r[0])}" data-what="name" title="Copy the name (right-click for more)">Copy</button>`;
  let st = cap1(PTYPE[r[2]]);
  if (r[2] === 1) {
    const s = groupStats(mRootP), parts = [plural(s.users, "user", "users") + (s.dis ? ` (${fmt(s.dis)} disabled)` : "")];
    if (s.groups) parts.push(plural(s.groups, "nested group", "nested groups"));
    if (s.other) parts.push(plural(s.other, "other account", "other accounts"));
    if (s.wk.length) parts.push("includes " + s.wk.map((w) => P[w][0]).join(", "));
    if (s.notLoaded) parts.push(`${fmt(s.notLoaded)} not read (limit ${fmt(M.cap)} per group)`);
    if (s.errs) parts.push(plural(s.errs, "group", "groups") + " not readable");
    st = parts.map(esc).join(" \u00b7 ");
    if (TD) {
      const tg = teamsInGroup(mRootP);
      if (tg.teams.length) st += ` \u00b7 <span title="${esc(tg.teams.map((e) => `${teamName(e.t)}: ${plural(e.n, "person", "people")}`).join("\n"))}">${esc(plural(tg.teams.length, "team", "teams") + ": " + listNames(tg.teams.map((e) => teamName(e.t))))}</span>`;
    }
    // checks for this group and every group nested below it
    const below = new Set([mRootP]), q = [mRootP];
    while (q.length) for (const c of gKids.get(q.pop()) || []) if (!below.has(c)) { below.add(c); q.push(c); }
    let bad = 0, empty = 0;
    for (const g of below) { const h = GH.get(g); if (h && h.st === 2) bad++; else if (h && h.st === 1) empty++; }
    if (bad) st += ` \u00b7 <span class="st bad">! ${fmt(bad)}</span> bad config`;
    if (empty) st += ` \u00b7 <span class="st empty">\u2205 ${fmt(empty)}</span> empty`;
  } else st = esc(st);
  $("dstats").innerHTML = st;
  const ups = parentsOf.get(mRootP), hh = GH.get(mRootP);
  const rr = rolesForP(mRootP), full = [];
  let mm = "";
  if (hh && hh.st) { mm += statusChip(mRootP) + " " + esc(hh.shorts.join(", ")); full.push(hh.why.join(" ")); }
  if (ups) { mm += (mm ? " \u00b7 " : "") + `<span class="st nest">nested</span> in ${esc(listNames(ups.map((x) => P[x][0])))}`; full.push("Member of " + ups.map((x) => P[x][0]).join(", ") + "."); }
  if (rr.length) { mm += (mm ? " \u00b7 " : "") + "assigned by " + roleChips(rr) + " " + esc(listNames(rr.map((x) => ROLES[x][0]))); full.push("Assigned by " + rr.map((x) => ROLES[x][0]).join(", ") + "."); }
  $("dmember").innerHTML = mm; $("dmember").hidden = !mm; $("dmember").title = full.join("\n");
  const v = PG.get(mRootP), note = (v && v.err ? "Members could not be read: " + v.err : "") || pNote(mRootP);
  $("dnote").textContent = note; $("dnote").hidden = !note;
  const fl = $("dfocus");
  if (focusRole >= 0 && HL) {
    const ro = ROLES[focusRole];
    fl.innerHTML = `Folder graph shows the access given by ${RKIND[ro[1]].toLowerCase()} <b>${esc(ro[0])}</b> through ${plural(roleGroups(focusRole).length, "group", "groups")} \u00b7 ${plural(highlightFolders().length, "folder", "folders")} with entries \u00b7 <button class="linkbtn" id="mreset">Back to ${esc(namePart(r[0]))}</button>`;
    fl.hidden = false;
  } else if (focusP >= 0 && focusP !== mRootP && HL) {
    const via = [...new Set(HL.values())].filter((x) => x >= 0 && x !== focusP).map((x) => P[x][0]);
    let t = `Folder graph shows the access of <b>${esc(P[focusP][0])}</b>`;
    t += via.length ? ` through ${esc(listNames(via))}` : "";
    t += ` \u00b7 ${plural(highlightFolders().length, "folder", "folders")} with entries`;
    fl.innerHTML = t + ` \u00b7 <button class="linkbtn" id="mreset">Back to ${esc(namePart(r[0]))}</button>`;
    fl.hidden = false;
  } else if (selId < 0 && HL) {
    // a group that is only nested, not on any ACL: show what its members get through the groups above it
    const via = [...new Set(HL.values())].filter((x) => x >= 0 && x !== mRootP).map((x) => P[x][0]);
    fl.innerHTML = `<b>${esc(r[0])}</b> has no permission entry of its own in this scan. ` +
      (via.length ? `Folder graph shows the access its members get through ${esc(listNames(via))}.` : "Its members get no access through other groups either.");
    fl.hidden = false;
  } else fl.hidden = true;
}
function showMTip(n, e) {
  if (n.p < 0) { mtip.hidden = true; return; }
  const r = P[n.p];
  let h = `<div class="tp">${esc(r[0])}</div>`;
  if (r[1]) h += `<div>${esc(r[1])}</div>`;
  h += `<div>${esc(cap1(PTYPE[r[2]]))}${r[3] & 2 ? " on the file server" : ""}${r[3] & 1 ? " \u00b7 disabled" : ""}</div>`;
  if (r[3] & 8) h += `<div>E External account (AD path contains ${esc(EXT_OU.map((o) => "'" + o + "'").join(" or "))})</div>`;
  if (TD && isAccount(n.p)) { const tl = personTeam(n.p); if (tl) h += `<div>Team: ${esc(teamLabel(tl))}</div>` + (teamPathOnly(tl[0]) ? `<div class="muted">${esc(TEAMS[tl[0]][1])}</div>` : ""); }
  if (TD && r[2] === 1 && PG.has(n.p)) { const tg = teamsInGroup(n.p); if (tg.teams.length) h += `<div>Teams: ${esc(listNames(tg.teams.map((e) => `${teamName(e.t)} (${fmt(e.n)})`)))}</div>`; }
  for (const id of pIds.get(n.p) || []) { const f = idFlag.get(id); if (f && f.fc.length) h += `<div class="warn">! ${esc(f.fc.join(" "))}</div>`; }
  if (r[2] === 1 && PG.has(n.p)) { const s = groupStats(n.p); if (s.ext) h += `<div>E ${esc(plural(s.ext, "external account", "external accounts"))} (all levels): ${esc(listNames(s.extList.map((x) => P[x][0])))}</div>`; }
  if (r[2] === 1 && PG.has(n.p)) {
    const s = groupStats(n.p);
    h += `<div>${plural(s.users, "user", "users")}${s.groups ? ", " + plural(s.groups, "nested group", "nested groups") : ""} (all levels)</div>`;
  }
  if (r[2] === 1) {
    const gh = GH.get(n.p), ups = parentsOf.get(n.p);
    if (ups) h += `<div>Member of ${esc(listNames(ups.map((x) => P[x][0])))}</div>`;
    const rs = rolesForP(n.p);
    for (const k of [0, 1]) {
      const names = rs.filter((ri) => ROLES[ri][1] === k).map((ri) => ROLES[ri][0]);
      if (names.length) h += `<div>${RKIND[k]}${names.length > 1 ? "s" : ""}: ${esc(listNames(names))}</div>`;
    }
    if (gh && gh.st) h += `<div class="${gh.st === 2 ? "warn" : ""}">${gh.st === 2 ? "! Bad config: " : "\u2205 "}${esc(gh.why.join(" "))}</div>`;
  }
  if (n.cyc) h += `<div>Circular nesting: this group already appears above.</div>`;
  const v = PG.get(n.p), note = (v && v.err) || pNote(n.p);
  if (note) h += `<div class="muted">${esc(note)}</div>`;
  const chain = [];
  for (let c = n; c; c = c.par) chain.push(pLabel(c.p));
  if (chain.length > 2) h += `<div class="muted">${esc(chain.reverse().join(" \u203a "))}</div>`;
  if (n.par) h += `<div class="muted">Click to show its access in the folder graph</div>`;
  mtip.innerHTML = h; mtip.hidden = false;
  placeTip(mtip, dbody, e);
}

function showRTip(rn, e) {
  const r = ROLES[rn.r], gs = roleGroups(rn.r);
  let h = `<div class="tp">${esc(r[0])}</div><div>${RKIND[r[1]]} in One Identity</div>`;
  h += `<div>Assigns ${esc(listNames(gs.map((g) => g.name)))}</div>`;
  if (r[5]) h += `<div class="muted">and ${plural(r[5], "other group", "other groups")} not used on these folders</div>`;
  h += `<div class="muted">Click to show the access this role gives</div>`;
  mtip.innerHTML = h; mtip.hidden = false;
  placeTip(mtip, dbody, e);
}

// ---------------------------------------------------------------- selection
function selectFolder(i, center) {
  selF = i;
  reveal(i);
  if (center) centerOn(i); else schedule();
  renderDetails();
}

function selectIdentity(id, toggleOff = true) {
  selRole = -1; focusRole = -1; clearTeams();
  if (id < 0 || (toggleOff && id === selId)) {
    selId = -1; focusP = -1;
    setHighlight(null);
    closeDrawer();
  } else {
    selId = id; focusP = pOf(id);
    setHighlight(new Map([[id, -1]]), IDS[id], -1);
    ownAny = 0; for (let i = 0; i < N; i++) if (G[i]) ownAny++;
    if (focusP >= 0 && (PG.has(focusP) || P[focusP][2] === 5)) openDrawer(focusP); else closeDrawer();
    revealHighlight();   // after the drawer, so the folder graph centres in the space that is left
  }
  renderIdCard(); renderIdList(); renderRoleList(); renderDetails(); renderLegend(); schedule();
}

// A One Identity role picked in the Roles tab: the access its members get through its groups
function selectRole(ri) {
  selId = -1; focusRole = -1; focusP = -1; clearTeams();
  if (ri < 0 || ri === selRole) { selRole = -1; setHighlight(null); }
  else {
    selRole = ri;
    closeDrawer();
    setHighlight(roleAccess(ri), ROLES[ri][0], -2, true);
    revealHighlight();
  }
  if (activeTab !== "roles") switchTab("roles");
  renderRoleList(); renderIdCard(); renderIdList(); renderDetails(); renderLegend(); schedule();
}
// A role node clicked in the member graph
function focusRoleNode(ri) {
  focusRole = ri; focusP = -1;
  setHighlight(roleAccess(ri), ROLES[ri][0], -2, true);
  revealHighlight();
  renderDrawerHead(); renderDetails(); renderLegend(); schedule(); mSchedule();
}

// Show the access of one member (through all its groups) without leaving the selected group
const rootMap = () => (selId >= 0 ? new Map([[selId, -1]]) : accessIds(mRootP));
function focusMember(p) {
  if (mRootP < 0) return;
  focusRole = -1;
  if (p < 0 || p === mRootP) { focusP = mRootP; setHighlight(rootMap(), selId >= 0 ? IDS[selId] : P[mRootP][0], selId >= 0 ? -1 : mRootP); }
  else { focusP = p; setHighlight(accessIds(p), P[p][0], p); }
  revealHighlight();
  renderDrawerHead(); renderDetails(); renderLegend(); schedule(); mSchedule();
}

// Open any group, also one that is only nested and has no permission entry of its own
function openGroup(p) {
  const ids = pIds.get(p);
  if (ids && ids.length) { selectIdentity(ids[0], false); return; }
  selId = -1; focusP = p; selRole = -1; focusRole = -1; clearTeams();
  setHighlight(accessIds(p), P[p][0], p);   // before the drawer, whose header describes it
  openDrawer(p);
  revealHighlight();
  renderIdCard(); renderIdList(); renderRoleList(); renderDetails(); renderLegend(); renderDrawerHead(); schedule();
}
function closeGroupView() {
  closeDrawer();
  if (selId < 0) { focusP = -1; setHighlight(null); renderDetails(); renderLegend(); schedule(); }
}

// ---------------------------------------------------------------- side panels
const idBtn = (id) => `<button class="idb" data-id="${id}" title="Highlight this identity">${escId(IDS[id])}</button>`;

function renderIdCard() {
  const el = $("idcard");
  if (selId < 0) { el.hidden = true; el.innerHTML = ""; return; }
  const pl = (place.get(selId) || []).slice().sort((a, b) => depth[a[0]] - depth[b[0]] || a[0] - b[0]);
  const fs = new Set(pl.map((p) => p[0]));
  const p = pOf(selId), hasMembers = p >= 0 && (PG.has(p) || P[p][2] === 5);
  let h = `<div class="cardhead"><div class="idname">${esc(IDS[selId])}</div><div class="cardbtns"><button class="ghost" data-copy="${esc(IDS[selId])}" data-what="name" title="Copy the name (right-click for more)">Copy</button>`;
  if (hasMembers) h += `<button class="ghost" id="idmembers">Members</button>`;
  h += `<button class="ghost" id="idclear" title="Clear (Esc)">Clear</button></div></div>`;
  const hint = principalHint(selId), achips = accountChips(selId);
  if (hint || achips) h += `<div class="cardnote">${esc(hint)}${achips}</div>`;
  else if (!M && !/^S-1-/.test(IDS[selId])) h += `<div class="cardnote">Build the page with -IncludeGroupMembers to see group members.</div>`;
  const rs = rolesForId(selId);
  if (rs.length) h += `<div class="rsec"><div class="cardnote">Assigned in One Identity by</div>` +
    rs.map((ri) => `<button class="rrow" data-r="${ri}"><span class="st rk${ROLES[ri][1]}">${RTAG[ROLES[ri][1]]}</span> ${esc(ROLES[ri][0])}</button>`).join("") + `</div>`;
  if (TD) {
    const tl = idTeam(selId);
    if (tl && (p < 0 || isAccount(p))) {
      h += `<div class="rsec"><div class="cardnote">Team in One Identity</div><button class="trow" data-team="${tl[0]}"><span class="nm"><span class="tname">${esc(teamName(tl[0]))}</span>${tl[1] >= 0 ? locChip(tl[1]) : ""}</span>` +
        (teamPathOnly(tl[0]) ? `<span class="meta">${esc(truncLeft(teamPathOnly(tl[0]), 60))}</span>` : "") + `</button></div>`;
    } else if (p >= 0 && PG.has(p)) {
      const tg = teamsInGroup(p);
      if (tg.teams.length) h += `<div class="rsec"><div class="cardnote">Teams in this group (all levels)</div>` +
        tg.teams.slice(0, 8).map((e) => `<button class="trow" data-team="${e.t}"><span class="nm"><span class="tname">${esc(teamName(e.t))}</span>${[...e.locs].map((l) => locChip(l)).join("")}<span class="tier">${plural(e.n, "person", "people")}</span></span></button>`).join("") +
        (tg.teams.length > 8 ? `<div class="more">and ${plural(tg.teams.length - 8, "more team", "more teams")}</div>` : "") +
        (tg.none ? `<div class="cardnote">${plural(tg.none, "account is", "accounts are")} not in the team file.</div>` : "") + `</div>`;
    }
  }
  h += `<div class="stats"><div><b>${fmt(fs.size)}</b><span>granted explicitly</span></div><div><b>${fmt(ownAny)}</b><span>with an entry, incl. inherited</span></div><div><b>${fmt(owned.get(selId) || 0)}</b><span>owned</span></div></div>`;
  if (pl.length) {
    h += `<div class="plist">` + pl.slice(0, 300).map(([i, a, above]) => {
      const ac = ACES[a];
      return `<button class="prow" data-f="${i}"><span class="pn">${esc(truncLeft(fullPath(i), 64))}</span><span class="pr">${ac[2] ? '<span class="deny">Deny</span> ' : ""}${esc(RIGHTS[ac[1]])} \u00b7 ${esc(APPLIES[ac[3]])}${above ? " \u00b7 inherited from above the scan" : ""}</span></button>`;
    }).join("") + `</div>`;
    if (pl.length > 300) h += `<div class="more">Showing 300 of ${fmt(pl.length)} entries.</div>`;
  }
  el.innerHTML = h; el.hidden = activeTab !== "ids";
}

function renderIdList() {
  const q = $("idq").value.trim().toLowerCase();
  const rows = q ? idRows.filter((r) => r.lc.includes(q) || rolesForId(r.id).some((ri) => ROLES[ri][0].toLowerCase().includes(q)) ||
    (TD && idTeam(r.id) && teamName(idTeam(r.id)[0]).toLowerCase().includes(q))) : idRows;
  let h = rows.slice(0, 400).map((r) => {
    const meta = [], hint = principalHint(r.id);
    if (hint) meta.push(hint);
    if (r.n) meta.push(plural(r.n, "folder", "folders") + (r.t >= 0 ? " \u00b7 " + TIER[r.t] : ""));
    if (r.deny) meta.push("has Deny");
    if (r.own) meta.push("owns " + fmt(r.own));
    return `<button class="idrow${r.id === selId ? " on" : ""}" data-id="${r.id}"><span class="nm">${esc(r.name)}${accountChips(r.id)}${groupChips(pOf(r.id))}${identityExtChip(r.id)}${roleChips(rolesForId(r.id))}</span><span class="meta">${esc(meta.join(" \u00b7 "))}</span></button>`;
  }).join("");
  if (rows.length > 400) h += `<div class="more">Showing 400 of ${fmt(rows.length)}. Type to filter.</div>`;
  if (!rows.length) h += `<div class="more">No identity matches.${M ? " To find a person, open a group and use Find member." : ""}</div>`;
  $("idlist").innerHTML = h;
}

function renderFindList() {
  if (!FIND.length) return;
  const idx = FIND.map((_, k) => k).sort((a, b) => FIND[a][1] - FIND[b][1] || (FIND[a][2] < FIND[b][2] ? -1 : FIND[a][2] > FIND[b][2] ? 1 : 0));
  let h = idx.slice(0, 600).map((k) => {
    const f = FIND[k];
    return `<button class="frow" data-f="${f[0]}" data-idn="${esc(f[4])}"><span class="sevb s${f[1]}">${SEV_NAME[f[1]]}</span><span class="fc">${esc(f[2])} \u00b7 ${esc(f[3])}</span><span class="meta">${esc(truncLeft(fullPath(f[0]), 60))}${f[4] ? " \u00b7 " + esc(f[4]) : ""}</span></button>`;
  }).join("");
  if (FIND.length > 600) h += `<div class="more">Showing 600 of ${fmt(FIND.length)}. The full list is in the findings CSV.</div>`;
  $("findlist").innerHTML = h;
}

// Issues tab: flagged folders, accounts and groups; red first, then yellow
function renderGroupList() {
  if (!M) {
    $("grouplist").innerHTML = `<div class="cardnote" style="margin:8px">The account and group checks (individual accounts on level ${esc(levelText)} folders, external accounts, empty and misconfigured groups) need the page to be built with <b>-IncludeGroupMembers</b>: only Active Directory can tell a user account from a group.</div>`;
    $("groupcount").textContent = "";
    return;
  }
  const chipsFor = (st, label) => (st === 2 ? `<span class="st bad">! ${label}</span>` : `<span class="st warn">${label}</span>`);
  let h = "", total = 0;
  // Folders
  const fRows = [...folderFlags.entries()].map(([i, f]) => ({ i, f, st: f.bad.length ? 2 : 1 }))
    .sort((a, b) => b.st - a.st || depth[a.i] - depth[b.i] || fullPath(a.i).localeCompare(fullPath(b.i)));
  total += fRows.length;
  h += `<div class="sect">Folders<span>${fmt(fRows.filter((r) => r.st === 2).length)} red \u00b7 ${fmt(fRows.filter((r) => r.st === 1).length)} yellow</span></div>`;
  h += fRows.slice(0, 300).map(({ i, f }) => {
    let c = "";
    if (f.bad.length) c += `<span class="st bad">! ${f.badFull ? "full control" : "direct access"}</span>`;
    if (f.ext.length) c += `<span class="st warn">E external access</span>`;
    const why = f.bad.concat(f.ext);
    return `<button class="prow" data-f="${i}"><span class="pn">${esc(truncLeft(fullPath(i), 58))}${c}</span><span class="why">${why.slice(0, 2).map(esc).join("<br>")}${why.length > 2 ? `<br>and ${fmt(why.length - 2)} more` : ""}</span></button>`;
  }).join("") || `<div class="more">No folder flagged.</div>`;
  // Accounts
  const aRows = [];
  for (const [id, f] of idFlag) if (f.fc.length) aRows.push({ st: 2, id, name: IDS[id], why: f.fc.join(" "), label: f.full ? "full control" : "direct access" });
  for (const [x, r] of extAccess) {
    const via = [...r.via].map((g) => P[g][0]);
    aRows.push({ st: 1, x, r, name: P[x][0], why: (r.ids.size ? "Has its own entries" : "") + (r.ids.size && via.length ? "; also " : "") + (via.length ? `through ${listNames(via)}` : "") + "." });
  }
  aRows.sort((a, b) => b.st - a.st || a.name.localeCompare(b.name));
  total += aRows.length;
  h += `<div class="sect">Accounts<span>${fmt(aRows.filter((r) => r.st === 2).length)} red \u00b7 ${fmt(aRows.filter((r) => r.st === 1).length)} yellow</span></div>`;
  h += aRows.slice(0, 300).map((a) => {
    const target = a.id !== undefined ? `data-id="${a.id}"` : a.r.via.size ? `data-xa="${a.x}" data-xg="${[...a.r.via][0]}"` : `data-id="${[...a.r.ids][0]}"`;
    const p = a.id !== undefined ? pOf(a.id) : a.x;
    return `<button class="grow" ${target}><span class="nm">${esc(a.name)}${chipsFor(a.st, a.st === 2 ? a.label : "E external")}${p >= 0 && P[p][3] & 1 ? `<span class="st acct dis">disabled</span>` : ""}</span><span class="why">${esc(a.why)}</span>${p >= 0 && P[p][1] ? `<span class="meta">${esc(P[p][1])}</span>` : ""}</button>`;
  }).join("") || `<div class="more">No account flagged.${anyExternal ? "" : ` No account was found in an OU matching ${esc(EXT_OU.map((o) => "'" + o + "'").join(" or "))}.`}</div>`;
  // Groups
  const gRows = [];
  for (const [g, gh] of GH) {
    const s = groupStats(g), st = gh.st === 2 ? 2 : gh.st === 1 || s.ext ? 1 : 0;
    if (st) gRows.push({ g, gh, s, st });
  }
  gRows.sort((a, b) => b.st - a.st || P[a.g][0].localeCompare(P[b.g][0]));
  total += gRows.length;
  const nested = [...PG.keys()].filter((g) => parentsOf.has(g)).length;
  h += `<div class="sect">Groups<span>${fmt(gRows.filter((r) => r.st === 2).length)} red \u00b7 ${fmt(gRows.filter((r) => r.st === 1).length)} yellow \u00b7 ${fmt(nested)} nested</span></div>`;
  h += gRows.slice(0, 300).map(({ g, gh, s }) => {
    const fs = new Set();
    for (const id of pIds.get(g) || []) for (const pl of place.get(id) || []) fs.add(pl[0]);
    const meta = [fs.size ? "on " + plural(fs.size, "folder", "folders") : "no entry of its own in this scan"];
    const ups = parentsOf.get(g);
    if (ups) meta.push("member of " + listNames(ups.map((x) => P[x][0])));
    const why = gh.why.slice();
    if (s.ext) why.push(`${plural(s.ext, "external account", "external accounts")} (all levels): ${listNames(s.extList.map((x) => P[x][0]))}.`);
    return `<button class="grow" data-g="${g}"><span class="nm">${esc(P[g][0])}${groupChips(g)}${roleChips(rolesForP(g))}</span><span class="why">${why.map(esc).join("<br>")}</span><span class="meta">${esc(meta.join(" \u00b7 "))}</span></button>`;
  }).join("") || `<div class="more">No group flagged.</div>`;
  h += `<div class="cardnote" style="margin:12px 8px 0">Red: individual accounts (not groups) with their own entry on level ${esc(levelText)} folders (the scanned folder is level 0); groups with circular nesting, Everyone / Authenticated Users / Domain Users / Domain Computers inside, disabled or unresolved members. Yellow: external accounts (AD path contains ${esc(EXT_OU.map((o) => "'" + o + "'").join(" or "))}) and where they have access; empty groups.</div>`;
  $("grouplist").innerHTML = h;
  $("groupcount").textContent = fmt(total);
}

function renderRoleList() {
  if (!ROLES.length) return;
  const card = $("rolecard");
  if (selRole >= 0) {
    const r = ROLES[selRole], gs = roleGroups(selRole);
    let h = `<div class="cardhead"><div class="idname"><span class="st rk${r[1]}">${RTAG[r[1]]}</span> ${esc(r[0])}</div><div class="cardbtns"><button class="ghost" data-copy="${esc(r[0])}" data-what="${RKIND[r[1]].toLowerCase()} name" title="Copy the role name (right-click for more)">Copy</button><button class="ghost" id="rclear" title="Clear (Esc)">Clear</button></div></div>`;
    h += `<div class="cardnote">${RKIND[r[1]]} in One Identity. The folder graph shows the access its members get through these groups.</div>`;
    h += `<div class="stats"><div><b>${fmt(gs.length)}</b><span>groups used here</span></div><div><b>${fmt(roleFolders(selRole))}</b><span>folders with entries</span></div><div><b>${fmt(r[5])}</b><span>other groups</span></div></div>`;
    h += gs.map((g) => `<button class="grow" ${g.p >= 0 ? `data-g="${g.p}"` : `data-id="${g.id}"`}><span class="nm">${esc(g.name)}${groupChips(g.p)}</span></button>`).join("");
    if (r[4].length) h += `<div class="cardnote">Also assigns, not used on these folders: ${esc(r[4].join(", "))}${r[5] > r[4].length ? ` and ${fmt(r[5] - r[4].length)} more` : ""}</div>`;
    card.innerHTML = h; card.hidden = false;
  } else { card.hidden = true; card.innerHTML = ""; }
  const q = $("rq").value.trim().toLowerCase();
  let idx = ROLES.map((_, i) => i);
  if (q) idx = idx.filter((i) => ROLES[i][0].toLowerCase().includes(q) || roleGroups(i).some((g) => g.name.toLowerCase().includes(q)));
  idx.sort((a, b) => flagRank(roleFlag(a).st) - flagRank(roleFlag(b).st) || byRole(a, b));   // red, yellow, rest
  let h = idx.slice(0, 400).map((i) => {
    const r = ROLES[i], gs = roleGroups(i);
    return `<button class="rrow${i === selRole ? " on" : ""}" data-r="${i}"><span class="nm"><span class="st rk${r[1]}">${RTAG[r[1]]}</span> ${esc(r[0])}${roleFlagChip(i)}</span><span class="meta">${esc(listNames(gs.map((g) => namePart(g.name))))} \u00b7 ${plural(roleFolders(i), "folder", "folders")}</span></button>`;
  }).join("");
  if (!idx.length) h = `<div class="more">No role matches.</div>`;
  if (idx.length > 400) h += `<div class="more">Showing 400 of ${fmt(idx.length)}. Type to filter.</div>`;
  $("rolelist").innerHTML = h;
  $("rolecount").textContent = fmt(ROLES.length);
}

// Teams tab: teams (One Identity departments) and locations; red, then yellow, then the rest
let selTeam = -1, selLoc = -1, teamsAll = false;
function folderTeamsHtml(i) {
  const ft = folderTeams(i);
  let h = `<h3>Teams with access <span class="muted">· ${plural(ft.teams.length, "team", "teams")}${ft.locs.length ? ", " + plural(ft.locs.length, "location", "locations") : ""}</span>`;
  if (ft.teams.length) h += `<button class="cbtn" data-tcopy="${i}" title="Copy as a table: team, full path, location, people, access, groups (right-click the folder for the people)">Copy</button>`;
  h += `</h3>`;
  if (ft.locs.length) h += `<div class="tlocs">${ft.locs.map(([l, n]) => locChip(l, n, " with access")).join("")}</div>`;
  const lim = teamsAll ? ft.teams.length : 12;
  h += ft.teams.slice(0, lim).map((e) => {
    const vias = [...e.via], own = vias.filter(isPersonId), grp = vias.filter((id) => !isPersonId(id));
    let via = grp.length ? "via " + listNames(grp.map((id) => namePart(IDS[id]))) : "";
    if (own.length) via += (via ? " + " : "") + plural(own.length, "own entry", "own entries");
    const names = [...e.people.keys()].map((k) => namePart(personName(k))).sort((a, b) => a.localeCompare(b));
    const title = (TEAMS[e.t][1] || teamName(e.t)) + "\n" + plural(names.length, "person", "people") + ": " + names.slice(0, 25).join(", ") + (names.length > 25 ? " …" : "");
    const on = e.t === selTeam || (selTeam < 0 && selLoc >= 0 && e.locs.has(selLoc));
    const path = teamPathOnly(e.t);
    return `<button class="trow${on ? " on" : ""}" data-team="${e.t}" title="${esc(title)}"><span class="nm"><span class="tname">${esc(teamName(e.t))}</span>${[...e.locs.keys()].map((l) => locChip(l, e.locs.get(l))).join("")}<span class="tier">${esc(TIER[e.tier])}</span></span>` +
      `<span class="meta">${esc(plural(e.n, "person", "people") + " · " + via)}</span>${path ? `<span class="meta">${esc(truncLeft(path, 60))}</span>` : ""}</button>`;
  }).join("");
  if (ft.teams.length > 12) h += `<button class="linkbtn" id="tall">${teamsAll ? "Show the first 12" : `Show all ${fmt(ft.teams.length)} teams`}</button>`;
  const notes = [];
  if (!ft.teams.length) notes.push(M ? "No team gets access here beyond what everyone has." : "No person from the team file has an own entry here. Build the page with -IncludeGroupMembers to include the people who get access through groups.");
  if (ft.broad.length) notes.push(`Also open to everyone through ${listNames(ft.broad.map(([id, t]) => IDS[id] + " (" + TIER[t] + ")"))}; not counted per team.`);
  if (ft.none.length) notes.push(`${plural(ft.none.length, "account", "accounts")} with access ${ft.none.length === 1 ? "is" : "are"} not in the team file: ${listNames(ft.none.map((k) => namePart(personName(k))).sort((a, b) => a.localeCompare(b)))}.`);
  if (ft.deny) notes.push(`Deny ${ft.deny === 1 ? "entry" : "entries"} on this folder ${ft.deny === 1 ? "is" : "are"} not subtracted.`);
  for (const t of notes) h += `<div class="cardnote">${esc(t)}</div>`;
  return h;
}
function teamCardHtml(t) {
  const ti = teamIndex(), ids = ti.tIds.get(t) || new Map(), ps = [...(ti.tPeople.get(t) || [])], known = ti.known.get(t) || new Set();
  let h = `<div class="cardhead"><div class="idname">${esc(teamName(t))}</div><div class="cardbtns"><button class="ghost" data-copy="${esc(teamName(t))}" data-what="team name" title="Copy the team name (right-click for more)">Copy</button><button class="ghost" id="tclear" title="Clear (Esc)">Clear</button></div></div>`;
  if (teamPathOnly(t)) h += `<div class="cardnote">${esc(TEAMS[t][1])}</div>`;
  const lc = ti.tLocAcc.get(t) || ti.tLocKnown.get(t);
  const chips = (lc ? sortLocs(lc).map(([l, n]) => locChip(l, n, ti.tLocAcc.has(t) ? " with access" : "")).join("") : "") + teamFlagChips(t);
  if (chips) h += `<div class="tlocs">${chips}</div>`;
  h += `<div class="stats"><div><b>${fmt(ps.length)}</b><span>people with access</span></div><div><b>${fmt((ti.tFolders.get(t) || new Set()).size)}</b><span>folders with entries</span></div><div><b>${fmt(ownAny)}</b><span>with access, incl. inherited</span></div></div>`;
  if (ids.size) {
    const rows = [...ids].sort((a, b) => b[1].size - a[1].size || IDS[a[0]].localeCompare(IDS[b[0]]));
    h += `<div class="cardnote">Access through</div>` + rows.slice(0, 30).map(([id, s]) => {
      const p = pOf(id), own = isPersonId(id), nf = new Set((place.get(id) || []).map((x) => x[0])).size;
      const attr = p >= 0 && P[p][2] === 1 ? `data-g="${p}"` : `data-id="${id}"`;
      return `<button class="grow" ${attr}><span class="nm">${esc(IDS[id])}${own ? accountChips(id) : groupChips(p) + roleChips(rolesForId(id))}</span><span class="meta">${own ? "own entry" : plural(s.size, "person", "people") + " of this team"} · on ${plural(nf, "folder", "folders")}</span></button>`;
    }).join("");
    if (rows.length > 30) h += `<div class="more">and ${fmt(rows.length - 30)} more</div>`;
  }
  if (ps.length) {
    ps.sort((a, b) => personName(a).localeCompare(personName(b)));
    h += `<div class="cardnote">People with access</div><div class="people">` + ps.slice(0, 200).map((k) => {
      const tl = personTeam(k), d = k >= 0 ? P[k][1] : "";
      return `<span class="pchip" title="${esc(personName(k) + (d ? " · " + d : "") + (tl && tl[1] >= 0 ? " · " + LOCS[tl[1]] : ""))}">${esc(namePart(personName(k)))}</span>`;
    }).join("") + (ps.length > 200 ? `<span class="pchip">+ ${fmt(ps.length - 200)} more</span>` : "") + `</div>`;
  }
  const rest = Math.max(0, known.size - ps.length);
  if (!ps.length) h += `<div class="cardnote">${M ? "No access beyond what everyone has." : "No person of this team has an own entry. Build the page with -IncludeGroupMembers to include access through groups."}</div>`;
  if (rest && ps.length) h += `<div class="cardnote">${plural(rest, "more person", "more people")} of this team ${rest === 1 ? "is" : "are"} in the scan or the groups read, with no access beyond what everyone has.</div>`;
  return h;
}
function locCardHtml(l) {
  const ti = teamIndex(), ids = ti.lIds.get(l) || new Map(), people = new Set(), fs = new Set();
  for (const s of ids.values()) for (const k of s) people.add(k);
  for (const id of ids.keys()) for (const pl of place.get(id) || []) fs.add(pl[0]);
  let h = `<div class="cardhead"><div class="idname">Location ${esc(LOCS[l])}</div><div class="cardbtns"><button class="ghost" data-copy="${esc(LOCS[l])}" data-what="location" title="Copy the location code">Copy</button><button class="ghost" id="lclear" title="Clear (Esc)">Clear</button></div></div>`;
  h += `<div class="stats"><div><b>${fmt((ti.lTeams.get(l) || new Set()).size)}</b><span>teams</span></div><div><b>${fmt(people.size)}</b><span>people with access</span></div><div><b>${fmt(fs.size)}</b><span>folders with entries</span></div></div>`;
  h += `<div class="cardnote">The folder graph shows the access of the people at ${esc(LOCS[l])}. Pick a team to narrow it down.</div>`;
  return h;
}
function renderTeamList() {
  if (!TD) return;
  const ti = teamIndex(), card = $("teamcard");
  if (selTeam >= 0) { card.innerHTML = teamCardHtml(selTeam); card.hidden = false; }
  else if (selLoc >= 0) { card.innerHTML = locCardHtml(selLoc); card.hidden = false; }
  else { card.hidden = true; card.innerHTML = ""; }
  const locs = LOCS.map((_, l) => l).filter((l) => ti.lTeams.has(l)).sort((a, b) => LOCS[a].localeCompare(LOCS[b]));
  $("locbar").innerHTML = locs.length > 1 || selLoc >= 0 ? locs.map((l) => {
    const n = ti.lTeams.get(l).size;
    return `<button class="lchip${l === selLoc ? " on" : ""}" data-loc="${l}" title="${esc(`${LOCS[l]}: ${plural(n, "team", "teams")}. Click to show the access of the people at ${LOCS[l]}.`)}">${esc(LOCS[l])}<span>${fmt(n)}</span></button>`;
  }).join("") : "";
  const q = $("tq").value.trim().toLowerCase();
  let idx = TEAMS.map((_, t) => t);
  if (selLoc >= 0) { const s = ti.lTeams.get(selLoc) || new Set(); idx = idx.filter((t) => s.has(t)); }
  if (q) idx = idx.filter((t) => TEAMS[t][0].toLowerCase().includes(q) || TEAMS[t][1].toLowerCase().includes(q) ||
    [...(ti.tLocKnown.get(t) || new Map()).keys()].some((l) => LOCS[l].toLowerCase() === q));
  const st = (t) => { const f = ti.tFlag.get(t); return f ? f.st : 0; };
  idx.sort((a, b) => flagRank(st(a)) - flagRank(st(b)) || (ti.tPeople.has(a) ? 0 : 1) - (ti.tPeople.has(b) ? 0 : 1) ||
    (TEAMS[a][1] || TEAMS[a][0]).localeCompare(TEAMS[b][1] || TEAMS[b][0]));
  let h = "";
  if (!M) h += `<div class="cardnote" style="margin:0 8px 6px">Only people with their own entries are shown. Build the page with <b>-IncludeGroupMembers</b> to include the people who get access through groups.</div>`;
  h += idx.slice(0, 400).map((t) => {
    const ps = ti.tPeople.get(t), lc = ti.tLocAcc.get(t) || ti.tLocKnown.get(t), ids = ti.tIds.get(t);
    let meta;
    if (ps) {
      const top = [...ids].filter(([id]) => !isPersonId(id)).sort((a, b) => b[1].size - a[1].size).map(([id]) => namePart(IDS[id]));
      const own = [...ids.keys()].filter(isPersonId).length;
      meta = `${plural(ps.size, "person", "people")} · ${plural(ti.tFolders.get(t).size, "folder", "folders")}` + (top.length ? " · via " + listNames(top) : "") + (own ? (top.length ? " + " : " · ") + plural(own, "own entry", "own entries") : "");
    } else meta = `${plural((ti.known.get(t) || new Set()).size, "person", "people")} found · no access beyond everyone's`;
    const path = teamPathOnly(t);
    return `<button class="trow${t === selTeam ? " on" : ""}" data-team="${t}"><span class="nm"><span class="tname">${esc(teamName(t))}</span>${lc ? sortLocs(lc).map(([l]) => locChip(l)).join("") : ""}${teamFlagChips(t)}</span><span class="meta">${esc(meta)}</span>${path ? `<span class="meta">${esc(truncLeft(path, 60))}</span>` : ""}</button>`;
  }).join("");
  if (!idx.length) h += `<div class="more">No team matches.</div>`;
  if (idx.length > 400) h += `<div class="more">Showing 400 of ${fmt(idx.length)}. Type to filter.</div>`;
  $("teamlist").innerHTML = h;
  $("teamcount").textContent = fmt(ti.tPeople.size);
}
function teamHighlight() {
  const ti = teamIndex();
  const src = selTeam >= 0 ? ti.tIds.get(selTeam) || new Map() : selLoc >= 0 ? ti.lIds.get(selLoc) || new Map() : null;
  if (!src) { setHighlight(null); return; }
  setHighlight(new Map([...src.keys()].map((id) => [id, -1])), selTeam >= 0 ? teamName(selTeam) : "People at " + LOCS[selLoc], -2, true);
  ownAny = 0; for (let i = 0; i < N; i++) if (G[i]) ownAny++;
  if (src.size) revealHighlight();
  else notify(selTeam >= 0 ? `${teamName(selTeam)} has no access beyond what everyone has.` : `Nobody at ${LOCS[selLoc]} has access beyond what everyone has.`);
}
function selectTeam(t, toggleOff = true) {
  selId = -1; selRole = -1; focusRole = -1; focusP = -1;
  closeDrawer();
  selTeam = t < 0 || (toggleOff && t === selTeam) ? -1 : t;
  teamHighlight();
  if (activeTab !== "teams") switchTab("teams");
  renderTeamList(); renderIdCard(); renderIdList(); renderRoleList(); renderDetails(); renderLegend(); schedule();
}
function selectLoc(l) {
  selId = -1; selRole = -1; focusRole = -1; focusP = -1;
  closeDrawer();
  selLoc = l < 0 || l === selLoc ? -1 : l; selTeam = -1;
  teamHighlight();
  if (activeTab !== "teams") switchTab("teams");
  renderTeamList(); renderIdCard(); renderIdList(); renderRoleList(); renderDetails(); renderLegend(); schedule();
}
const clearTeams = () => { if (selTeam >= 0 || selLoc >= 0) { selTeam = -1; selLoc = -1; renderTeamList(); } };

function renderDetails() {
  const el = $("details");
  if (selF < 0) {
    el.innerHTML = `<div class="empty"><h2>No folder selected</h2><p>Click a folder to see its owner and permissions.</p><ul><li>Click <b>+</b> on a folder, or double-click it, to open it.</li><li>Pick an identity on the left to see where it has access.</li><li>Drag to pan, scroll to zoom.</li></ul></div>`;
    return;
  }
  const i = selF, f = F[i];
  let h = `<h2>${esc(f[0])}</h2><div class="path">${esc(fullPath(i))}<button class="cbtn" data-copy="${esc(fullPath(i))}" data-what="path" title="Copy the path (or right-click the folder)">Copy path</button></div>`;
  h += `<dl class="facts"><dt>Owner</dt><dd>${f[2] >= 0 ? idBtn(f[2]) : '<span class="muted">unknown</span>'}</dd>`;
  h += `<dt>Inheritance</dt><dd>${f[3] & 1 ? "<b>Disabled</b> on this folder" : "Enabled"}</dd>`;
  h += `<dt>Level</dt><dd>${depth[i]}${depth[i] === 0 ? " (scanned folder)" : ""}</dd>`;
  h += `<dt>Subfolders</dt><dd>${fmt(desc[i])}</dd>`;
  if (f[6] >= 0) h += `<dt>Note</dt><dd class="warn">${esc(NOTES[f[6]])}</dd>`;
  h += `</dl>`;
  const ffl = folderFlags.get(i);
  if (ffl) {
    h += `<h3>Flags</h3><ul class="flist">` +
      ffl.bad.map((t) => `<li><span class="st bad">! ${/Full Control/.test(t) ? "full control" : "direct access"}</span> ${esc(t)}</li>`).join("") +
      ffl.ext.map((t) => `<li><span class="st warn">E external access</span> ${esc(t)}</li>`).join("") + `</ul>`;
  }
  if (TD) h += folderTeamsHtml(i);
  const fl = findBy.get(i);
  if (fl && fl.length) {
    h += `<h3>Findings</h3><ul class="flist">` + fl.slice().sort((a, b) => FIND[a][1] - FIND[b][1]).map((k) => {
      const x = FIND[k];
      return `<li><span class="sevb s${x[1]}">${SEV_NAME[x[1]]}</span> <b>${esc(x[3])}</b>${x[4] ? " \u00b7 " + esc(x[4]) : ""}${x[5] ? " \u00b7 " + esc(x[5]) : ""}${x[6] ? `<div class="muted">${esc(x[6])}</div>` : ""}</li>`;
    }).join("") + `</ul>`;
  }
  const ex = f[4], inh = f[5] >= 0 ? SETS[f[5]] : [];
  h += `<h3>Permissions <span class="muted">\u00b7 ${fmt(ex.length)} explicit, ${fmt(inh.length)} inherited</span></h3>`;
  if (!ex.length && !inh.length) {
    h += `<p class="muted">No entries recorded for this folder.</p>`;
  } else {
    const row = (a) => {
      const ac = ACES[a], hint = principalHint(ac[0]);
      const chips = accountChips(ac[0]) + groupChips(pOf(ac[0])) + identityExtChip(ac[0]) + roleChips(rolesForId(ac[0]));
      return `<tr${HL && HL.has(ac[0]) ? ' class="hl"' : ""}><td>${idBtn(ac[0])}${hint || chips ? `<span class="hint">${esc(hint)}${chips}</span>` : ""}</td><td>${ac[2] ? '<span class="deny">Deny</span> ' : ""}${esc(RIGHTS[ac[1]])}</td><td>${esc(APPLIES[ac[3]])}</td></tr>`;
    };
    h += `<table class="acl"><thead><tr><th>Identity</th><th>Access</th><th>Applies to</th></tr></thead><tbody>`;
    if (ex.length) h += `<tr class="grp"><td colspan="3">Explicit</td></tr>` + ex.map(row).join("");
    if (inh.length) h += `<tr class="grp"><td colspan="3">Inherited</td></tr>` + inh.map(row).join("");
    h += `</tbody></table>`;
  }
  el.innerHTML = h;
}

function renderLegend() {
  let h = `<span><span class="sw"></span>Folder</span><span><span class="lp">3</span>explicit entries</span>`;
  h += `<span><svg width="26" height="8" aria-hidden="true"><path d="M0 4h26" stroke="var(--edge)" stroke-width="1.6" stroke-dasharray="6 4"/></svg>inheritance off</span>`;
  if (HL) h += `<span><span class="sw g"></span>granted here</span><span><span class="sw r"></span>inherited access</span>`;
  if (FIND.length && showFind) h += `<span><span class="lb s0">C</span><span class="lb s1">H</span><span class="lb s2">M</span><span class="lb s3">L</span>worst finding</span>`;
  if ([...folderFlags.values()].some((f) => f.bad.length)) h += `<span><span class="lb s0">!</span>individual account on level ${levelText}</span>`;
  if ([...folderFlags.values()].some((f) => f.ext.length)) h += `<span><span class="lb s2">E</span>external access</span>`;
  $("legend").innerHTML = h;
}

function switchTab(t) {
  activeTab = t;
  for (const b of document.querySelectorAll(".tabs button")) b.classList.toggle("on", b.dataset.tab === t);
  $("pane-ids").hidden = t !== "ids";
  $("pane-find").hidden = t !== "find";
  $("pane-groups").hidden = t !== "groups";
  $("pane-roles").hidden = t !== "roles";
  $("pane-teams").hidden = t !== "teams";
  $("idcard").hidden = t !== "ids" || selId < 0;
}

// ---------------------------------------------------------------- input
let lastTap = { key: null, t: 0 };
const isDoubleTap = (key) => { const now = Date.now(), d = lastTap.key === key && now - lastTap.t < 350; lastTap = d ? { key: null, t: 0 } : { key, t: now }; return d; };

function showTip(i, e) {
  const f = F[i], inh = f[5] >= 0 ? SETS[f[5]].length : 0;
  let h = `<div class="tp">${esc(fullPath(i))}</div><div>Level ${depth[i]}</div>`;
  h += `<div>Owner: ${f[2] >= 0 ? esc(IDS[f[2]]) : "unknown"}</div>`;
  h += `<div>${fmt(f[4].length)} explicit, ${fmt(inh)} inherited entries</div>`;
  if (f[3] & 1) h += `<div>Inheritance disabled</div>`;
  if (kids[i].length) h += `<div>${plural(desc[i], "subfolder", "subfolders")}</div>`;
  if (G && G[i]) h += `<div>${esc(hlName)}: ${esc(GV.get(i) || "inherited entry")}</div>`;
  const ff = folderFlags.get(i);
  if (ff) {
    for (const t of ff.bad.slice(0, 3)) h += `<div class="warn">! ${esc(t)}</div>`;
    for (const t of ff.ext.slice(0, 3)) h += `<div>E ${esc(t)}</div>`;
    const more = Math.max(0, ff.bad.length - 3) + Math.max(0, ff.ext.length - 3);
    if (more) h += `<div class="muted">and ${fmt(more)} more</div>`;
  }
  if (TD) {
    const ft = folderTeams(i);
    if (ft.teams.length) h += `<div>Teams: ${esc(listNames(ft.teams.map((e) => teamName(e.t) + (e.locs.size ? " (" + [...e.locs.keys()].map(locName).join(", ") + ")" : ""))))}</div>`;
  }
  const fl = findBy.get(i);
  if (fl && showFind) h += `<div>${plural(fl.length, "finding", "findings")}, worst ${SEV_NAME[worst[i]]}</div>`;
  if (f[6] >= 0) h += `<div class="warn">${esc(NOTES[f[6]])}</div>`;
  tip.innerHTML = h; tip.hidden = false;
  placeTip(tip, mainEl, e);
}

attachPanZoom(svg, mainV, applyT,
  (target) => {
    const tg = target.closest("[data-t]");
    if (tg) { toggle(+tg.dataset.t); return; }
    const n = target.closest("[data-i]");
    if (!n) return;
    const i = +n.dataset.i;
    if (isDoubleTap("f" + i) && kids[i].length) { toggle(i); return; }
    selectFolder(i, false);
  },
  (e) => { const n = e.target.closest ? e.target.closest("[data-i]") : null; if (n) showTip(+n.dataset.i, e); else tip.hidden = true; },
  () => { tip.hidden = true; });

attachPanZoom(msvg, mv, mApply,
  (target) => {
    const tg = target.closest("[data-mt]");
    if (tg) { mToggle(mVis[+tg.dataset.mt]); return; }
    const rn = target.closest("[data-mr]");
    if (rn) { focusRoleNode(mRoles[+rn.dataset.mr].r); return; }
    const el = target.closest("[data-m]");
    if (!el) return;
    const n = mVis[+el.dataset.m];
    if (!n || n.p < 0) return;
    if (isDoubleTap(n) && expandable(n)) { mToggle(n); return; }
    focusMember(n.par ? n.p : -1);
  },
  (e) => {
    const rn = e.target.closest ? e.target.closest("[data-mr]") : null;
    if (rn && mRoles[+rn.dataset.mr]) { showRTip(mRoles[+rn.dataset.mr], e); return; }
    const el = e.target.closest ? e.target.closest("[data-m]") : null;
    if (el && mVis[+el.dataset.m]) showMTip(mVis[+el.dataset.m], e); else mtip.hidden = true;
  },
  () => { mtip.hidden = true; });

// ---------------------------------------------------------------- copy: right-click menu, copy buttons, Ctrl+C
async function copyText(text, what) {
  let ok = false;
  try { await navigator.clipboard.writeText(text); ok = true; } catch (_) { /* fall back below */ }
  if (!ok) {   // pages opened from disk can be refused the clipboard API; the old way still works there
    const ta = document.createElement("textarea");
    ta.value = text; ta.setAttribute("readonly", ""); ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    try { ok = document.execCommand("copy"); } catch (_) { ok = false; }
    ta.remove();
  }
  const lines = text.split("\n");
  notify(ok ? `Copied ${what}: ${trunc(lines[0], 80)}${lines.length > 1 ? ` (+${plural(lines.length - 1, "more line", "more lines")})` : ""}` : "Copy failed: the browser blocked access to the clipboard.");
}
function memberNames(g) {   // every account in the group, all levels, one per line
  const out = new Set(), seen = new Set([g]), stack = [g];
  while (stack.length) {
    const v = PG.get(stack.pop());
    if (v) for (const c of v.m) {
      if (P[c][2] === 1) { if (!seen.has(c)) { seen.add(c); stack.push(c); } }
      else out.add(P[c][0]);
    }
  }
  return [...out].sort((a, b) => a.localeCompare(b));
}
const roleCopy = (ri) => ({ label: `Copy ${RKIND[ROLES[ri][1]].toLowerCase()}: ${trunc(ROLES[ri][0], 36)}`, text: ROLES[ri][0], what: RKIND[ROLES[ri][1]].toLowerCase() + " name" });
function nameItems(name) {
  const it = [{ label: "Copy name", text: name, what: "name" }];
  if (name.includes("\\")) it.push({ label: "Copy name without domain", text: namePart(name), what: "name" });
  return it;
}
function principalMenu(p) {
  const r = P[p], it = nameItems(r[0]);
  it[0].label = r[2] === 1 ? "Copy group name" : r[2] === 5 ? "Copy name" : "Copy account name";
  if (r[1]) it.push({ label: "Copy display name", text: r[1], what: "display name" });
  if (TD && r[2] !== 1) { const tl = personTeam(p); if (tl) it.push({ label: `Copy team: ${trunc(teamName(tl[0]), 34)}`, text: teamName(tl[0]), what: "team name" }); }
  if (r[2] === 1 && PG.has(p)) {
    const m = memberNames(p), s = groupStats(p);
    if (m.length) it.push({ label: `Copy member list (${fmt(m.length)} accounts${s.notLoaded ? ", not all read" : ""})`, text: m.join("\n"), what: "member list" });
    const tg = TD ? teamsInGroup(p) : null;
    if (tg && tg.teams.length) it.push({ label: `Copy teams in this group (${fmt(tg.teams.length)})`, what: "teams",
      text: ["Team\tFull path\tLocation\tPeople"].concat(tg.teams.map((e) => [teamName(e.t), TEAMS[e.t][1], [...e.locs].map(locName).join(", "), e.n].join("\t"))).join("\n") });
  }
  for (const ri of rolesForP(p).slice(0, 6)) it.push(roleCopy(ri));
  return { title: r[0], items: it };
}
function identityMenu(id) {
  const p = pOf(id);
  if (p >= 0) {
    const g = principalMenu(p);
    if (IDS[id] !== P[p][0]) g.items.unshift({ label: "Copy name as written on the folder", text: IDS[id], what: "name" });
    return g;
  }
  const it = nameItems(IDS[id]);
  const tl = TD ? teamOfId.get(id) : null;
  if (tl) it.push({ label: `Copy team: ${trunc(teamName(tl[0]), 34)}`, text: teamName(tl[0]), what: "team name" });
  for (const ri of rolesForId(id).slice(0, 6)) it.push(roleCopy(ri));
  return { title: IDS[id], items: it };
}
function roleMenu(ri) {
  const r = ROLES[ri], gs = roleGroups(ri);
  return { title: `${RKIND[r[1]]}: ${r[0]}`, items: [
    { label: `Copy ${RKIND[r[1]].toLowerCase()} name`, text: r[0], what: RKIND[r[1]].toLowerCase() + " name" },
    { label: `Copy its groups (${fmt(gs.length)})`, text: gs.map((g) => g.name).join("\n"), what: "groups" }] };
}
function folderMenu(i) {
  const it = [{ label: "Copy path", text: fullPath(i), what: "path" }, { label: "Copy folder name", text: F[i][0], what: "folder name" }];
  const ft = TD ? folderTeams(i) : null;
  if (ft && ft.teams.length) {
    it.push({ label: `Copy teams with access (${fmt(ft.teams.length)})`, text: teamsTsv(i), what: "teams with access" });
    it.push({ label: `Copy people with access (${fmt(ft.teams.reduce((n, e) => n + e.n, 0))})`, text: peopleTsv(i), what: "people with access" });
  }
  return { title: fullPath(i), items: it };
}
function teamMenu(t) {
  const ps = [...(teamIndex().tPeople.get(t) || [])].map(personName).sort((a, b) => a.localeCompare(b)), fs = teamFolderList(t);
  const it = [{ label: "Copy team name", text: teamName(t), what: "team name" }];
  if (teamPathOnly(t)) it.push({ label: "Copy full team path", text: TEAMS[t][1], what: "team path" });
  if (ps.length) it.push({ label: `Copy people with access (${fmt(ps.length)})`, text: ps.join("\n"), what: "people" });
  if (fs.length) it.push({ label: `Copy folders with entries (${fmt(fs.length)})`, text: fs.map(fullPath).join("\n"), what: "folder paths" });
  return { title: "Team: " + teamName(t), items: it };
}
function locMenu(l) {
  const ts = [...(teamIndex().lTeams.get(l) || [])].map(teamName).sort((a, b) => a.localeCompare(b));
  return { title: "Location " + LOCS[l], items: [{ label: "Copy location code", text: LOCS[l], what: "location" },
    { label: `Copy its teams (${fmt(ts.length)})`, text: ts.join("\n"), what: "teams" }] };
}

const cmenu = document.createElement("div");
cmenu.className = "cmenu"; cmenu.setAttribute("role", "menu"); cmenu.hidden = true;
document.body.appendChild(cmenu);
let cItems = [];
const hideMenu = () => { if (!cmenu.hidden) { cmenu.hidden = true; cItems = []; } };
function showMenu(groups, x, y) {
  cItems = [];
  let h = "";
  groups.forEach((g, gi) => {
    if (gi) h += `<div class="csep"></div>`;
    h += `<div class="chead" title="${esc(g.title)}">${esc(g.title)}</div>`;
    for (const it of g.items) { h += `<button class="citem" role="menuitem" data-ci="${cItems.length}">${esc(it.label)}</button>`; cItems.push(it); }
  });
  cmenu.innerHTML = h; cmenu.hidden = false;
  tip.hidden = true; mtip.hidden = true;
  cmenu.style.left = Math.max(4, Math.min(x, innerWidth - cmenu.offsetWidth - 8)) + "px";
  cmenu.style.top = Math.max(4, Math.min(y, innerHeight - cmenu.offsetHeight - 8)) + "px";
  const first = cmenu.querySelector(".citem");
  if (first) first.focus();
}
document.addEventListener("contextmenu", (e) => {
  const t = e.target instanceof Element ? e.target : null;
  if (!t || t.closest("input, textarea")) return;
  const groups = [];
  const fn = t.closest("#vp [data-i]"), mr = t.closest("#mvp [data-mr]"), mn = t.closest("#mvp [data-m]");
  if (fn) groups.push(folderMenu(+fn.dataset.i));
  else if (mr && mRoles[+mr.dataset.mr]) groups.push(roleMenu(mRoles[+mr.dataset.mr].r));
  else if (mn && mVis[+mn.dataset.m] && mVis[+mn.dataset.m].p >= 0) groups.push(principalMenu(mVis[+mn.dataset.m].p));
  else {
    const b = t.closest("button");
    if (b && !b.classList.contains("citem")) {
      if (b.dataset.f !== undefined) groups.push(folderMenu(+b.dataset.f));
      const idn = b.dataset.idn ? idByName.get(b.dataset.idn.toLowerCase()) : undefined;
      if (idn !== undefined) groups.push(identityMenu(idn));
      if (b.dataset.id !== undefined) groups.push(identityMenu(+b.dataset.id));
      if (b.dataset.g !== undefined) groups.push(principalMenu(+b.dataset.g));
      if (b.dataset.xa !== undefined) groups.push(principalMenu(+b.dataset.xa));
      if (b.dataset.r !== undefined) groups.push(roleMenu(+b.dataset.r));
      if (b.dataset.team !== undefined) groups.push(teamMenu(+b.dataset.team));
      if (b.dataset.loc !== undefined) groups.push(locMenu(+b.dataset.loc));
      if (b.dataset.tcopy !== undefined) groups.push(folderMenu(+b.dataset.tcopy));
    }
    if (!groups.length && selTeam >= 0 && t.closest("#teamcard .idname")) groups.push(teamMenu(selTeam));
    if (!groups.length && selF >= 0 && t.closest("#details h2, #details .path")) groups.push(folderMenu(selF));
    if (!groups.length && mRootP >= 0 && t.closest("#dtitle")) groups.push(principalMenu(mRootP));
  }
  if (!groups.length) return;   // anywhere else: the browser's own menu
  e.preventDefault();
  showMenu(groups, e.clientX, e.clientY);
});
cmenu.addEventListener("click", (e) => {
  const b = e.target.closest(".citem");
  if (!b) return;
  const it = cItems[+b.dataset.ci];
  hideMenu();
  if (it) copyText(it.text, it.what);
});
cmenu.addEventListener("keydown", (e) => {
  const items = [...cmenu.querySelectorAll(".citem")], k = items.indexOf(document.activeElement);
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    e.preventDefault();
    items[(k + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length].focus();
  }
});
document.addEventListener("pointerdown", (e) => { if (!cmenu.hidden && !cmenu.contains(e.target)) hideMenu(); }, true);
window.addEventListener("blur", hideMenu);
window.addEventListener("wheel", hideMenu, { passive: true });

document.addEventListener("click", (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  if (b.dataset.copy !== undefined) { copyText(b.dataset.copy, b.dataset.what || "text"); return; }
  if (b.dataset.tcopy !== undefined) { copyText(teamsTsv(+b.dataset.tcopy), "teams with access"); return; }
  if (b.dataset.team !== undefined) { selectTeam(+b.dataset.team, !b.closest("#details, #idcard")); return; }
  if (b.dataset.loc !== undefined) { selectLoc(+b.dataset.loc); return; }
  if (b.classList.contains("frow")) {
    const id = b.dataset.idn ? idByName.get(b.dataset.idn.toLowerCase()) : undefined;
    if (id !== undefined) selectIdentity(id, false);
    selectFolder(+b.dataset.f, true);
  }
  else if (b.classList.contains("grow")) {
    if (b.dataset.g !== undefined) openGroup(+b.dataset.g);
    else if (b.dataset.xa !== undefined) { openGroup(+b.dataset.xg); focusMember(+b.dataset.xa); }   // external account reached through a group
    else selectIdentity(+b.dataset.id, false);
  }
  else if (b.dataset.r !== undefined) selectRole(+b.dataset.r);
  else if (b.id === "rclear") selectRole(-1);
  else if (b.id === "tclear") selectTeam(-1);
  else if (b.id === "lclear") selectLoc(-1);
  else if (b.id === "tall") { teamsAll = !teamsAll; renderDetails(); }
  else if (b.dataset.id !== undefined) selectIdentity(+b.dataset.id);
  else if (b.classList.contains("prow")) selectFolder(+b.dataset.f, true);
  else if (b.id === "idclear") selectIdentity(-1);
  else if (b.id === "idmembers") { const p = pOf(selId); if (p >= 0) openDrawer(p); }
  else if (b.id === "mclose") closeGroupView();
  else if (b.id === "mfit") { fitView(mv, msvg, mItems(), 0.6); mApply(); }   // keep names readable
  else if (b.id === "mreset") focusMember(-1);
  else if (b.dataset.lv) expandLevel(+b.dataset.lv);
  else if (b.dataset.tab) switchTab(b.dataset.tab);
  else if (b.id === "fit") fit();
});
{ // drag the top edge of the member graph to resize it
  const grip = $("dgrip");
  let start = null;
  grip.addEventListener("pointerdown", (e) => { start = { y: e.clientY, h: drawerEl.offsetHeight }; grip.setPointerCapture(e.pointerId); e.preventDefault(); });
  grip.addEventListener("pointermove", (e) => {
    if (!start) return;
    const h = Math.max(160, Math.min(graph.clientHeight - 120, start.h + start.y - e.clientY));
    drawerEl.style.flexBasis = h + "px";
    schedule(); mSchedule();
  });
  const end = () => { start = null; };
  grip.addEventListener("pointerup", end);
  grip.addEventListener("pointercancel", end);
}
$("idq").addEventListener("input", renderIdList);
$("rq").addEventListener("input", renderRoleList);
$("tq").addEventListener("input", renderTeamList);
$("showfind").addEventListener("change", (e) => { showFind = e.target.checked; renderLegend(); schedule(); });
function refilterMembers() {
  buildMemberTree(); mLayout();
  const active = mQuery.trim() || mIssuesOnly;
  if (active) { fitView(mv, msvg, mItems(), 0.6); mApply(); } else mHome();   // show the matching paths
  $("mqinfo").textContent = !active ? "" : mMatches ? (mMatches >= MATCH_LIMIT ? `first ${MATCH_LIMIT}` : plural(mMatches, "match", "matches")) : "No match";
}
let mqTimer = 0;
$("mq").addEventListener("input", (e) => {
  clearTimeout(mqTimer);
  mqTimer = setTimeout(() => { mQuery = e.target.value; refilterMembers(); }, 150);
});
$("missues").addEventListener("change", (e) => { mIssuesOnly = e.target.checked; if (!drawerEl.hidden) refilterMembers(); });
const lcNames = F.map((f) => f[0].toLowerCase());
let fMatches = [], fPos = -1, fLast = "";
$("fq").addEventListener("keydown", (e) => {
  if (e.key !== "Enter") return;
  const q = e.target.value.trim().toLowerCase();
  if (!q) return;
  if (q !== fLast) { fLast = q; fMatches = order.filter((i) => lcNames[i].includes(q)); fPos = -1; }
  if (!fMatches.length) { $("fqinfo").textContent = "No match"; return; }
  fPos = (fPos + (e.shiftKey ? -1 : 1) + fMatches.length) % fMatches.length;
  $("fqinfo").textContent = `${fmt(fPos + 1)} of ${fmt(fMatches.length)}`;
  selectFolder(fMatches[fPos], true);
});
$("fq").addEventListener("input", (e) => { if (!e.target.value) { $("fqinfo").textContent = ""; fLast = ""; } });
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !cmenu.hidden) { hideMenu(); return; }
  if ((e.ctrlKey || e.metaKey) && (e.key === "c" || e.key === "C") && selF >= 0 && e.target.tagName !== "INPUT" &&
      !String(window.getSelection() || "")) { e.preventDefault(); copyText(fullPath(selF), "path"); return; }
  if (e.key !== "Escape" || e.target.tagName === "INPUT") return;
  if (mRootP >= 0 && !drawerEl.hidden && (focusRole >= 0 || (focusP >= 0 && focusP !== mRootP))) focusMember(-1);
  else if (selId >= 0) selectIdentity(-1);
  else if (selRole >= 0) selectRole(-1);
  else if (selTeam >= 0) selectTeam(-1);
  else if (selLoc >= 0) selectLoc(-1);
  else if (!drawerEl.hidden) closeGroupView();
  else if (selF >= 0) { selF = -1; renderDetails(); schedule(); }
});
window.addEventListener("resize", () => { schedule(); mSchedule(); });

// ---------------------------------------------------------------- start
const m = D.meta;
$("subtitle").textContent = `${m.root} \u00b7 ${plural(N, "folder", "folders")} \u00b7 ${fmt(m.entries)} entries \u00b7 scan ${m.source}` +
  (m.findingsSource ? ` \u00b7 findings ${m.findingsSource}` : "") + ` \u00b7 generated ${m.generated}` +
  (M ? ` \u00b7 group members read ${M.at}` : "") + (RD ? ` \u00b7 roles ${RD.src.join(", ")}` : "") + (TD ? ` \u00b7 teams ${TD.src}` : "");
$("idcount").textContent = fmt(idRows.length);
if (FIND.length) $("findcount").textContent = fmt(FIND.length);
else { $("findtab").hidden = true; $("findtoggle").hidden = true; }
$("grouptab").hidden = false;
if (ROLES.length) $("roletab").hidden = false;
if (TD) $("teamtab").hidden = false;
renderIdList(); renderFindList(); renderGroupList(); renderRoleList(); renderTeamList(); renderLegend();
let L = 1;
while (L < 3 && L + 1 < perDepth.length && levelCount(L + 1) <= 80) L++;
for (let i = 0; i < N; i++) expanded[i] = depth[i] < L ? 1 : 0;
relayout();
if (roots.length) selF = roots[0];
renderDetails();
home();
})();
</script>
</body>
</html>
'@

# =============================================================================================
# Write the page
# =============================================================================================

if (-not $OutputPath) {
    $OutputPath = Join-Path (Split-Path -Parent $inputFile) ([System.IO.Path]::GetFileNameWithoutExtension($inputFile) + '_graph.html')
}
$outFull = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$outDir  = Split-Path -Parent $outFull
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) { $null = New-Item -ItemType Directory -Path $outDir }

$html = $template.Replace('__TITLE__', [System.Net.WebUtility]::HtmlEncode($Title)).Replace('__PERMISSION_DATA__', $sb.ToString())
[System.IO.File]::WriteAllText($outFull, $html, [System.Text.UTF8Encoding]::new($false))

Write-Host ('Graph written: {0} ({1:N1} MB)' -f $outFull, ((Get-Item -LiteralPath $outFull).Length / 1MB))
if ($membershipJson) {
    Write-Host 'The file contains the full permission map and the members of each group. Store and share it accordingly.' -ForegroundColor Yellow
}
else {
    Write-Host 'The file contains the full permission map of the scanned folders. Store and share it accordingly.' -ForegroundColor Yellow
}
