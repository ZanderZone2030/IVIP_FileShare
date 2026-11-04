# Samples

Synthetic data to try the scripts without a file share or a domain. Every name, group, team and SID in these files is made up.

| File | What it is | Used with |
|---|---|---|
| `SampleScan.csv` | A scan of a small share (`D:\Shares`, 11 folders), as written by `Get-FolderPermissions.ps1`. It contains broad groups, direct user grants, an orphaned SID, broken inheritance, a Deny entry, an unreadable folder and an external account. | all three scripts |
| `SampleScan_findings.csv` | The findings for that scan, as written by `Find-PermissionIssues.ps1` | `New-PermissionGraph.ps1 -FindingsPath` |
| `Sample_OIM_business_roles.csv` | Business roles (Org) and the AD groups they assign: `Ident_Org;cn` | `-BusinessRolePath` |
| `Sample_OIM_system_roles.csv` | System roles (ESet) and their AD groups: `DisplayName;cn` | `-SystemRolePath` |
| `Sample_OIM_departments.csv` | The department table: `SAMAccountName;DepartmentName;FullPath;LocationCode` | `-TeamPath` |
| `lastaccess/store/` | A last-access store for server FS01: share connections and audited folders from 2026-07-01 to 2026-10-22 | `-LastAccessPath`, `Join-LastAccess.ps1 -StorePath` |
| `lastaccess/runs/` | The two collector runs the store was merged from, as written by `Get-ShareAccessEvents.ps1` | `Merge-LastAccess.ps1 -Path` |
| `lastaccess/FS01_who_can_access.csv` | Who can reach which folder, and `_lastused.csv` with last use added by `Join-LastAccess.ps1` | `Join-LastAccess.ps1 -AccessPath` |

```powershell
# Findings report
..\scripts\Find-PermissionIssues.ps1 -Path .\SampleScan.csv -SkipAccountLookup

# Graph with findings and roles (no domain needed)
..\scripts\New-PermissionGraph.ps1 -Path .\SampleScan.csv -FindingsPath .\SampleScan_findings.csv `
    -BusinessRolePath .\Sample_OIM_business_roles.csv -SystemRolePath .\Sample_OIM_system_roles.csv

# Last use added to an access list
..\scripts\Join-LastAccess.ps1 -AccessPath .\lastaccess\FS01_who_can_access.csv -StorePath .\lastaccess\store -FileServer FS01
```

`..\dev\Test-Sample.ps1` rebuilds everything in `lastaccess\` from synthetic Security logs. See [docs/last-access.md](../docs/last-access.md).

Group members, teams and the account flags come from Active Directory (`-IncludeGroupMembers`), and these sample accounts don't exist in your domain. To see the full experience with members, teams and flags, open the [demo page](../docs/demo/index.html). It was built from these files with a simulated directory. You can also [view it online](https://zanderzone2030.github.io/IVIP_FileShare/demo/).
