# Samples

Synthetic data to try the scripts without a file share or a domain. Every name, group, team and SID in these files is made up.

| File | What it is | Used with |
|---|---|---|
| `SampleScan.csv` | A scan of a small share (`D:\Shares`, 11 folders), as written by `Get-FolderPermissions.ps1`. It contains broad groups, direct user grants, an orphaned SID, broken inheritance, a Deny entry, an unreadable folder and an external account. | all three scripts |
| `SampleScan_findings.csv` | The findings for that scan, as written by `Find-PermissionIssues.ps1` | `New-PermissionGraph.ps1 -FindingsPath` |
| `Sample_OIM_business_roles.csv` | Business roles (Org) and the AD groups they assign: `Ident_Org;cn` | `-BusinessRolePath` |
| `Sample_OIM_system_roles.csv` | System roles (ESet) and their AD groups: `DisplayName;cn` | `-SystemRolePath` |
| `Sample_OIM_departments.csv` | The department table: `SAMAccountName;DepartmentName;FullPath;LocationCode` | `-TeamPath` |

```powershell
# Findings report
..\scripts\Find-PermissionIssues.ps1 -Path .\SampleScan.csv -SkipAccountLookup

# Graph with findings and roles (no domain needed)
..\scripts\New-PermissionGraph.ps1 -Path .\SampleScan.csv -FindingsPath .\SampleScan_findings.csv `
    -BusinessRolePath .\Sample_OIM_business_roles.csv -SystemRolePath .\Sample_OIM_system_roles.csv
```

Group members, teams and the account flags come from Active Directory (`-IncludeGroupMembers`), and these sample accounts don't exist in your domain. To see the full experience with members, teams and flags, open the [demo page](../docs/demo/index.html). It was built from these files with a simulated directory. You can also [view it online](https://zanderzone2030.github.io/IVIP_FileShare/demo/).
