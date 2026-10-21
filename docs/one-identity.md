# One Identity Manager inputs

`New-PermissionGraph.ps1` can overlay three exports from One Identity Manager. All three are optional and independent.

| Parameter | What it adds |
|---|---|
| `-BusinessRolePath` | Business roles (Org) and the AD groups they assign |
| `-SystemRolePath` | System roles (ESet) and the AD groups they contain |
| `-TeamPath` | The department table: which team and location each person belongs to |

**File rules, for all three:**

- Separator: comma, semicolon or tab. It is detected from the header line.
- Encoding: UTF-8 with or without a byte-order mark, UTF-16 with a byte-order mark, or ANSI (the Windows code page, as Excel saves "CSV"). It is detected from the file.
- Columns: only the columns listed below are read. Other columns are ignored.

The script prints which columns it used and how many rows matched something in the scan. If a required column is missing, it stops and lists the columns it found.

## Business roles (Org)

One row per role and group.

| Column | Content |
|---|---|
| `Ident_Org` | The business role |
| `cn` | The common name of the AD group |

```csv
Ident_Org;cn
Contrôleurs de gestion;GG-Finance-Team
Contrôleurs de gestion;GG-Shares-RW
HR Business Partners;GG-HR-RW
```

If your export uses different headers, name them with `-BusinessRoleNameColumn` and `-BusinessRoleGroupColumn`.

## System roles (ESet)

One row per role and group.

| Column | Content |
|---|---|
| `DisplayName` | The system role |
| `cn` | The common name of the AD group |

```csv
DisplayName;cn
FS Shares Write;GG-Shares-RW
FS Old Projects;GG-Projects-Old
```

If your export uses different headers, name them with `-SystemRoleNameColumn` and `-SystemRoleGroupColumn`.

### How groups are matched

The group value is reduced to the bare group name and compared without regard to case. All of these forms match the group `GG-Shares-RW`:

- `GG-Shares-RW`
- `CORP\GG-Shares-RW`
- `CN=GG-Shares-RW,OU=Groups,DC=corp,DC=local`
- `GG-Shares-RW@corp.local`

A cell may hold several groups, separated by line breaks or `|`. With `-IncludeGroupMembers`, groups are matched against AD, so a role that assigns a group nested inside a group on the ACL is linked too. Without it, groups are matched against the identities in the scan.

The script reports how many roles assign groups used on the scanned folders, and how many groups in the file are not related to these folders.

## Teams (department table)

One row per person.

| Column | Content | Required |
|---|---|---|
| `SAMAccountName` | The person's AD account | yes |
| `DepartmentName` | The team | yes |
| `FullPath` | The team's full path in the organisation | no |
| `LocationCode` | The location code, for example `CH1` or `ES1` | no |

```csv
SAMAccountName;DepartmentName;FullPath;LocationCode
fin.user01;Controlling;Company X\Finance\Controlling;CH1
fin.user21;Accounting;Company X\Finance\Accounting;ES1
hr-lead;HR Operations;Company X\Human Resources\HR Operations;CH1
```

**Alternative headers.** When the default headers are not in the file, these common alternatives are recognised:

| Column | Alternatives |
|---|---|
| Account | `CentralAccount`, `AccountName`, `Account`, `UserName`, `Login` |
| Team | `Department`, `TeamName`, `Team`, `Ident_Department`, `Name` |
| Full path | `TeamPath`, `DepartmentPath`, `TeamFullPath`, `Path` |
| Location | `Location`, `Ident_Locality`, `Locality`, `Site`, `SiteCode` |

Any other names can be set with `-TeamAccountColumn`, `-TeamNameColumn`, `-TeamFullPathColumn` and `-TeamLocationColumn`.

### Matching rules

- Account values may be written as `jdoe`, `CORP\jdoe` or `jdoe@corp.local`. They are reduced to `jdoe` and compared without regard to case.
- A team is identified by its full path, or by its name when the path is empty. Two teams with the same name in different branches stay separate.
- When an account is listed more than once, the first row wins and the script warns.
- People are matched to:
  - the accounts read from AD with `-IncludeGroupMembers`, which includes every member of every group on the ACLs, at any depth;
  - accounts set directly on folders.

  Without `-IncludeGroupMembers`, only people with their own entries can be matched.
- Only the teams and locations that match someone are written to the page.

### How team access is computed

For each folder, every Allow entry, explicit and inherited, is expanded to the people it covers:

- a group entry covers all of its members, at any nesting depth;
- an account entry covers that account.

The people are then grouped by team. Each team shows:

- its location codes;
- the number of people;
- the highest access level any of them gets;
- the groups (or own entries) the access comes through.

Some principals put practically everyone on the folder: Everyone, Authenticated Users, Domain Users, Domain Computers, BUILTIN\Users, and any group that contains one of them. Their access is listed separately as "open to everyone" and is not counted per team. Otherwise every team would appear on every folder. Deny entries are mentioned but not subtracted.

The Teams tab works in the other direction. For a team or a location, it collects the identities on the ACLs that give its people access, then highlights every folder those identities reach, through explicit entries and inheritance.
