# Checks and flags

There are two layers of checks:

- **Findings** come from `Find-PermissionIssues.ps1`. They work from the scan CSV alone, and two of them use AD when it is reachable.
- **Flags** come from `New-PermissionGraph.ps1`. They need the AD group membership read with `-IncludeGroupMembers`.

## Findings (Find-PermissionIssues.ps1)

Each permission entry is reported **once, where it is set**: on the folder where it is explicit, or on the scanned top folder when it is inherited from above the scan. The `FoldersAffected` column counts the folders that inherit it, so one bad entry at the top of a share is one finding, not thousands.

| Id | Severity | Check | Why it matters |
|---|---|---|---|
| FP01 | Critical | Broad group can change permissions | Everyone, Authenticated Users, Domain Users, Users... with Full Control, Change Permissions or Take Ownership: any member can grant access to anyone. |
| FP02 | High | Broad group has write access | Every user can change or delete the data. |
| FP03 | Medium | Broad group has read access | Every user can read the data. Rated Low when the entry applies to "This folder only". |
| FP04 | Medium | Entry for an orphaned SID | The account was deleted, or its domain was unreachable during the scan. |
| FP05 | Medium | Permission granted directly to a user | The entry bypasses group-based access and can't be reviewed or revoked centrally. *Needs AD.* |
| FP06 | High | Non-admin has Full Control / Change Permissions / Take Ownership | The holder can grant access to anyone, bypassing the access request process. |
| FP07 | Medium | CREATOR OWNER has Full Control | Users can change permissions on everything they create. |
| FP08 | Low | Explicit Deny entry | Effective access becomes hard to predict and to review. |
| FP09 | Medium | Administrators / SYSTEM lack Full Control where inheritance is broken | Administrators must take ownership to recover access, and backup or antivirus may fail. |
| FP10 | Medium | Folder could not be read | The scan account had no access. Administrators may be locked out too. |
| FP11 | High | Empty or NULL DACL | A NULL DACL grants everyone full access; an empty one denies everyone except the owner. |
| FP12 | Medium | Owner is an orphaned SID | Nobody manages the folder through ownership. |
| FP13 | High | Owner is a broad group | The owner can always change permissions, so every member of the group can grant themselves access. |
| FP14 | Low | Folder owned by an individual user | The owner can change permissions regardless of the ACL. *Needs AD.* |
| FP15 | Info | Inheritance disabled | Undocumented breaks are where permissions drift away from the access model. |
| FP16 | Low | Explicit permissions set deep in the tree | Deep entries are hard to find and to review. The depth is set with `-MaxExplicitDepth` (default 3). |
| FP17 | Low | Too many explicit entries on one folder | The limit is set with `-MaxExplicitAces` (default 15). |
| FP18 | Low | Explicit entry that duplicates an inherited one | It adds nothing and hides the real access model. |

Names are matched in English, French and German, for example *Everyone / Tout le monde / Jeder* and *Domain Users / Utilisateurs du domaine / Domänen-Benutzer*.

The *Needs AD* checks classify accounts as user, group or computer through Active Directory. They run when the machine can reach a domain controller and are skipped, with a note in the report, otherwise or with `-SkipAccountLookup`.

Your own admin groups can be added with `-AdminIdentity 'CORP\FS-Admins'`. Identities to ignore entirely, such as a backup service account, go in `-ExcludeIdentity`. Both accept wildcards.

## Flags in the graph (New-PermissionGraph.ps1)

Red always means *fix this*, and yellow means *look at this*. Every list on the left (Identities, Issues, Roles, Teams) shows red items first, then yellow.

### Folders

| Flag | Rule |
|---|---|
| 🔴 **!** direct access | An individual account has its own Allow entry, with any rights, on a folder at one of the `-DirectAccessLevels` (default 0, 1, 2, 3; level 0 is the scanned folder). Individual accounts are users, service accounts, computers and accounts from trusted domains. **full control** is called out when the entry is Full Control. |
| 🟡 **E** external access | An external account can reach the folder: it is on the ACL itself, it is inside a group on the ACL (at any nesting depth), or the folder is open to Everyone / Authenticated Users while external accounts exist. |

### Accounts

| Flag | Rule |
|---|---|
| 🔴 direct access / full control | The account has the folder flag above on at least one folder. |
| 🟡 external | The account's AD distinguished name contains an OU or container matching `-ExternalOu` (default `Consultant Users`; several values allowed). |
| disabled, other domain, local, unresolved | Shown as neutral tags. |

### Groups

| Flag | Rule |
|---|---|
| 🔴 bad config | Any of: circular nesting (the group ends up as a member of itself); Everyone, Authenticated Users, Domain Users or Domain Computers inside a group that is not broad by design; disabled accounts still members; members that no longer resolve. |
| 🟡 empty | No members, or only groups that are empty themselves. Groups whose members could not be read, or were cut at the member limit, are never reported as empty. |
| 🟡 E external | The group contains external accounts at any nesting depth. |
| 🟣 nested | The group is a member of another group. Information, not a problem. |

Groups that are broad by design (Domain Users, BUILTIN\Users...) are not flagged for containing broad members.

### One Identity roles

| Flag | Rule |
|---|---|
| 🔴 bad config group | The role assigns a group with a bad config. |
| 🟡 empty group | The role assigns an empty group. |
| 🟡 externals | The role assigns a group that contains external accounts. |

### Teams

| Flag | Rule |
|---|---|
| 🔴 direct access | A person of the team has the direct-access flag. |
| 🟡 external | A person of the team who has access is an external account. |
