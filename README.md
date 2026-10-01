```
     _    ____  _____
    / \  |  _ \| ____|_ __  _   _ _ __ ___
   / _ \ | | | |  _| | '_ \| | | | '_ ` _ \
  / ___ \| |_| | |___| | | | |_| | | | | | |
 /_/   \_\____/|_____|_| |_|\__,_|_| |_| |_|
```

# ADEnum

Windows & Active Directory enumeration module. Single PowerShell script — no dependencies, no RSAT, no external modules. Runs native LDAP queries and outputs a self-contained HTML report with JSON data.

## Features

**Local Enumeration**
- System info, local users, local administrators
- Network shares, established connections
- Services with non-default RunAs (flags unquoted paths)
- Scheduled tasks (non-Microsoft)
- AV/EDR detection (products, security services, EDR processes)

**Active Directory Enumeration**
- Domain context, forest info, FSMO roles, domain trusts
- All domain users with group membership, logon history, password age
- Privileged accounts (Domain Admins, Enterprise Admins, Schema Admins, etc.)
- Domain computers, domain controllers, OU structure
- Groups, GPOs, DNS records

**Security Checks**
- Credentials in AD object descriptions (regex-based detection)
- Kerberoastable accounts (users with SPNs)
- AS-REP roastable accounts (no pre-authentication)
- Unconstrained & constrained delegation (flags protocol transition)
- Password policy audit (min length, lockout, complexity)
- Inactive accounts (90+ days, still enabled)
- Accounts with password never expires
- Machine account quota (RBCD attack vector)
- LAPS deployment & readability
- GPP passwords in SYSVOL (MS14-025)
- Unquoted service paths

## Requirements

- PowerShell 5.1+
- Domain-joined machine (for AD enumeration; local enum works standalone)
- No admin required (runs with current user privileges; admin unlocks more data)

## Usage

```powershell
# Load the module
Import-Module .\ADEnum.ps1

# Full enumeration — local + AD + security checks
Invoke-FullEnum

# Skip AD enumeration (local only)
Invoke-FullEnum -SkipDomain

# Enumerate shares on all domain machines
Invoke-FullEnum -ScanAllShares

# Show all available functions
Get-ADEnumHelp
```

Individual functions can be called standalone after running `Initialize-ADEnum`:

```powershell
Initialize-ADEnum
Get-KerberoastableAccounts
Get-PasswordPolicy
Get-UnconstrainedDelegation
```

## Output

Results are saved to `./ADEnum_Results/`:

| File | Description |
|------|-------------|
| `ADEnum_<domain>_<timestamp>.json` | Structured JSON with all collected data |
| `ADEnum_<domain>_<timestamp>.html` | Self-contained HTML report (dark theme, filterable tables, copy-to-clipboard) |

The HTML report includes:
- Summary dashboard (user count, machines, privileged accounts, findings)
- Severity-ranked findings panel
- Filterable/searchable tables for every data category
- One-click copy for usernames, hostnames, IPs

## Available Functions

| Function | Description |
|----------|-------------|
| `Get-SystemInfo` | OS, hostname, domain, admin status |
| `Get-DomainContext` | Domain/forest info, DCs, FSMO roles |
| `Get-LocalUsersEnum` | Local user accounts |
| `Get-LocalAdmins` | Local Administrators group members |
| `Get-DomainUsersLDAP` | All domain users via LDAP |
| `Get-DomainAdmins` | Members of all privileged groups |
| `Get-SensitiveDescriptions` | Credentials in AD descriptions |
| `Get-InactiveAccounts` | Accounts inactive 90+ days |
| `Get-NeverExpirePasswords` | Accounts with non-expiring passwords |
| `Get-KerberoastableAccounts` | Users with SPNs set |
| `Get-ASREPRoastableAccounts` | Accounts without pre-auth |
| `Get-DomainComputers` | All domain computers |
| `Get-DomainControllers` | Domain controllers |
| `Get-DomainGroupsEnum` | All domain groups |
| `Get-OUStructure` | Organizational units |
| `Get-PasswordPolicy` | Domain password policy |
| `Get-GPOInfo` | Group Policy Objects |
| `Get-DomainTrusts` | Domain trust relationships |
| `Get-DNSRecords` | DNS records via LDAP |
| `Get-UnconstrainedDelegation` | Unconstrained delegation objects |
| `Get-ConstrainedDelegation` | Constrained delegation + protocol transition |
| `Get-MachineAccountQuota` | ms-DS-MachineAccountQuota value |
| `Get-LAPSStatus` | LAPS deployment and readability |
| `Get-GPPPasswords` | GPP cpassword in SYSVOL |
| `Get-AVStatus` | AV products, security services, EDR |
| `Get-NetworkShares` | Network shares |
| `Get-NetConnections` | Established TCP connections |
| `Get-InterestingServices` | Services with custom RunAs |
| `Get-ScheduledTasksEnum` | Non-Microsoft scheduled tasks |

## Disclaimer

This tool is intended for authorized security assessments and penetration testing engagements only. Always obtain proper authorization before running enumeration tools against any network or system. Unauthorized use may violate applicable laws.
