# Detection Card — T1021.002 SMB/Windows Admin Shares

## Overview
| Field | Value |
|-------|-------|
| Technique ID | T1021.002 |
| Name | Remote Services: SMB/Windows Admin Shares |
| Tactic | Lateral Movement |
| Severity | HIGH |
| False Positive Risk | MEDIUM |
| Data Sources | Security Log (EID 5140, 5145, 4624 type 3) |

## What Are We Detecting?
Access to administrative SMB shares (C$, ADMIN$, IPC$) from non-management workstations. This is a primary lateral movement mechanism where attackers use stolen credentials to access file systems and execute code on remote hosts.

## Expected Windows Event IDs
| Event ID | Channel | Field of Interest | What It Shows |
|----------|---------|-------------------|---------------|
| 5140 | Security | ShareName, SubjectUserName, IpAddress | Network share object accessed |
| 5145 | Security | RelativeTargetName, ShareName | Detailed share object access (specific files) |
| 4624 | Security | LogonType (3), WorkstationName | Network logon on destination host |
| 7045 | System | ServiceName, ImagePath | New service created (PsExec indicator) |

## Sigma Rules Applied
- `smb_admin_share_access.yml` — Detects access to C$, ADMIN$, IPC$ shares

## Detection Logic
```
IF event_id = 5140
  AND share_name CONTAINS any of ["\C$", "\ADMIN$", "\IPC$"]
  AND subject_user NOT ENDS_WITH "$"
THEN → ALERT: Admin Share Access (MEDIUM)

CORRELATION: If source_ip NOT IN [management_workstation_list]
THEN → ESCALATE to HIGH: Lateral Movement via Admin Shares
```

## Atomic Red Team Test
- **T1021.002 Test #1**: Map admin share using net use
- **T1021.002 Test #2**: Copy file to admin share

## Evasion Variants to Know
1. **WMI lateral movement**: Using WMI instead of SMB for remote execution
2. **WinRM**: Using Windows Remote Management protocol instead of SMB
3. **Named pipes**: Using SMB named pipes for C2 instead of admin shares
4. **PSExec variants**: Using legitimate tools that use admin shares internally

## Known Threat Groups
APT29, Lazarus Group, Wizard Spider, Sandworm Team, FIN7, Ryuk/Conti operators

## References
- [MITRE ATT&CK T1021.002](https://attack.mitre.org/techniques/T1021/002/)
- [Atomic Red Team T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md)
