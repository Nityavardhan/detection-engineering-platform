# Detection Card — T1078 Valid Accounts

## Overview
| Field | Value |
|-------|-------|
| Technique ID | T1078 |
| Name | Valid Accounts |
| Tactic | Defense Evasion, Persistence, Privilege Escalation, Initial Access |
| Severity | HIGH |
| False Positive Risk | MEDIUM |
| Data Sources | Security Log (EID 4624, 4648, 4672), Domain Controller Logs |

## What Are We Detecting?
Abuse of valid user credentials to access systems while blending in as legitimate activity. This is a behavioral detection focused on anomalous logon patterns — unusual source hosts, unusual times, special privilege assignment to unexpected accounts, or logon types inconsistent with user role.

## Expected Windows Event IDs
| Event ID | Channel | Field of Interest | What It Shows |
|----------|---------|-------------------|---------------|
| 4624 | Security | LogonType, WorkstationName, IpAddress | Successful logon with source details |
| 4648 | Security | TargetUserName, TargetServerName | Explicit credential use (RunAs) |
| 4672 | Security | SubjectUserName, PrivilegeList | Special privilege assigned at logon |
| 4625 | Security | TargetUserName, Status | Failed logon (pre-compromise indicator) |

## Sigma Rules Applied
- `valid_account_abuse.yml` — Detects special privilege assignment to non-system accounts

## Detection Logic
```
IF event_id = 4672 (Special Privilege Assigned)
  AND subject_user NOT ENDS_WITH "$" (not a machine account)
  AND subject_user NOT IN ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]
THEN → ALERT: Valid Account with Special Privileges (MEDIUM)

CORRELATE WITH:
  IF event_id = 4624 AND logon_type = 3
  AND source_workstation NOT IN [known_management_hosts]
THEN → ESCALATE to HIGH
```

## Atomic Red Team Test
- **T1078 Test #1**: Create local account and use for logon
- **T1078 Test #2**: Use domain account credentials from unexpected host

## Evasion Variants to Know
1. **Credential stuffing**: Using credentials from data breaches for initial access
2. **Token impersonation**: Using stolen tokens instead of passwords (no EID 4624)
3. **Pass-the-hash**: Using NTLM hashes directly (EID 4624 but NtlmV2 in AuthPackage)
4. **Golden ticket**: Forged Kerberos tickets (EID 4769 with unusual service names)
5. **Silver ticket**: Forged service tickets targeting specific services

## Known Threat Groups
APT29, APT28, FIN7, Lazarus Group, Sandworm Team, Turla, Carbanak

## References
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)
- [Atomic Red Team T1078](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078/T1078.md)
