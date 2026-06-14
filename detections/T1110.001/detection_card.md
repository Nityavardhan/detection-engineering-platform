# Detection Card — T1110.001 Password Spraying

## Overview
| Field | Value |
|-------|-------|
| Technique ID | T1110.001 |
| Name | Brute Force: Password Spraying |
| Tactic | Credential Access |
| Severity | HIGH |
| False Positive Risk | MEDIUM |
| Data Sources | Security Log (EID 4625, 4624), Domain Controller Logs |

## What Are We Detecting?
Multiple failed logon attempts (EID 4625 with Status 0xC000006A) from the same source IP targeting different user accounts within a short time window. This pattern indicates a password spray attack where one or two passwords are tried against many accounts to stay below lockout thresholds.

## Expected Windows Event IDs
| Event ID | Channel | Field of Interest | What It Shows |
|----------|---------|-------------------|---------------|
| 4625 | Security | TargetUserName, IpAddress, Status | Failed logon with source and reason |
| 4624 | Security | TargetUserName, IpAddress, LogonType | Successful logon (spray succeeded) |
| 4771 | Security | TargetUserName, IpAddress | Kerberos pre-authentication failure |

## Sigma Rules Applied
- `password_spray_detection.yml` — Detects failed logon events indicative of spraying

## Detection Logic
```
IF event_id = 4625
  AND status = "0xC000006A" (wrong password)
  AND target_user NOT ENDS_WITH "$"
THEN → BASE SIGNAL (MEDIUM)

SIEM CORRELATION:
  IF count(DISTINCT target_user) > 10
  FROM same ip_address
  WITHIN 30 minutes
THEN → ALERT: Password Spraying Detected (HIGH)
```

**Note:** Full detection fidelity requires SIEM temporal correlation. The Sigma rule provides the base signal; threshold-based alerting must be configured in the SIEM.

## Atomic Red Team Test
- **T1110.001 Test #1**: Password spray with multiple failed logons using net use

## Evasion Variants to Know
1. **Slow spray**: One attempt per account per hour to stay below detection thresholds
2. **Distributed sources**: Spraying from multiple IP addresses
3. **Targeting cloud-first**: Spraying against Azure AD / O365 instead of on-prem AD
4. **Protocol variation**: Spraying via LDAP, Kerberos, SMB, or HTTP separately
5. **Off-hours spraying**: Targeting accounts during non-business hours

## Known Threat Groups
APT28, APT33, APT34, MuddyWater, Phosphorus

## References
- [MITRE ATT&CK T1110.001](https://attack.mitre.org/techniques/T1110/001/)
- [Atomic Red Team T1110.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.001/T1110.001.md)
