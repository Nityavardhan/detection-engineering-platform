# Detection Card — T1070.001 Clear Windows Event Logs

## Overview
| Field | Value |
|-------|-------|
| Technique ID | T1070.001 |
| Name | Indicator Removal: Clear Windows Event Logs |
| Tactic | Defense Evasion |
| Severity | CRITICAL |
| False Positive Risk | VERY_LOW |
| Data Sources | Security Log (EID 1102), System Log (EID 104), Sysmon (EID 1) |

## What Are We Detecting?
Clearing of Windows event logs via `wevtutil cl`, PowerShell `Clear-EventLog`, or any other method. EID 1102 fires when the Security log is cleared, and EID 104 fires when the System log is cleared. These events are generated at the moment of clearing — even if the attacker clears the log, the clearing event itself is recorded first.

## Expected Windows Event IDs
| Event ID | Channel | Field of Interest | What It Shows |
|----------|---------|-------------------|---------------|
| 1102 | Security | SubjectUserName, SubjectDomainName | Security log was cleared (who did it) |
| 104 | System | -- | System log was cleared |
| 1 (Sysmon) | Sysmon Operational | Image, CommandLine | wevtutil.exe or PowerShell execution |

## Sigma Rules Applied
- `event_log_cleared.yml` — Detects wevtutil cl and Clear-EventLog commands

## Detection Logic
```
IF event_id = 1102 (Security Log Cleared)
THEN → ALERT: CRITICAL — Event Log Cleared

IF image ENDS_WITH "\wevtutil.exe"
  AND command_line CONTAINS "cl" or "clear-log"
THEN → ALERT: CRITICAL — Log Clearing Command Detected
```

## Atomic Red Team Test
- **T1070.001 Test #1**: Clear event logs via wevtutil
- **T1070.001 Test #2**: Clear event logs via PowerShell

## Evasion Variants to Know
1. **Selective event deletion**: Using wevtutil to delete specific events instead of clearing entire log
2. **Direct registry manipulation**: Modifying log file paths in registry
3. **Timestomping**: Changing event timestamps instead of deleting
4. **Shadow log manipulation**: Attacking the log file directly on disk
5. **Thread injection into EventLog service**: Patching the service in memory

## Known Threat Groups
Lazarus Group, APT38, APT41, most ransomware operators

## References
- [MITRE ATT&CK T1070.001](https://attack.mitre.org/techniques/T1070/001/)
- [Atomic Red Team T1070.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md)
