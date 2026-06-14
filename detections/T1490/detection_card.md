# Detection Card — T1490 Inhibit System Recovery

## Overview
| Field | Value |
|-------|-------|
| Technique ID | T1490 |
| Name | Inhibit System Recovery |
| Tactic | Impact |
| Severity | CRITICAL |
| False Positive Risk | VERY_LOW |
| Data Sources | Sysmon (EID 1), Process Creation Logs |

## What Are We Detecting?
Deletion of Volume Shadow Copies (`vssadmin delete shadows`), WMIC shadow copy deletion, or disabling Windows recovery via `bcdedit`. These are pre-encryption steps executed by virtually every ransomware variant.

## Expected Windows Event IDs
| Event ID | Channel | Field of Interest | What It Shows |
|----------|---------|-------------------|---------------|
| 1 (Sysmon) | Sysmon Operational | Image, CommandLine | vssadmin/wmic/bcdedit execution |
| 4688 | Security | NewProcessName, CommandLine | Process creation with recovery deletion |

## Sigma Rules Applied
- `vssadmin_delete_shadows.yml` — Detects VSS/recovery deletion commands

## Detection Logic
```
IF (image ENDS_WITH "\vssadmin.exe" AND command_line CONTAINS "delete" AND "shadows")
  OR (image ENDS_WITH "\wmic.exe" AND command_line CONTAINS "shadowcopy" AND "delete")
  OR (image ENDS_WITH "\bcdedit.exe" AND command_line CONTAINS "recoveryenabled no")
THEN → ALERT: CRITICAL — System Recovery Inhibited (Ransomware Indicator)
```

## Atomic Red Team Test
- **T1490 Test #1**: Delete Volume Shadow Copies via vssadmin
- **T1490 Test #2**: Delete Shadow Copies via WMIC
- **T1490 Test #3**: Disable Windows Recovery via bcdedit

## Evasion Variants to Know
1. **PowerShell WMI**: Using Get-WmiObject to delete shadow copies without vssadmin
2. **COM objects**: Using the VSS COM API directly to delete shadows
3. **Scheduled deletion**: Scheduling VSS deletion for a future time
4. **Renamed utilities**: Copying vssadmin.exe to avoid process name detection

## Known Threat Groups
Wizard Spider (Ryuk/Conti), LockBit, REvil, DarkSide, BlackCat, WannaCry, Lazarus

## References
- [MITRE ATT&CK T1490](https://attack.mitre.org/techniques/T1490/)
- [Atomic Red Team T1490](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md)
