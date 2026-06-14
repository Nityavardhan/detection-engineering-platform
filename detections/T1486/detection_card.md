# Detection Card — T1486 Data Encrypted for Impact

## Overview
| Field | Value |
|-------|-------|
| Technique ID | T1486 |
| Name | Data Encrypted for Impact |
| Tactic | Impact |
| Severity | CRITICAL |
| False Positive Risk | LOW |
| Data Sources | Sysmon (EID 11, EID 23), File System Activity, Process Creation |

## What Are We Detecting?
Mass file encryption activity indicative of ransomware execution. Detection focuses on high-volume FileCreate events with unusual extensions, creation of ransom notes, and use of legitimate encryption utilities in suspicious contexts.

## Expected Windows Event IDs
| Event ID | Channel | Field of Interest | What It Shows |
|----------|---------|-------------------|---------------|
| 11 (Sysmon) | Sysmon Operational | TargetFilename, Image | File created with new extension |
| 23 (Sysmon) | Sysmon Operational | TargetFilename, Image | Original file deleted after encryption |
| 1 (Sysmon) | Sysmon Operational | Image, CommandLine | Encrypting process execution |

## Sigma Rules Applied
- `ransomware_file_encryption.yml` — Detects ransomware indicators in process creation

## Detection Logic
```
IF command_line CONTAINS any of ["DECRYPT", "RECOVER", "ransom", ".locked", ".encrypted"]
  OR (image ENDS_WITH "\cipher.exe" AND command_line CONTAINS "/w:")
THEN → ALERT: CRITICAL — Potential Ransomware Activity
```

## Atomic Red Team Test
- **T1486 Test #1**: Encrypt files using Python script (simulated)

## Evasion Variants to Know
1. **Intermittent encryption**: Encrypting only portions of files to speed up the process
2. **Delayed encryption**: Using a time bomb to encrypt days after initial access
3. **Process injection**: Injecting encryption code into legitimate processes
4. **Remote encryption**: Encrypting files on network shares from a single compromised host

## Known Threat Groups
Wizard Spider (Ryuk/Conti), LockBit, BlackCat/ALPHV, REvil, DarkSide

## References
- [MITRE ATT&CK T1486](https://attack.mitre.org/techniques/T1486/)
- [Atomic Red Team T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md)
