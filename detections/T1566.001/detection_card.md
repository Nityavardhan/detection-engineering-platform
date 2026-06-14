# Detection Card — T1566.001 Spearphishing Attachment

## Overview
| Field | Value |
|-------|-------|
| Technique ID | T1566.001 |
| Name | Phishing: Spearphishing Attachment |
| Tactic | Initial Access |
| Severity | CRITICAL |
| False Positive Risk | LOW |
| Data Sources | Sysmon (EID 1, EID 3), Email Gateway Logs |

## What Are We Detecting?
Microsoft Office applications (WINWORD, EXCEL, OUTLOOK) spawning command shell processes (cmd.exe, powershell.exe, wscript.exe). This parent-child relationship is a near-zero false positive indicator of successful malicious macro execution from a spearphishing attachment.

## Expected Windows Event IDs
| Event ID | Channel | Field of Interest | What It Shows |
|----------|---------|-------------------|---------------|
| 1 (Sysmon) | Sysmon Operational | ParentImage, Image, CommandLine | Office → shell process creation chain |
| 3 (Sysmon) | Sysmon Operational | Image, DestinationIp | Network connection from Office (C2/download) |
| 11 (Sysmon) | Sysmon Operational | TargetFilename, Image | Files dropped by the macro |

## Sigma Rules Applied
- `office_spawning_shell.yml` — Detects Office application spawning command shells

## Detection Logic
```
IF parent_image ENDS_WITH any of
  ["\WINWORD.EXE", "\EXCEL.EXE", "\OUTLOOK.EXE", "\POWERPNT.EXE"]
  AND child_image ENDS_WITH any of
  ["\cmd.exe", "\powershell.exe", "\wscript.exe", "\cscript.exe", "\mshta.exe"]
THEN → ALERT: CRITICAL — Office Spawning Shell (Phishing Execution)
```

## Atomic Red Team Test
- **T1566.001 Test #1**: Download macro-enabled document simulation
- **T1566.001 Test #2**: Office spawning PowerShell via macro

## Evasion Variants to Know
1. **Macro-free exploitation**: Using DDE (Dynamic Data Exchange) instead of VBA macros
2. **Template injection**: Document loads malicious template from remote URL
3. **ISO/IMG containers**: Bypassing Mark-of-the-Web by embedding documents in disk images
4. **OneNote attachments**: Using .one files with embedded scripts (2023+ technique)
5. **HTML smuggling**: Embedding encoded payload in HTML email body

## Known Threat Groups
APT29, APT28, Lazarus Group, FIN7, Gamaredon, Kimsuky, MuddyWater, OilRig

## References
- [MITRE ATT&CK T1566.001](https://attack.mitre.org/techniques/T1566/001/)
- [Atomic Red Team T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md)
