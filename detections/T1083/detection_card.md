# Detection Card — T1083 File and Directory Discovery

## Overview
| Field | Value |
|-------|-------|
| Technique ID | T1083 |
| Name | File and Directory Discovery |
| Tactic | Discovery |
| Severity | MEDIUM |
| False Positive Risk | MEDIUM |
| Data Sources | Sysmon (EID 1), Security Log (EID 4663), PowerShell Operational (EID 4104) |

## What Are We Detecting?
Execution of file and directory enumeration commands (`dir /s`, `tree`, `Get-ChildItem -Recurse`) that indicate post-compromise reconnaissance. Focus is on recursive scans of sensitive directories.

## Expected Windows Event IDs
| Event ID | Channel | Field of Interest | What It Shows |
|----------|---------|-------------------|---------------|
| 1 (Sysmon) | Sysmon Operational | Image, CommandLine | Discovery command execution |
| 4663 | Security | ObjectName, ProcessName | File access following discovery |
| 4104 | PowerShell Operational | ScriptBlockText | PowerShell discovery commands |

## Sigma Rules Applied
- `file_directory_discovery.yml` — Detects common file discovery commands with recursive flags

## Detection Logic
```
IF (image ENDS_WITH "\cmd.exe" AND command_line CONTAINS "dir /s")
  OR image ENDS_WITH "\tree.com"
  OR (image ENDS_WITH "\powershell.exe" AND command_line CONTAINS "Get-ChildItem")
THEN → ALERT: File Discovery Activity (MEDIUM)
```

## Atomic Red Team Test
- **T1083 Test #1**: File and directory discovery via cmd
- **T1083 Test #2**: File and directory discovery via PowerShell

## Evasion Variants to Know
1. **WMI queries**: Using WMI to enumerate files without spawning discovery commands
2. **API calls**: Direct Win32 API (FindFirstFile/FindNextFile) without command-line footprint
3. **PowerShell remoting**: Executing discovery on remote hosts via Invoke-Command
4. **.NET methods**: Using System.IO.Directory.GetFiles() in memory-only scripts

## Known Threat Groups
APT29, FIN7, Lazarus Group, APT28, Turla (virtually all post-exploitation)

## References
- [MITRE ATT&CK T1083](https://attack.mitre.org/techniques/T1083/)
- [Atomic Red Team T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md)
