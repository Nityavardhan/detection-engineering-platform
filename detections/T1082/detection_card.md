# Detection Card — T1082 System Information Discovery

## Overview
| Field | Value |
|-------|-------|
| Technique ID | T1082 |
| Name | System Information Discovery |
| Tactic | Discovery |
| Severity | MEDIUM |
| False Positive Risk | MEDIUM |
| Data Sources | Sysmon (EID 1), Security Log (EID 4688) |

## What Are We Detecting?
Execution of system discovery commands (`systeminfo`, `whoami`, `hostname`, `ipconfig`, `net`) particularly when multiple commands are executed in rapid succession from the same parent process, indicating automated post-compromise enumeration.

## Expected Windows Event IDs
| Event ID | Channel | Field of Interest | What It Shows |
|----------|---------|-------------------|---------------|
| 1 (Sysmon) | Sysmon Operational | Image, CommandLine, ParentImage | Discovery command execution with parent chain |
| 4688 | Security | NewProcessName, CommandLine | Process creation with command line |

## Sigma Rules Applied
- `system_info_discovery.yml` — Detects execution of common system recon commands

## Detection Logic
```
IF image ENDS_WITH any of:
  ["\systeminfo.exe", "\whoami.exe", "\hostname.exe",
   "\ipconfig.exe", "\net.exe", "\nltest.exe"]
THEN → BASE SIGNAL (MEDIUM)

CORRELATION: If 3+ distinct discovery commands share same parent_process_id
             within 60 seconds → ESCALATE to HIGH
```

## Atomic Red Team Test
- **T1082 Test #1**: System Information Discovery via systeminfo
- **T1082 Test #2**: System Information via PowerShell Get-ComputerInfo

## Evasion Variants to Know
1. **WMI queries**: Using WMI (wmic os get) instead of command-line tools
2. **PowerShell cmdlets**: Get-ComputerInfo, Get-NetAdapter, Get-ADDomain
3. **Registry reads**: Directly reading HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
4. **.NET methods**: System.Environment class properties (MachineName, OSVersion)

## Known Threat Groups
APT29, APT28, Lazarus Group, FIN7, Turla (virtually all threat groups)

## References
- [MITRE ATT&CK T1082](https://attack.mitre.org/techniques/T1082/)
- [Atomic Red Team T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md)
