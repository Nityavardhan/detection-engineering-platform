# Detection Card — T1218.011 Rundll32

## Overview
| Field | Value |
|-------|-------|
| Technique ID | T1218.011 |
| Name | System Binary Proxy Execution: Rundll32 |
| Tactic | Defense Evasion |
| Severity | HIGH |
| False Positive Risk | LOW |
| Data Sources | Sysmon (EID 1, EID 3), Security Log (EID 4688) |

## What Are We Detecting?
Abuse of rundll32.exe to proxy execution of malicious code. Detection focuses on: rundll32 spawning cmd/powershell, rundll32 executing JavaScript/VBScript, and rundll32 making network connections (C2 beaconing).

## Expected Windows Event IDs
| Event ID | Channel | Field of Interest | What It Shows |
|----------|---------|-------------------|---------------|
| 1 (Sysmon) | Sysmon Operational | CommandLine, ParentImage, Image | Rundll32 execution with DLL arguments |
| 3 (Sysmon) | Sysmon Operational | Image, DestinationIp, DestinationPort | Network connections from rundll32 |

## Sigma Rules Applied
- `rundll32_lolbin_abuse.yml` — Detects rundll32 spawning shells or executing scripts

## Detection Logic
```
IF parent_image ENDS_WITH "\rundll32.exe"
  AND child_image IN ["\cmd.exe", "\powershell.exe", "\wscript.exe"]
THEN → ALERT: Rundll32 Spawning Shell (HIGH)

IF image ENDS_WITH "\rundll32.exe"
  AND command_line CONTAINS ["javascript:", "vbscript:"]
THEN → ALERT: Rundll32 Script Execution (HIGH)
```

## Atomic Red Team Test
- **T1218.011 Test #1**: Rundll32 execute JavaScript
- **T1218.011 Test #2**: Rundll32 execute VBScript
- **T1218.011 Test #3**: Rundll32 advpack.dll LaunchINFSection

## Evasion Variants to Know
1. **DLL side-loading**: Placing malicious DLL in a directory where a trusted app loads it
2. **Obfuscated entry points**: Using obscure DLL export functions
3. **Renamed rundll32**: Copying rundll32 to avoid process name detection
4. **Inline base64 payload**: Encoding the command within the DLL argument

## Known Threat Groups
APT29, Lazarus Group, FIN7, Cobalt Group, MuddyWater, Turla

## References
- [MITRE ATT&CK T1218.011](https://attack.mitre.org/techniques/T1218/011/)
- [LOLBAS Rundll32](https://lolbas-project.github.io/lolbas/Binaries/Rundll32/)
