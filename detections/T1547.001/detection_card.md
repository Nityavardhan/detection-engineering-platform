# Detection Card — T1547.001 Registry Run Keys / Startup Folder

## Overview
| Field | Value |
|-------|-------|
| Technique ID | T1547.001 |
| Name | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| Tactic | Persistence |
| Severity | HIGH |
| False Positive Risk | LOW |
| Data Sources | Sysmon (EID 13 — RegistryValueSet), Security Log (EID 4657) |

## What Are We Detecting?
Modification of Windows Registry Run and RunOnce keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and HKLM equivalent) used to establish persistence. Any non-installer process writing to these keys is suspicious.

## Expected Windows Event IDs
| Event ID | Channel | Field of Interest | What It Shows |
|----------|---------|-------------------|---------------|
| 13 (Sysmon) | Sysmon Operational | TargetObject, Details, Image | Registry value set with path, value, and writing process |
| 4657 | Security | ObjectName, ProcessName | Registry value modified (requires SACL configuration) |

## Sigma Rules Applied
- `registry_run_key_persistence.yml` — Detects writes to Run/RunOnce registry keys

## Detection Logic
```
IF registry_event_type = "SetValue"
  AND target_object CONTAINS "\CurrentVersion\Run"
  AND image NOT IN [known_installers]
THEN → ALERT: Registry Run Key Persistence (HIGH)
```

## Atomic Red Team Test
- **T1547.001 Test #1**: Reg Key Run — Adds entry to HKCU Run key
- **T1547.001 Test #2**: Reg Key RunOnce — Adds entry to HKCU RunOnce

## Evasion Variants to Know
1. **Indirect registry write**: Using `reg.exe` or WMI instead of direct API calls
2. **Less-monitored keys**: RunServices, Explorer\Run, Winlogon\Shell
3. **HKLM vs HKCU**: HKLM requires admin but survives user profile deletion
4. **Startup folder**: Placing shortcuts in shell:startup instead of registry
5. **Registry symlinks**: Creating junction points to redirect Run key reads

## Known Threat Groups
APT29, APT28, Lazarus Group, FIN7, Turla, Kimsuky, DarkHotel

## References
- [MITRE ATT&CK T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [Atomic Red Team T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md)
