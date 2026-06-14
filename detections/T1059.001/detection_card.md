# Detection Card — T1059.001 PowerShell

## Overview
| Field | Value |
|-------|-------|
| Technique ID | T1059.001 |
| Name | Command and Scripting Interpreter: PowerShell |
| Tactic | Execution |
| Severity | HIGH |
| False Positive Risk | LOW |
| Data Sources | PowerShell Operational Log (EID 4104), Sysmon (EID 1), Security Log (EID 4688) |

## What Are We Detecting?
Execution of PowerShell with Base64-encoded commands via the `-EncodedCommand` parameter, as well as suspicious parameter combinations (`-WindowStyle Hidden`, `-ExecutionPolicy Bypass`, download cradles). Encoded commands are the single most common PowerShell obfuscation method used by threat actors, ranging from commodity malware to APT groups.

## Expected Windows Event IDs
| Event ID | Channel | Field of Interest | What It Shows |
|----------|---------|-------------------|---------------|
| 4104 | PowerShell Operational | ScriptBlockText | Decoded script content after AMSI inspection |
| 4688 | Security | CommandLine | Process creation with full command line arguments |
| 1 (Sysmon) | Sysmon Operational | CommandLine, ParentImage | Process creation with parent-child relationship |
| 3 (Sysmon) | Sysmon Operational | DestinationIp, DestinationPort | Network connections from PowerShell (C2 indicator) |

## Sigma Rules Applied
- `powershell_encoded_cmd.yml` — Detects `-EncodedCommand` / `-enc` in the command line
- `powershell_suspicious_params.yml` — Detects suspicious parameter combinations and download cradles

## Detection Logic
```
IF (process_name ENDS_WITH "powershell.exe" OR "pwsh.exe")
  AND (command_line CONTAINS "-EncodedCommand" OR "-enc" OR "-ec")
THEN → ALERT: Encoded PowerShell Execution (HIGH)

IF (process_name ENDS_WITH "powershell.exe" OR "pwsh.exe")
  AND (command_line CONTAINS "-WindowStyle Hidden" OR "-ExecutionPolicy Bypass")
  AND (command_line CONTAINS "Invoke-WebRequest" OR "DownloadString" OR "IEX")
THEN → ALERT: Suspicious PowerShell Download Cradle (HIGH)
```

## Atomic Red Team Test
- **T1059.001 Test #1**: Mimikatz download cradle — Downloads and executes script via IEX
- **T1059.001 Test #2**: Encoded command execution — Runs base64-encoded whoami via -EncodedCommand
- **T1059.001 Test #3**: PowerShell with BloodHound — Encoded PS used for AD enumeration

## Evasion Variants to Know
1. **String concatenation**: `-E` + `ncodedCommand` split across variables to avoid static string matching
2. **Environment variable abuse**: Storing encoded command in env var, then calling `powershell $env:cmd`
3. **AMSI bypass**: `[Ref].Assembly.GetType()` reflection to disable AMSI before execution
4. **PowerShell v2 downgrade**: `powershell -Version 2` bypasses Script Block Logging entirely
5. **Alternate encoding**: Using UTF-16LE or compressed streams instead of standard Base64
6. **Living-off-the-land**: Using `mshta.exe` or `wscript.exe` to launch PowerShell indirectly

## Known Threat Groups
APT29, APT28, Lazarus Group, FIN7, Cobalt Group, Turla, Wizard Spider, Carbanak, MuddyWater

## References
- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Atomic Red Team T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md)
