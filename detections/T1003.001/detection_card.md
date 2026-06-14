# Detection Card — T1003.001 LSASS Memory

## Overview
| Field | Value |
|-------|-------|
| Technique ID | T1003.001 |
| Name | OS Credential Dumping: LSASS Memory |
| Tactic | Credential Access |
| Severity | CRITICAL |
| False Positive Risk | LOW |
| Data Sources | Sysmon (EID 10 — ProcessAccess), Security Log (EID 4656, 4663) |

## What Are We Detecting?
Any non-Windows-system process accessing the LSASS (Local Security Authority Subsystem Service) memory space with access masks that indicate credential dumping. LSASS stores NTLM hashes, Kerberos tickets, and in some cases cleartext passwords in memory.

## Expected Windows Event IDs
| Event ID | Channel | Field of Interest | What It Shows |
|----------|---------|-------------------|---------------|
| 10 (Sysmon) | Sysmon Operational | SourceImage, TargetImage, GrantedAccess | Process accessing another process's memory |
| 4656 | Security | ObjectName, ProcessName, AccessMask | Handle request to LSASS object |
| 1 (Sysmon) | Sysmon Operational | CommandLine, Image | Process creation of dump tools (procdump, mimikatz) |

## Sigma Rules Applied
- `lsass_memory_dump.yml` — Detects suspicious process access to lsass.exe

## Detection Logic
```
IF sysmon_event_id = 10
  AND target_image ENDS_WITH "\lsass.exe"
  AND granted_access IN ["0x1FFFFF", "0x1010", "0x1038", "0x143A"]
  AND source_image NOT STARTS_WITH ["C:\Windows\System32\", known_security_products]
THEN → ALERT: LSASS Credential Dump Attempt (CRITICAL)
```

## Atomic Red Team Test
- **T1003.001 Test #1**: Dump LSASS with Mimikatz `sekurlsa::logonpasswords`
- **T1003.001 Test #2**: Dump LSASS with ProcDump `procdump.exe -ma lsass.exe`
- **T1003.001 Test #3**: Dump LSASS with comsvcs.dll `rundll32 comsvcs.dll MiniDump`

## Evasion Variants to Know
1. **Direct syscalls**: Bypassing API hooks by calling NtReadVirtualMemory directly
2. **Living-off-the-land**: Using comsvcs.dll MiniDump function via rundll32
3. **Credential Guard bypass**: Targeting LSASS in systems without Credential Guard
4. **Renamed tools**: Renaming mimikatz.exe to avoid filename-based detection
5. **Memory-only execution**: Running mimikatz from memory without touching disk
6. **Lower access masks**: Using 0x400 (PROCESS_QUERY_INFORMATION) for reconnaissance

## Known Threat Groups
APT28, APT29, Lazarus Group, Carbanak, FIN7, Turla, Wizard Spider, Sandworm Team

## References
- [MITRE ATT&CK T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [Atomic Red Team T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md)
