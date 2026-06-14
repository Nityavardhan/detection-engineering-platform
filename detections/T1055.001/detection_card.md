# Detection Card — T1055.001 DLL Injection

## Overview
| Field | Value |
|-------|-------|
| Technique ID | T1055.001 |
| Name | Process Injection: Dynamic-link Library Injection |
| Tactic | Defense Evasion, Privilege Escalation |
| Severity | HIGH |
| False Positive Risk | LOW |
| Data Sources | Sysmon (EID 8 — CreateRemoteThread, EID 10 — ProcessAccess) |

## What Are We Detecting?
Cross-process thread creation (CreateRemoteThread) where a non-system process creates a thread in another process's address space. This is the primary mechanism for DLL injection used by threat actors to hide malicious code inside legitimate processes.

## Expected Windows Event IDs
| Event ID | Channel | Field of Interest | What It Shows |
|----------|---------|-------------------|---------------|
| 8 (Sysmon) | Sysmon Operational | SourceImage, TargetImage, StartModule | Remote thread creation across processes |
| 10 (Sysmon) | Sysmon Operational | SourceImage, TargetImage, GrantedAccess | Process memory access with write permission |
| 7 (Sysmon) | Sysmon Operational | Image, ImageLoaded | DLL loaded into target process after injection |

## Sigma Rules Applied
- `dll_injection_remote_thread.yml` — Detects CreateRemoteThread from non-system processes

## Detection Logic
```
IF sysmon_event_id = 8 (CreateRemoteThread)
  AND source_image NOT STARTS_WITH ["C:\Windows\System32\", "C:\Program Files\"]
THEN → ALERT: DLL Injection via CreateRemoteThread (HIGH)
```

## Atomic Red Team Test
- **T1055.001 Test #1**: DLL injection via CreateRemoteThread
- **T1055.001 Test #2**: Process injection via NtMapViewOfSection

## Evasion Variants to Know
1. **APC injection**: Using QueueUserAPC instead of CreateRemoteThread
2. **Process hollowing**: Creating process in suspended state and replacing code (T1055.012)
3. **Thread execution hijacking**: Modifying existing thread context instead of creating new thread
4. **Atom bombing**: Using global atom tables for cross-process code injection
5. **Process doppelgänging**: Using NTFS transactions to mask injected code

## Known Threat Groups
Lazarus Group, APT32, APT41, Turla, Carbanak, Cobalt Group

## References
- [MITRE ATT&CK T1055.001](https://attack.mitre.org/techniques/T1055/001/)
- [Atomic Red Team T1055.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.001/T1055.001.md)
