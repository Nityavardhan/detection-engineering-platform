# Hunt Report — HUNT-002: LSASS Process Access

| Field | Value |
|-------|-------|
| Hunt ID | HUNT-002 |
| Analyst | Nityavardhan |
| Date Executed | 2026-06-14 |
| Technique | T1003.001 — LSASS Memory |
| Status | **CONFIRMED** |
| Duration | 60 minutes |

## Executive Summary

This hunt investigated whether any non-system processes were accessing LSASS memory at access masks lower than our production detection threshold (0x1010). The goal was to identify credential access reconnaissance that might precede a full LSASS dump. The Atomic Red Team test was detected at the expected high access mask, and no unexpected low-and-slow probing was found.

## Findings

### Finding 1: Atomic Red Team Dump Detected ✅
- **Source**: Sysmon EID 10 (ProcessAccess)
- **SourceImage**: procdump64.exe
- **TargetImage**: lsass.exe
- **GrantedAccess**: 0x1FFFFF (PROCESS_ALL_ACCESS)
- **Timestamp**: 2026-06-14T10:20:15Z
- **Assessment**: Expected — this is the Atomic Red Team T1003.001 test

### Finding 2: Windows Defender Access (Expected) ℹ️
- **SourceImage**: C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe
- **GrantedAccess**: 0x1400
- **Assessment**: Benign — Defender's real-time protection accessing LSASS for monitoring

### Finding 3: WerFault.exe Access (Expected) ℹ️
- **SourceImage**: C:\Windows\System32\WerFault.exe
- **GrantedAccess**: 0x1410
- **Assessment**: Benign — Windows Error Reporting crash handler

### Finding 4: No Low-Access-Mask Probing ✅
- No non-system processes accessed LSASS at 0x400 (PROCESS_QUERY_INFORMATION)
- No evidence of direct syscall-based LSASS access
- No renamed system utilities were observed accessing LSASS

## Detection Gap Identified

The current production rule filters on specific high-access-mask values (0x1FFFFF, 0x1010, 0x1038). Emerging tools like **NanoDump** and **HandleKatz** use novel access methods that may not match these specific values:
- NanoDump uses `MiniDumpWriteDump` with a duplicated handle (different access pattern)
- HandleKatz elevates an existing handle rather than opening LSASS directly

## Recommendations

1. **Access Mask Monitoring**: Add monitoring for GrantedAccess values below 0x1010 from non-system, non-security-product processes
2. **comsvcs.dll Detection**: Add Sigma rule for `rundll32 comsvcs.dll MiniDump` which uses a different LSASS access pattern
3. **Tool Signatures**: Monitor for known tool artifacts:
   - NanoDump: Creates `.dmp` files with specific byte patterns
   - HandleKatz: Uses `DuplicateHandle` on existing LSASS handles
4. **Next Hunt**: HUNT-004 — Investigate LSASS access from renamed system utilities

## Conclusion

Detection coverage for standard LSASS dumping tools is **adequate**. The production rule successfully detects Mimikatz, ProcDump, and similar tools. The identified gap around novel tools (NanoDump, HandleKatz) represents an **emerging risk** that should be addressed proactively. Overall detection posture for T1003.001 is rated as **STRONG** for known tools, **MODERATE** for emerging tools.
