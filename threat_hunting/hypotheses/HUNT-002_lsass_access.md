# HUNT-002 — Non-System LSASS Process Access

| Field | Value |
|-------|-------|
| Hunt ID | HUNT-002 |
| Hypothesis | Any non-system process accessing LSASS at any access mask |
| Hunt Technique | T1003.001 |
| Tactic | Credential Access |
| Data Source | Sysmon EID 10 (ProcessAccess) |
| Hunt Date | 2026-06-14 |
| Analyst | Nityavardhan |
| Status | CONFIRMED |

## Hypothesis

Any process other than known Windows system processes accessing LSASS memory — even at lower access masks than a full dump (below 0x1010) — may indicate credential access reconnaissance. Attackers may use lower access masks like 0x400 (PROCESS_QUERY_INFORMATION) to enumerate LSASS before attempting a full dump, or use direct syscalls that request minimal permissions.

## Query Used

**Sigma (broad hunt rule):**
```yaml
# See: threat_hunting/queries/sigma/hunt_lsass_access.yml
# Matches ANY ProcessAccess to lsass.exe regardless of GrantedAccess
```

**Chainsaw execution:**
```bash
chainsaw hunt evidence/T1003.001/raw/ \
  --sigma threat_hunting/queries/sigma/hunt_lsass_access.yml \
  --mapping mappings/sigma-event-logs-all.yml \
  --format json
```

## Expected Findings

1. The Atomic Red Team T1003.001 test should produce high-access-mask events (0x1FFFFF or 0x1010)
2. EDR/AV products may produce legitimate LSASS access at various masks
3. Any unexpected non-system process accessing LSASS at any mask is noteworthy

## Actual Findings

1. **Atomic Red Team dump detected** — Sysmon EID 10 captured the expected LSASS access at GrantedAccess 0x1FFFFF from the procdump test
2. **Windows Defender** generated legitimate LSASS access events at GrantedAccess 0x1400 (expected behavior for real-time protection)
3. **WerFault.exe** accessed LSASS once at 0x1410 during a crash reporting event
4. **No additional low-and-slow LSASS probing** was found from non-system processes
5. No evidence of direct syscall-based LSASS access was observed

## Conclusion

The current production rule (lsass_memory_dump.yml) correctly detects high-access-mask LSASS access from non-system processes. The hunt confirms that our environment does not currently have any low-access-mask reconnaissance targeting LSASS.

**Recommended next steps:**
1. Monitor for GrantedAccess values below 0x1010 from non-system processes as an emerging technique indicator
2. Add monitoring for `comsvcs.dll` MiniDump usage (rundll32 comsvcs.dll MiniDump) as this uses a different access pattern
3. Consider adding `NanoDump` and `HandleKatz` tool signatures as these use novel LSASS access methods
4. Create HUNT-003 to investigate LSASS access from renamed system utilities (e.g., `notepad.exe` copied and renamed to bypass path-based filtering)
