# HUNT-001 — Encoded PowerShell Activity Beyond Detected Events

| Field | Value |
|-------|-------|
| Hunt ID | HUNT-001 |
| Hypothesis | Encoded PowerShell beyond standard -EncodedCommand |
| Hunt Technique | T1059.001 |
| Tactic | Execution |
| Data Source | PowerShell Operational (EID 4104), Sysmon EID 1 |
| Hunt Date | 2026-06-14 |
| Analyst | Nityavardhan |
| Status | CONFIRMED |

## Hypothesis

Attackers may be using PowerShell with Base64-encoded content that does NOT use the standard `-EncodedCommand` parameter. Specifically, threat actors may encode payloads inline using `[System.Convert]::FromBase64String()` or store encoded commands in environment variables to evade our production Sigma rule that only matches the `-enc` flag.

## Query Used

**Sigma (broad hunt rule):**
```yaml
# See: threat_hunting/queries/sigma/hunt_encoded_powershell.yml
# Matches any Base64 decode operation in PowerShell scripts
```

**Chainsaw execution:**
```bash
chainsaw hunt evidence/T1059.001/raw/ \
  --sigma threat_hunting/queries/sigma/hunt_encoded_powershell.yml \
  --mapping mappings/sigma-event-logs-all.yml \
  --format json
```

## Expected Findings

1. Atomic Red Team T1059.001 test execution should be detected via EID 4104
2. Any additional unauthorized encoded PowerShell beyond the Atomic test would indicate a gap in our production detection

## Actual Findings

1. **Atomic Red Team test detected** — EID 4104 captured the decoded ScriptBlockText containing the base64-encoded command from the lab simulation
2. **No additional unauthorized encoded PowerShell** found beyond the test execution
3. The broad hunt query captured 1 additional event: a legitimate IT automation script using `[Convert]::ToBase64String()` for encoding data (not executing encoded commands)
4. No evidence of string concatenation obfuscation (`-E` + `ncodedCommand`) was found

## Conclusion

Detection coverage for standard `-EncodedCommand` patterns is adequate. The current production rules (powershell_encoded_cmd.yml) successfully detect the known Atomic Red Team patterns. However, the hunt reveals a detection gap for **inline Base64 decode operations** that don't use `-EncodedCommand`. 

**Recommended next steps:**
1. Add a new Sigma rule targeting `FromBase64String` and `[Convert]::` patterns in EID 4104 ScriptBlockText
2. Create HUNT-003 to investigate **split-string obfuscation** as the next hypothesis (e.g., `$a = '-Enc'; $b = 'odedCommand'; powershell "$a$b"`)
3. Consider monitoring for PowerShell v2 downgrade attacks (`-Version 2`) which bypass Script Block Logging entirely
