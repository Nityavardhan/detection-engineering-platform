# Hunt Report — HUNT-001: Encoded PowerShell Activity

| Field | Value |
|-------|-------|
| Hunt ID | HUNT-001 |
| Analyst | Nityavardhan |
| Date Executed | 2026-06-14 |
| Technique | T1059.001 — PowerShell |
| Status | **CONFIRMED** |
| Duration | 45 minutes |

## Executive Summary

This hunt investigated whether encoded PowerShell activity existed in the lab telemetry beyond what our production detection rules (`powershell_encoded_cmd.yml`) would catch. The Atomic Red Team test execution was successfully identified, and no additional unauthorized encoded PowerShell activity was found.

## Findings

### Finding 1: Atomic Red Team Test Detected ✅
- **Source**: EID 4104 (Script Block Logging)
- **Content**: Base64-encoded command decoded by AMSI to reveal `Invoke-WebRequest` download cradle
- **Timestamp**: 2026-06-14T10:15:32Z
- **Assessment**: Expected — this is the Atomic Red Team test execution

### Finding 2: Legitimate IT Script (False Positive) ℹ️
- **Source**: EID 4104
- **Content**: `[Convert]::ToBase64String()` used for encoding certificate data
- **Assessment**: Benign — legitimate IT automation, not executing encoded commands

### Finding 3: No Unauthorized Encoded PowerShell ✅
- No evidence of split-string obfuscation
- No environment variable-based encoded command injection
- No PowerShell v2 downgrade attempts detected

## Detection Gap Identified

The current production rule only matches the `-EncodedCommand` flag in process creation events. It does NOT detect:
1. Inline `FromBase64String()` calls in script blocks
2. Environment variable-based payload storage and execution
3. Split-string obfuscation of the `-EncodedCommand` parameter

## Recommendations

1. **New Sigma Rule**: Create a production rule targeting `FromBase64String` in EID 4104 ScriptBlockText
2. **Next Hunt**: HUNT-003 — Investigate split-string obfuscation patterns
3. **Monitoring Enhancement**: Add PowerShell v2 engine startup detection (EID 400 with EngineVersion=2)

## Conclusion

Detection coverage is **adequate for known patterns**. The identified gap (inline Base64 decode) represents a moderate risk that should be addressed with an additional Sigma rule. Overall detection posture for T1059.001 is rated as **STRONG**.
