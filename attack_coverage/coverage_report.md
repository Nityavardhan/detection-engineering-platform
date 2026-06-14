# ATT&CK Coverage Report

**Generated:** 2026-06-14
**Platform:** Detection Engineering & IR Validation Platform

## Summary

| Metric | Value |
|--------|-------|
| Techniques Validated | 15 |
| Detected | 15 |
| Partial | 0 |
| Missed | 0 |
| Detection Rate | 100% |

*Note: Detection rate reflects offline demo mode validation. Run with live EVTX telemetry for production accuracy.*

## Technique Results

| Technique ID | Name | Tactic | Result | Severity |
|-------------|------|--------|--------|----------|
| T1003.001 | LSASS Memory | Credential Access | DETECTED | CRITICAL |
| T1021.002 | SMB Admin Shares | Lateral Movement | DETECTED | HIGH |
| T1053.005 | Scheduled Task | Persistence | DETECTED | HIGH |
| T1055.001 | DLL Injection | Defense Evasion | DETECTED | HIGH |
| T1059.001 | PowerShell | Execution | DETECTED | HIGH |
| T1070.001 | Clear Event Logs | Defense Evasion | DETECTED | CRITICAL |
| T1078 | Valid Accounts | Defense Evasion | DETECTED | HIGH |
| T1082 | System Info Discovery | Discovery | DETECTED | MEDIUM |
| T1083 | File Discovery | Discovery | DETECTED | MEDIUM |
| T1110.001 | Password Spraying | Credential Access | DETECTED | HIGH |
| T1218.011 | Rundll32 | Defense Evasion | DETECTED | HIGH |
| T1486 | Data Encrypted | Impact | DETECTED | CRITICAL |
| T1490 | Inhibit Recovery | Impact | DETECTED | CRITICAL |
| T1547.001 | Registry Run Keys | Persistence | DETECTED | HIGH |
| T1566.001 | Spearphishing | Initial Access | DETECTED | CRITICAL |
