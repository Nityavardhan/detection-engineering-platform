# Detection Library

This directory contains detection content for **15 MITRE ATT&CK techniques** validated by the Detection Engineering Platform.

## Structure

Each technique folder follows a consistent structure:

```
T1059.001/
├── detection_card.md       # Human-readable detection documentation
├── response_data.yaml      # IR playbook data (containment, investigation, remediation)
└── sigma_rules/
    ├── rule_one.yml        # Sigma detection rule
    └── rule_two.yml        # Additional Sigma rules (optional)
```

## Files

### detection_card.md
Contains: overview table, what we detect, expected event IDs, detection logic (pseudocode), Atomic Red Team test reference, evasion variants, known threat groups, and ATT&CK references.

### response_data.yaml
Structured YAML containing:
- Adversary context (why this technique matters)
- Containment steps (with actual commands)
- Investigation steps (specific event IDs and fields to check)
- Evidence checklist
- Remediation steps
- False positive scenarios with tuning recommendations
- Compliance mapping notes

### sigma_rules/*.yml
Valid Sigma rules that can be:
- Used by Chainsaw for EVTX analysis
- Converted to SIEM queries via pySigma
- Imported into security tools supporting Sigma format

## Techniques Covered

| ID | Name | Tactic | Severity |
|----|------|--------|----------|
| T1059.001 | PowerShell | Execution | HIGH |
| T1053.005 | Scheduled Task | Persistence | HIGH |
| T1547.001 | Registry Run Keys | Persistence | HIGH |
| T1078 | Valid Accounts | Defense Evasion | HIGH |
| T1003.001 | LSASS Memory | Credential Access | CRITICAL |
| T1110.001 | Password Spraying | Credential Access | HIGH |
| T1055.001 | DLL Injection | Defense Evasion | HIGH |
| T1218.011 | Rundll32 | Defense Evasion | HIGH |
| T1083 | File Discovery | Discovery | MEDIUM |
| T1082 | System Info Discovery | Discovery | MEDIUM |
| T1021.002 | SMB Admin Shares | Lateral Movement | HIGH |
| T1070.001 | Clear Event Logs | Defense Evasion | CRITICAL |
| T1486 | Data Encrypted | Impact | CRITICAL |
| T1490 | Inhibit Recovery | Impact | CRITICAL |
| T1566.001 | Spearphishing | Initial Access | CRITICAL |
