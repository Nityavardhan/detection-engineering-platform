# Threat Hunting Lab

This directory contains threat hunting artifacts developed as part of the Detection Engineering Platform. It demonstrates a **hypothesis-driven hunting methodology** applied to ATT&CK techniques validated in the lab.

## What is Threat Hunting?

Threat hunting is the **proactive** search for threats that have evaded existing automated detections. Unlike reactive detection (waiting for alerts), hunting assumes the attacker is already inside and actively searches for evidence of compromise.

## Approach

This lab uses the **hypothesis-driven hunting methodology**:

1. **Hypothesize** — Form a testable hypothesis based on ATT&CK TTPs and threat intelligence
2. **Query** — Develop and run detection queries (Sigma, KQL) against available telemetry
3. **Execute** — Run the queries against lab EVTX telemetry using Chainsaw
4. **Analyze** — Evaluate findings against expected baselines
5. **Document** — Record results, conclusions, and detection improvements
6. **Improve** — Feed findings back into production Sigma rules and detection cards

## Difference: Reactive Detection vs. Proactive Hunting

| Aspect | Reactive Detection | Proactive Hunting |
|--------|-------------------|-------------------|
| Trigger | Automated alert fires | Analyst initiates based on hypothesis |
| Scope | Known-bad patterns | Unknown-bad and anomalous patterns |
| Rules | Tuned for low FP (production) | Broad queries (acceptable noise) |
| Goal | Alert on known threats | Discover unknown threats |
| Output | Incident ticket | Detection improvement + hunt report |

## Directory Structure

```
threat_hunting/
├── methodology.md           # Detailed methodology documentation
├── hypotheses/              # Hunt hypothesis documents
│   ├── HUNT-001_encoded_powershell.md
│   └── HUNT-002_lsass_access.md
├── queries/
│   ├── sigma/               # Sigma rules for hunting (broader than production)
│   │   ├── hunt_encoded_powershell.yml
│   │   └── hunt_lsass_access.yml
│   └── kql/                 # KQL equivalents for cloud SIEM
│       ├── hunt_encoded_powershell.kql
│       └── hunt_lsass_access.kql
└── hunt_reports/            # Documented hunt outcomes
    ├── HUNT-001_results.md
    └── HUNT-002_results.md
```

## Hunts Conducted

| ID | Hypothesis | Technique | Status | Key Finding |
|----|-----------|-----------|--------|-------------|
| HUNT-001 | Encoded PowerShell beyond known patterns | T1059.001 | CONFIRMED | Atomic test detected; recommend string obfuscation hunt |
| HUNT-002 | Non-system LSASS access at any mask | T1003.001 | CONFIRMED | Expected dump detected; recommend low-access-mask monitoring |
