# Threat Hunting Methodology

## Overview

This document describes the hypothesis-driven threat hunting methodology used in this Detection Engineering Platform. The methodology follows the **PEAK framework** (Prepare, Execute, Act, Knowledge) adapted for a lab environment.

## The Hypothesis-Driven Hunting Cycle

```
┌─────────────────────────────────────────────────────────────┐
│  1. HYPOTHESIS FORMATION                                     │
│  "I believe [attacker behavior X] exists in our environment  │
│   because [threat intelligence / ATT&CK TTP / gap analysis]" │
├─────────────────────────────────────────────────────────────┤
│  2. QUERY DEVELOPMENT                                        │
│  Create Sigma rule or KQL query to detect the behavior       │
│  Use broader conditions than production rules                │
├─────────────────────────────────────────────────────────────┤
│  3. EXECUTE AGAINST TELEMETRY                                │
│  Run queries via Chainsaw against EVTX telemetry             │
│  Review results for true positives and anomalies             │
├─────────────────────────────────────────────────────────────┤
│  4. ANALYZE RESULTS                                          │
│  Compare findings against expected baselines                 │
│  Classify: CONFIRMED / NOT_FOUND / INCONCLUSIVE             │
├─────────────────────────────────────────────────────────────┤
│  5. DOCUMENT FINDINGS                                        │
│  Record hypothesis, query, results, and conclusions          │
│  File hunt report in hunt_reports/                           │
├─────────────────────────────────────────────────────────────┤
│  6. IMPROVE DETECTIONS                                       │
│  Feed findings back into Sigma rules and detection cards     │
│  Create new production rules from successful hunts           │
│  Generate next hypothesis from findings                      │
└─────────────────────────────────────────────────────────────┘
```

## How Hypotheses Are Formed

Hypotheses originate from three sources:

### 1. ATT&CK TTP Analysis
Review ATT&CK techniques for behaviors our current rules might miss:
- Sub-techniques not yet covered
- Evasion variants documented in detection cards
- Techniques used by threat groups targeting our sector

### 2. Detection Gap Analysis
Identify gaps between what we detect and what we should detect:
- Techniques with only one Sigma rule (may miss variants)
- Behavioral techniques requiring correlation (T1078, T1110.001)
- Techniques where we only detect the most obvious execution method

### 3. Threat Intelligence
External intelligence informs hunt priorities:
- New tools and techniques observed in the wild
- Sector-specific targeting reports
- Vulnerability disclosures that enable new attack paths

## How Results Feed Back Into Detections

```
Hunt Result → CONFIRMED
  ├── Create new Sigma rule for production detection
  ├── Update detection_card.md with new evasion variant
  └── Generate next hypothesis based on finding

Hunt Result → NOT_FOUND
  ├── Document coverage adequacy
  ├── Consider broader query parameters
  └── Reassess hypothesis validity

Hunt Result → INCONCLUSIVE
  ├── Refine query and re-execute
  ├── Collect additional telemetry
  └── Collaborate with team for second opinion
```

## Tools Used

| Tool | Purpose | Usage |
|------|---------|-------|
| **Chainsaw** | Primary EVTX analysis engine | `chainsaw hunt evtx_dir --sigma rules/` |
| **Sigma** | Detection rule format for hunting queries | Broader rules than production |
| **KQL** | Cloud SIEM query language | Azure Sentinel / Defender for Endpoint |
| **Python** | Automation and analysis | Pipeline orchestration and data processing |

## Hunt Quality Criteria

A well-formed hunt hypothesis must be:
- **Specific**: Clearly defines the attacker behavior being sought
- **Testable**: Can be validated or refuted with available telemetry
- **Actionable**: Results can improve detection capability
- **Time-bounded**: Has a defined scope and execution timeframe
- **Documented**: Follows the standard hunt report template
