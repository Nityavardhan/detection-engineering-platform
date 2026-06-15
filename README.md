# Detection Engineering & IR Validation Platform

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)

A portfolio-quality automated platform for validating MITRE ATT&CK detections, generating Incident Response playbooks, and tracking compliance coverage. Built for SOC Analysts, Detection Engineers, and Incident Responders.

## 🌟 Features

*   **Automated Validation Pipeline:** Evaluates EVTX telemetry against Sigma rules using Chainsaw.
*   **Offline Mode:** Fully functional even without live telemetry or tools using synthetic deterministic generation (perfect for demonstrations).
*   **IR Playbook Generation:** Dynamically generates Markdown IR playbooks customized per technique and detection result using Jinja2 templates.
*   **Compliance Mapping:** Tracks detection coverage across NIST CSF, CIS Controls v8, and ISO 27001:2022.
*   **ATT&CK Integration:** Automatically pulls latest metadata from MITRE ATT&CK STIX data and generates Navigator heatmaps.
*   **Interactive Dashboard:** Streamlit-based web dashboard providing metrics, detection timelines, and compliance matrices.
*   **Threat Hunting Library:** Includes a documented hypothesis-driven hunting methodology with Sigma/KQL queries and hunt reports.

## 📂 Project Structure

```text
├── attack_coverage/     # ATT&CK Navigator JSON layers
├── compliance/          # Framework mappings and generated reports
├── core/                # Core Python modules (pipeline logic, DB, rendering)
├── Dashboard/           # Streamlit web application
├── data/                # SQLite DB and MITRE ATT&CK STIX
├── detections/          # Detection library (15 techniques with Sigma rules)
├── evidence/            # EVTX telemetry and Chainsaw output
├── playbooks/           # Generated IR playbooks (Markdown)
├── reports/             # Generated detection reports (Markdown)
├── tests/               # Pytest unit tests
├── threat_hunting/      # Hypothesis-driven hunt methodology and reports
└── run_pipeline.py      # Master CLI script
```

## 🚀 Quick Start

### Prerequisites
*   Python 3.10+
*   Windows environment (recommended)

### Installation

1. Clone the repository
2. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the complete pipeline (processes all 15 included techniques):
   ```bash
   # Note: For Windows environments with encoding issues, use:
   # $env:PYTHONUTF8=1; python run_all.py
   python run_all.py
   ```

### Running the Dashboard

Launch the interactive metrics dashboard:
```bash
streamlit run Dashboard/app.py
```

## 🛠️ Usage

### Pipeline Execution
Run the pipeline for a specific technique (e.g., T1059.001 - PowerShell):
```bash
python run_pipeline.py --technique T1059.001
```

Run with your own EVTX telemetry:
```bash
python run_pipeline.py --technique T1059.001 --evtx-dir C:\Path\To\EVTX
```

### Detection Library
The `detections/` directory contains 15 techniques spanning the entire ATT&CK Kill Chain. Each technique includes:
*   `sigma_rules/`: Custom Sigma detection rules.
*   `detection_card.md`: Analyst documentation on the technique.
*   `response_data.yaml`: Data to populate the IR playbook (containment, investigation steps).

## 🧪 Testing

Run the pytest suite to verify core logic (DB management, parsing, rendering):
```bash
pytest tests/ -v
```

