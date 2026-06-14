"""
Core modules for the Detection Engineering & IR Validation Platform.

This package provides the main pipeline components:
- chainsaw_runner: Runs Chainsaw against EVTX telemetry
- telemetry_collector: Collects Windows Event Log EVTX files
- sigma_validator: Validates detections using Sigma rules
- attack_mapper: Maps techniques to MITRE ATT&CK metadata
- playbook_generator: Generates IR playbooks from templates
- report_generator: Generates detection reports from templates
- navigator_updater: Updates ATT&CK Navigator layer JSON
- compliance_mapper: Maps detections to compliance frameworks
- db_manager: Manages SQLite database operations
"""
