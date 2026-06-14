# IR Playbook for {{ technique_id }} — {{ technique_name }}

- Technique: {{ technique_id }}
- Tactic: {{ tactic }}
- Severity: {{ severity }}
- Detection Result: {{ detection_result }}

## Adversary Context
{{ adversary_context }}

## Containment Steps
{{ containment_steps }}

## Investigation Steps
{{ investigation_steps }}

## Evidence Checklist
{{ evidence_checklist }}

## Remediation Steps
{{ remediation_steps }}

## Compliance Notes
{{ compliance_notes }}

## False Positive Scenarios
{{ false_positive_scenarios }}

## Triggered Rules
{% if triggered_rules %}
{% for rule in triggered_rules %}
- {{ rule }}
{% endfor %}
{% else %}
- None recorded
{% endif %}
