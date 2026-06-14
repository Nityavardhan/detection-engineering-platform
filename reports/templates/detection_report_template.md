# Detection Report for {{ technique_id }} — {{ technique_name }}

- Tactic: {{ tactic }}
- Severity: {{ severity }}
- Detection Result: {{ detection_result }}
- False Positive Risk: {{ false_positive_risk }}
- Report Date: {{ report_date }}

## Detection Card
{{ detection_card }}

## Chainsaw Hits
{% if chainsaw_hits %}
{% for hit in chainsaw_hits %}
- Rule: {{ hit.rule_name }} (Level: {{ hit.rule_level }})
{% endfor %}
{% else %}
- No detections were observed.
{% endif %}
