import yaml
from pathlib import Path
from rich.console import Console

console = Console()

FRAMEWORK_FILES = {
    "NIST_CSF": "compliance/mappings/nist_csf.yaml",
    "CIS_v8": "compliance/mappings/cis_controls_v8.yaml",
    "ISO_27001": "compliance/mappings/iso27001.yaml"
}


def get_mappings_for_technique(technique_id: str) -> list:
    """
    Return compliance mappings for a technique from all frameworks.
    """
    all_mappings = []
    
    for framework, filepath in FRAMEWORK_FILES.items():
        path = Path(filepath)
        if not path.exists():
            continue
        
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        
        technique_mappings = data.get(technique_id, [])
        for mapping in technique_mappings:
            mapping["framework"] = framework
            all_mappings.append(mapping)
    
    return all_mappings