import json
from pathlib import Path
from rich.console import Console
import requests
import yaml

console = Console()

with open("config.yaml", "r", encoding="utf-8") as f:
    CONFIG = yaml.safe_load(f)

# Cache loaded STIX data in memory
_ATTACK_DATA = None


def download_attack_stix(stix_path: str = None) -> bool:
    """Download the MITRE ATT&CK STIX bundle into the configured data path."""
    target_path = Path(stix_path or CONFIG["paths"].get("attack_stix_data", "data/enterprise-attack.json"))
    target_path.parent.mkdir(parents=True, exist_ok=True)

    urls = [
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        "https://github.com/mitre-attack/attack-stix-data/raw/master/enterprise-attack/enterprise-attack.json",
    ]

    for url in urls:
        try:
            response = requests.get(url, timeout=60)
            response.raise_for_status()
            target_path.write_text(response.text, encoding="utf-8")
            console.print(f"[green]✓ Downloaded ATT&CK STIX data to {target_path}[/green]")
            return True
        except Exception as exc:
            console.print(f"[yellow]⚠ Failed to download ATT&CK STIX from {url}: {exc}[/yellow]")

    return False


def load_attack_data(stix_path: str = "data/enterprise-attack.json") -> dict:
    """Load MITRE ATT&CK STIX data from local file."""
    global _ATTACK_DATA
    if _ATTACK_DATA is not None:
        return _ATTACK_DATA
    
    stix_file = Path(stix_path)
    if not stix_file.exists():
        console.print(f"[yellow]⚠ ATT&CK STIX file not found at {stix_path}[/yellow]")
        console.print("[yellow]  Attempting to download the MITRE ATT&CK STIX bundle...[/yellow]")
        if not download_attack_stix(str(stix_file)):
            console.print("[yellow]  Download from: https://github.com/mitre-attack/attack-stix-data[/yellow]")
            return {}
    
    with open(stix_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    # Index by external ID (T1059.001 etc.) for fast lookup
    indexed = {}
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id", "")
                    indexed[ext_id] = {
                        "id": obj.get("id"),
                        "technique_id": ext_id,
                        "name": obj.get("name", ""),
                        "description": obj.get("description", ""),
                        "tactic": extract_tactic(obj),
                        "platforms": obj.get("x_mitre_platforms", []),
                        "data_sources": obj.get("x_mitre_data_sources", []),
                        "detection": obj.get("x_mitre_detection", ""),
                        "url": ref.get("url", "")
                    }
    
    _ATTACK_DATA = indexed
    console.print(f"[green]✓ Loaded {len(indexed)} ATT&CK techniques[/green]")
    return indexed


def extract_tactic(obj: dict) -> str:
    """Extract primary tactic from kill chain phases."""
    phases = obj.get("kill_chain_phases", [])
    for phase in phases:
        if phase.get("kill_chain_name") == "mitre-attack":
            return phase.get("phase_name", "unknown").replace("-", " ").title()
    return "Unknown"


def get_technique_metadata(technique_id: str) -> dict:
    """Return metadata for a specific technique ID."""
    data = load_attack_data()
    if not data:
        return {
            "technique_id": technique_id,
            "name": "Unknown",
            "tactic": "Unknown",
            "description": "",
            "platforms": [],
            "data_sources": [],
            "detection": "",
            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
        }
    
    return data.get(technique_id, {
        "technique_id": technique_id,
        "name": "Not Found in STIX Data",
        "tactic": "Unknown",
        "description": "",
        "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
    })


def get_threat_groups_for_technique(technique_id: str,
                                     stix_path: str = "data/enterprise-attack.json") -> list:
    """Return threat groups known to use this technique."""
    stix_file = Path(stix_path)
    if not stix_file.exists():
        return []
    
    with open(stix_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    # Find technique STIX id
    technique_stix_id = None
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("external_id") == technique_id:
                    technique_stix_id = obj.get("id")
                    break
    
    if not technique_stix_id:
        return []
    
    # Find relationships linking groups to this technique
    group_ids = set()
    for obj in data.get("objects", []):
        if (obj.get("type") == "relationship" and
                obj.get("relationship_type") == "uses" and
                obj.get("target_ref") == technique_stix_id):
            group_ids.add(obj.get("source_ref"))
    
    # Resolve group names
    groups = []
    for obj in data.get("objects", []):
        if obj.get("id") in group_ids and obj.get("type") == "intrusion-set":
            groups.append(obj.get("name", "Unknown"))
    
    return sorted(groups)