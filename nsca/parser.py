import json
import yaml
from pathlib import Path
from nsca.adapters import ADAPTERS


def load_config(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    if p.suffix in ADAPTERS:
        with open(p, encoding="utf-8") as f:
            return ADAPTERS[p.suffix](f.read())
    with open(p, encoding="utf-8") as f:
        if p.suffix in (".yaml", ".yml"):
            return yaml.safe_load(f)
        return json.load(f)


def get_rules(config: dict) -> list[dict]:
    return config.get("rules", [])
