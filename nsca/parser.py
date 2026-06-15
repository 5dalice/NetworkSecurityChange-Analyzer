import json
from pathlib import Path


def load_config(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def get_rules(config: dict) -> list[dict]:
    return config.get("rules", [])
