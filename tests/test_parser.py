import pytest
from nsca.parser import load_config

def test_load_valid_config():
    config = load_config("examples/before.json")
    assert config["device"] == "firewall-01"
    assert len(config["rules"]) == 3

def test_load_missing_file():
    with pytest.raises(FileNotFoundError):
        load_config("nonexistent.json")
