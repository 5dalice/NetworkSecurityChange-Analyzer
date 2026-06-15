from nsca.parser import load_config
from nsca.diff_engine import diff

def test_diff_counts():
    b = load_config("examples/before.json")
    a = load_config("examples/after.json")
    result = diff(b, a)
    assert result["summary"]["added"]    == 1
    assert result["summary"]["removed"]  == 1
    assert result["summary"]["modified"] == 1
    assert result["summary"]["total"]    == 3

def test_diff_no_changes():
    b = load_config("examples/before.json")
    result = diff(b, b)
    assert result["summary"]["total"] == 0
