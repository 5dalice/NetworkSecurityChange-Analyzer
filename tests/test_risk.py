from nsca.risk import classify

def test_critical_rdp():
    assert classify({"action": "PERMIT", "source": "ANY", "port": 3389}) == "CRITICAL"

def test_critical_telnet():
    assert classify({"action": "PERMIT", "source": "ANY", "port": 23}) == "CRITICAL"

def test_high_any_source():
    assert classify({"action": "PERMIT", "source": "ANY", "port": 80}) == "HIGH"

def test_medium_specific_source():
    assert classify({"action": "PERMIT", "source": "10.0.0.1", "port": 22}) == "MEDIUM"

def test_low_deny():
    assert classify({"action": "DENY", "source": "ANY", "port": 80}) == "LOW"
