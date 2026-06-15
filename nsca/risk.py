RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def classify(change: dict) -> str:
    action = change.get("action", "")
    port   = change.get("port", 0)
    src    = change.get("source", "")

    if action == "PERMIT" and src == "ANY" and port in (0, 22, 23, 3389):
        return "CRITICAL"
    if action == "PERMIT" and src == "ANY":
        return "HIGH"
    if action == "PERMIT":
        return "MEDIUM"
    return "LOW"


def enrich(changes: list[dict]) -> list[dict]:
    for c in changes:
        c["risk"] = classify(c)
    return changes
