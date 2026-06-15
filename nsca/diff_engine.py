from nsca.risk import enrich


def _rule_id(rule: dict) -> str:
    return rule.get("id", str(rule))


def diff(before: dict, after: dict) -> dict:
    old_rules = {_rule_id(r): r for r in before.get("rules", [])}
    new_rules = {_rule_id(r): r for r in after.get("rules", [])}

    added = [
        {"type": "ADDED", **r}
        for rid, r in new_rules.items() if rid not in old_rules
    ]
    removed = [
        {"type": "REMOVED", **r}
        for rid, r in old_rules.items() if rid not in new_rules
    ]
    modified = [
        {"type": "MODIFIED", **new_rules[rid]}
        for rid in old_rules
        if rid in new_rules and old_rules[rid] != new_rules[rid]
    ]

    changes = enrich(added + removed + modified)

    return {
        "summary": {
            "added":    len(added),
            "removed":  len(removed),
            "modified": len(modified),
            "total":    len(changes),
        },
        "changes": changes,
    }
