import re


def parse_cisco_acl(text: str) -> dict:
    rules = []
    rule_id = 1
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("!"):
            continue
        m = re.match(
            r"(permit|deny)\s+\S+\s+(\S+)(?:\s+\S+)?\s+(\S+)(?:\s+eq\s+(\d+))?",
            line, re.IGNORECASE
        )
        if m:
            rules.append({
                "id":          f"ACL{rule_id}",
                "action":      m.group(1).upper(),
                "source":      m.group(2),
                "destination": m.group(3),
                "port":        int(m.group(4)) if m.group(4) else 0,
            })
            rule_id += 1
    return {"device": "cisco-acl", "rules": rules}


def parse_iptables(text: str) -> dict:
    rules = []
    rule_id = 1
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(":"):
            continue
        action_m = re.search(r"-j\s+(\S+)", line)
        src_m    = re.search(r"-s\s+(\S+)", line)
        dport_m  = re.search(r"--dport\s+(\d+)", line)
        if action_m:
            action = "PERMIT" if action_m.group(1) in ("ACCEPT", "RETURN") else "DENY"
            rules.append({
                "id":          f"IPT{rule_id}",
                "action":      action,
                "source":      src_m.group(1) if src_m else "ANY",
                "destination": "ANY",
                "port":        int(dport_m.group(1)) if dport_m else 0,
            })
            rule_id += 1
    return {"device": "iptables", "rules": rules}


ADAPTERS = {
    ".acl":      parse_cisco_acl,
    ".iptables": parse_iptables,
}
