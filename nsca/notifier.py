import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def _critical_changes(result: dict) -> list[dict]:
    return [c for c in result["changes"] if c["risk"] in ("CRITICAL", "HIGH")]


def notify_slack(result: dict, webhook_url: str) -> bool:
    critical = _critical_changes(result)
    if not critical:
        return False
    rows = "\n".join(
        f"  * `{c['id']}` {c['type']} - {c['action']} from {c['source']} port {c['port']} [{c['risk']}]"
        for c in critical
    )
    payload = {
        "text": f":rotating_light: *Network Security Alert* - {len(critical)} high-risk change(s) detected",
        "attachments": [{
            "color": "danger",
            "text": rows,
            "footer": f"Total: {result['summary']['total']} | Added: {result['summary']['added']} | Removed: {result['summary']['removed']} | Modified: {result['summary']['modified']}"
        }]
    }
    resp = requests.post(webhook_url, json=payload, timeout=10)
    resp.raise_for_status()
    return True


def notify_email(result: dict, smtp_host: str, smtp_port: int,
                 username: str, password: str,
                 from_addr: str, to_addr: str) -> bool:
    critical = _critical_changes(result)
    if not critical:
        return False
    rows_html = "".join(
        f"<tr><td>{c['id']}</td><td>{c['type']}</td><td>{c['action']}</td>"
        f"<td>{c['source']}</td><td>{c['port']}</td>"
        f"<td style='color:{'red' if c['risk']=='CRITICAL' else 'orange'}'><b>{c['risk']}</b></td></tr>"
        for c in critical
    )
    html = f"""<html><body>
    <h2 style="color:#cc0000">Network Security Alert</h2>
    <p><b>{len(critical)}</b> high-risk change(s) detected.</p>
    <table border="1" cellpadding="6" cellspacing="0">
      <thead><tr><th>ID</th><th>Type</th><th>Action</th><th>Source</th><th>Port</th><th>Risk</th></tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
    <p>Total changes: {result['summary']['total']}</p>
    </body></html>"""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[ALERT] {len(critical)} high-risk network change(s) detected"
    msg["From"]    = from_addr
    msg["To"]      = to_addr
    msg.attach(MIMEText(html, "html"))
    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls()
        server.login(username, password)
        server.sendmail(from_addr, to_addr, msg.as_string())
    return True
