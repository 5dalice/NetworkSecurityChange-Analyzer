import click
from rich.console import Console
from rich.table import Table
from rich import box

from nsca.parser import load_config
from nsca.diff_engine import diff
from nsca.reporter import save_json, save_html
from nsca.notifier import notify_slack, notify_email

console = Console()

RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "dark_orange",
    "MEDIUM":   "yellow",
    "LOW":      "green",
}
TYPE_COLORS = {
    "ADDED":    "green",
    "REMOVED":  "red",
    "MODIFIED": "cyan",
}


@click.command()
@click.argument("before")
@click.argument("after")
@click.option("--json-out",      default=None, help="Save JSON report to file")
@click.option("--html-out",      default=None, help="Save HTML report to file")
@click.option("--min-risk",      default="LOW", type=click.Choice(["LOW","MEDIUM","HIGH","CRITICAL"]), help="Filter by minimum risk level")
@click.option("--notify-slack",  default=None, help="Slack webhook URL")
@click.option("--notify-email",  default=None, help="Send email alert to this address")
@click.option("--smtp-host",     default="smtp.gmail.com", help="SMTP host")
@click.option("--smtp-port",     default=587, help="SMTP port")
@click.option("--smtp-user",     default=None, help="SMTP username")
@click.option("--smtp-pass",     default=None, help="SMTP password")
@click.option("--smtp-from",     default=None, help="From address")
def main(before, after, json_out, html_out, min_risk,
         notify_slack_url=None, notify_email=None,
         smtp_host=None, smtp_port=587, smtp_user=None,
         smtp_pass=None, smtp_from=None, **kwargs):
    """Analyze network security changes between BEFORE and AFTER configs."""
    levels    = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    threshold = levels.index(min_risk)

    b      = load_config(before)
    a      = load_config(after)
    result = diff(b, a)

    filtered = [c for c in result["changes"] if levels.index(c["risk"]) >= threshold]

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white on grey23")
    table.add_column("Type",   style="bold", width=10)
    table.add_column("ID",     width=6)
    table.add_column("Action", width=8)
    table.add_column("Source", width=18)
    table.add_column("Port",   width=6)
    table.add_column("Risk",   width=10)

    for c in filtered:
        table.add_row(
            f"[{TYPE_COLORS[c['type']]}]{c['type']}[/]",
            c["id"], c["action"], c["source"], str(c["port"]),
            f"[{RISK_COLORS[c['risk']]}]{c['risk']}[/]",
        )

    console.print()
    console.print("[bold]Network Security Change Analyzer[/bold]", style="white on grey23")
    console.print(f"  Before : [dim]{before}[/dim]")
    console.print(f"  After  : [dim]{after}[/dim]")
    console.print()
    console.print(table)
    console.print(f"\n  Total: [bold]{result['summary']['total']}[/] changes  "
                  f"([green]+{result['summary']['added']}[/] added "
                  f"[red]-{result['summary']['removed']}[/] removed "
                  f"[cyan]~{result['summary']['modified']}[/] modified)\n")

    if json_out:
        save_json(result, json_out)
        console.print(f"[dim]JSON saved: {json_out}[/dim]")
    if html_out:
        save_html(result, html_out, before, after)
        console.print(f"[dim]HTML saved: {html_out}[/dim]")

    slack = kwargs.get("notify_slack")
    if slack:
        sent = notify_slack(result, slack)
        console.print(f"[green]Slack alert sent[/green]" if sent else "[dim]No high-risk changes — Slack skipped[/dim]")

    if notify_email and smtp_user and smtp_pass and smtp_from:
        from nsca.notifier import notify_email as send_email
        sent = send_email(result, smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from, notify_email)
        console.print(f"[green]Email alert sent to {notify_email}[/green]" if sent else "[dim]No high-risk changes — email skipped[/dim]")


if __name__ == "__main__":
    main()
