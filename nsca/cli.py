import click
import json
from rich.console import Console
from rich.table import Table
from rich import box

from nsca.parser import load_config
from nsca.diff_engine import diff
from nsca.reporter import save_json, save_html

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
@click.option("--json-out",  default=None, help="Save JSON report to file")
@click.option("--html-out",  default=None, help="Save HTML report to file")
@click.option("--min-risk",  default="LOW", type=click.Choice(["LOW","MEDIUM","HIGH","CRITICAL"]), help="Filter by minimum risk level")
def main(before, after, json_out, html_out, min_risk):
    """Analyze network security changes between BEFORE and AFTER configs."""
    levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    threshold = levels.index(min_risk)

    b = load_config(before)
    a = load_config(after)
    result = diff(b, a)

    filtered = [c for c in result["changes"] if levels.index(c["risk"]) >= threshold]

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white on grey23")
    table.add_column("Type",        style="bold", width=10)
    table.add_column("ID",          width=6)
    table.add_column("Action",      width=8)
    table.add_column("Source",      width=18)
    table.add_column("Port",        width=6)
    table.add_column("Risk",        width=10)

    for c in filtered:
        table.add_row(
            f"[{TYPE_COLORS[c['type']]}]{c['type']}[/]",
            c["id"],
            c["action"],
            c["source"],
            str(c["port"]),
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


if __name__ == '__main__':
    main()
