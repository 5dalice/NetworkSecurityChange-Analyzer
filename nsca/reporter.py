import json
from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader


def save_json(result: dict, path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)


def save_html(result: dict, path: str, before_path: str, after_path: str) -> None:
    env = Environment(loader=FileSystemLoader("templates"))
    tmpl = env.get_template("report.html")
    html = tmpl.render(
        result=result,
        before_path=before_path,
        after_path=after_path,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
