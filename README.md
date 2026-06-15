# NetworkSecurityChangeAnalyzer

A CLI tool that compares two network device configurations (firewall rules, ACLs) and identifies security-relevant changes with automatic risk classification.

![CI](https://github.com/YOUR_USERNAME/NetworkSecurityChange-Analyzer/actions/workflows/ci.yml/badge.svg)

## Features

- Detects added, removed, and modified firewall rules
- Classifies each change as `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`
- Color-coded terminal output
- Exports reports as JSON or HTML
- 9 automated tests with pytest + GitHub Actions CI

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/NetworkSecurityChange-Analyzer.git
cd NetworkSecurityChange-Analyzer
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

## Usage

```bash
# Terminal output
python -m nsca.cli examples/before.json examples/after.json

# Filter by minimum risk level
python -m nsca.cli examples/before.json examples/after.json --min-risk HIGH

# Export reports
python -m nsca.cli examples/before.json examples/after.json --json-out reports/result.json --html-out reports/result.html
```

## Risk Classification

| Level    | Criteria                                      |
|----------|-----------------------------------------------|
| CRITICAL | PERMIT from ANY to sensitive ports (22,23,3389)|
| HIGH     | PERMIT from ANY to any port                   |
| MEDIUM   | PERMIT from specific source                   |
| LOW      | DENY rules                                    |

## Project Structure
## License

MIT
