import requests
import time

# Common CVEs per port — cached to avoid hammering the API
_CACHE: dict[int, list[str]] = {}

PORT_KEYWORDS = {
    21:   "ftp",
    22:   "ssh",
    23:   "telnet",
    80:   "http",
    443:  "ssl tls",
    445:  "smb",
    3389: "remote desktop rdp",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017:"mongodb",
}


def lookup_cves(port: int, max_results: int = 3) -> list[str]:
    if port in _CACHE:
        return _CACHE[port]
    keyword = PORT_KEYWORDS.get(port)
    if not keyword:
        _CACHE[port] = []
        return []
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"keywordSearch": keyword, "resultsPerPage": max_results}
        resp = requests.get(url, params=params, timeout=8)
        resp.raise_for_status()
        items = resp.json().get("vulnerabilities", [])
        cves = [item["cve"]["id"] for item in items]
        _CACHE[port] = cves
        return cves
    except Exception:
        _CACHE[port] = []
        return []
