from flask import Flask, request, jsonify, render_template_string
import json
import os
import tempfile

from nsca.parser import load_config
from nsca.diff_engine import diff

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Security Change Analyzer</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
  header { background: #1e293b; border-bottom: 1px solid #334155; padding: 20px 40px; display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 1.25rem; font-weight: 600; color: #f1f5f9; }
  header span { font-size: 0.75rem; background: #0ea5e9; color: #fff; padding: 2px 10px; border-radius: 20px; }
  main { max-width: 1000px; margin: 40px auto; padding: 0 24px; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 28px; margin-bottom: 24px; }
  .card h2 { font-size: 0.9rem; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: .06em; margin-bottom: 20px; }
  .upload-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  label { display: block; font-size: 0.82rem; color: #94a3b8; margin-bottom: 6px; }
  textarea { width: 100%; height: 180px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #e2e8f0; padding: 12px; font-family: monospace; font-size: 0.82rem; resize: vertical; }
  textarea:focus { outline: none; border-color: #0ea5e9; }
  button { margin-top: 16px; width: 100%; padding: 12px; background: #0ea5e9; color: #fff; border: none; border-radius: 8px; font-size: 0.95rem; font-weight: 600; cursor: pointer; }
  button:hover { background: #0284c7; }
  #results { display: none; }
  .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
  .stat { background: #0f172a; border-radius: 8px; padding: 16px; text-align: center; }
  .stat .num { font-size: 2rem; font-weight: 700; }
  .stat .lbl { font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: .05em; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 10px 14px; font-size: 0.78rem; color: #64748b; text-transform: uppercase; letter-spacing: .05em; border-bottom: 1px solid #334155; }
  td { padding: 12px 14px; font-size: 0.88rem; border-bottom: 1px solid #1e293b; }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 0.72rem; font-weight: 700; }
  .CRITICAL { background: #7f1d1d; color: #fca5a5; }
  .HIGH     { background: #7c2d12; color: #fdba74; }
  .MEDIUM   { background: #713f12; color: #fde047; }
  .LOW      { background: #14532d; color: #86efac; }
  .ADDED    { background: #14532d; color: #86efac; }
  .REMOVED  { background: #7f1d1d; color: #fca5a5; }
  .MODIFIED { background: #0c4a6e; color: #7dd3fc; }
  .error { background: #7f1d1d; border: 1px solid #991b1b; border-radius: 8px; padding: 14px 18px; color: #fca5a5; margin-top: 16px; display: none; }
</style>
</head>
<body>
<header>
  <h1>Network Security Change Analyzer</h1>
  <span>v0.2.0</span>
</header>
<main>
  <div class="card">
    <h2>Paste Configurations</h2>
    <div class="upload-grid">
      <div>
        <label>BEFORE (JSON)</label>
        <textarea id="before" placeholder=\'{"device": "fw-01", "rules": [...]}\'></textarea>
      </div>
      <div>
        <label>AFTER (JSON)</label>
        <textarea id="after" placeholder=\'{"device": "fw-01", "rules": [...]}\'></textarea>
      </div>
    </div>
    <div class="error" id="error"></div>
    <button onclick="analyze()">Analyze Changes</button>
  </div>

  <div id="results">
    <div class="summary-grid">
      <div class="stat"><div class="num" id="s-total">0</div><div class="lbl">Total</div></div>
      <div class="stat"><div class="num" style="color:#86efac" id="s-added">0</div><div class="lbl">Added</div></div>
      <div class="stat"><div class="num" style="color:#fca5a5" id="s-removed">0</div><div class="lbl">Removed</div></div>
      <div class="stat"><div class="num" style="color:#7dd3fc" id="s-modified">0</div><div class="lbl">Modified</div></div>
    </div>
    <div class="card">
      <h2>Changes</h2>
      <table>
        <thead><tr><th>Type</th><th>ID</th><th>Action</th><th>Source</th><th>Port</th><th>Risk</th></tr></thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </div>
</main>
<script>
async function analyze() {
  const errorEl = document.getElementById("error");
  errorEl.style.display = "none";
  let before, after;
  try {
    before = JSON.parse(document.getElementById("before").value);
    after  = JSON.parse(document.getElementById("after").value);
  } catch(e) {
    errorEl.textContent = "Invalid JSON: " + e.message;
    errorEl.style.display = "block";
    return;
  }
  const res = await fetch("/api/analyze", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({before, after})
  });
  const data = await res.json();
  if (data.error) {
    errorEl.textContent = data.error;
    errorEl.style.display = "block";
    return;
  }
  document.getElementById("s-total").textContent    = data.summary.total;
  document.getElementById("s-added").textContent    = data.summary.added;
  document.getElementById("s-removed").textContent  = data.summary.removed;
  document.getElementById("s-modified").textContent = data.summary.modified;
  const tbody = document.getElementById("tbody");
  tbody.innerHTML = data.changes.map(c => `
    <tr>
      <td><span class="badge ${c.type}">${c.type}</span></td>
      <td>${c.id}</td>
      <td>${c.action}</td>
      <td>${c.source}</td>
      <td>${c.port}</td>
      <td><span class="badge ${c.risk}">${c.risk}</span></td>
    </tr>`).join("");
  document.getElementById("results").style.display = "block";
}
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/api/analyze", methods=["POST"])
def analyze():
    try:
        data   = request.get_json()
        before = data["before"]
        after  = data["after"]
        result = diff(before, after)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    app.run(debug=True)
