from flask import Flask, request, jsonify, render_template_string
import json
import yaml
from nsca.parser import load_config
from nsca.diff_engine import diff
from nsca.adapters import ADAPTERS
import tempfile, os
from pathlib import Path

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Security Change Analyzer</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
  header{background:#1e293b;border-bottom:1px solid #334155;padding:20px 40px;display:flex;align-items:center;gap:12px}
  header h1{font-size:1.25rem;font-weight:600;color:#f1f5f9}
  header span{font-size:.75rem;background:#0ea5e9;color:#fff;padding:2px 10px;border-radius:20px}
  main{max-width:1100px;margin:40px auto;padding:0 24px}
  .card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:28px;margin-bottom:24px}
  .card h2{font-size:.9rem;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:.06em;margin-bottom:20px}
  .tabs{display:flex;gap:8px;margin-bottom:20px}
  .tab{padding:8px 18px;border-radius:8px;border:1px solid #334155;background:transparent;color:#94a3b8;cursor:pointer;font-size:.85rem}
  .tab.active{background:#0ea5e9;color:#fff;border-color:#0ea5e9}
  .upload-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  .drop-zone{border:2px dashed #334155;border-radius:10px;padding:32px;text-align:center;cursor:pointer;transition:.2s;min-height:160px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px}
  .drop-zone:hover,.drop-zone.drag{border-color:#0ea5e9;background:#0ea5e910}
  .drop-zone.loaded{border-color:#22c55e;background:#22c55e10}
  .drop-zone .icon{font-size:2rem}
  .drop-zone .label{font-size:.85rem;color:#64748b}
  .drop-zone .fname{font-size:.82rem;color:#22c55e;font-weight:600}
  input[type=file]{display:none}
  label.inp{display:block;font-size:.82rem;color:#94a3b8;margin-bottom:6px}
  textarea{width:100%;height:160px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;padding:12px;font-family:monospace;font-size:.82rem;resize:vertical}
  textarea:focus{outline:none;border-color:#0ea5e9}
  button.analyze{margin-top:16px;width:100%;padding:12px;background:#0ea5e9;color:#fff;border:none;border-radius:8px;font-size:.95rem;font-weight:600;cursor:pointer}
  button.analyze:hover{background:#0284c7}
  button.analyze:disabled{background:#334155;cursor:not-allowed}
  .summary-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
  .stat{background:#0f172a;border-radius:8px;padding:16px;text-align:center}
  .stat .num{font-size:2rem;font-weight:700}
  .stat .lbl{font-size:.75rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-top:4px}
  table{width:100%;border-collapse:collapse}
  th{text-align:left;padding:10px 14px;font-size:.78rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid #334155}
  td{padding:12px 14px;font-size:.88rem;border-bottom:1px solid #0f172a;vertical-align:top}
  .badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:.72rem;font-weight:700}
  .CRITICAL{background:#7f1d1d;color:#fca5a5}
  .HIGH{background:#7c2d12;color:#fdba74}
  .MEDIUM{background:#713f12;color:#fde047}
  .LOW{background:#14532d;color:#86efac}
  .ADDED{background:#14532d;color:#86efac}
  .REMOVED{background:#7f1d1d;color:#fca5a5}
  .MODIFIED{background:#0c4a6e;color:#7dd3fc}
  .cve-list{margin-top:6px;display:flex;flex-wrap:wrap;gap:4px}
  .cve-tag{font-size:.68rem;background:#312e81;color:#a5b4fc;padding:2px 7px;border-radius:4px;text-decoration:none}
  .cve-tag:hover{background:#4338ca}
  .error{background:#7f1d1d;border:1px solid #991b1b;border-radius:8px;padding:14px 18px;color:#fca5a5;margin-top:16px;display:none}
  #results{display:none}
  .spinner{display:none;text-align:center;padding:20px;color:#64748b}
  .format-badge{font-size:.7rem;background:#1e3a5f;color:#7dd3fc;padding:2px 8px;border-radius:4px;margin-left:8px}
</style>
</head>
<body>
<header>
  <h1>Network Security Change Analyzer</h1>
  <span>v0.3.0</span>
</header>
<main>
  <div class="card">
    <h2>Input Mode</h2>
    <div class="tabs">
      <button class="tab active" onclick="setMode('paste')">Paste JSON/YAML</button>
      <button class="tab" onclick="setMode('upload')">Upload File</button>
    </div>

    <div id="mode-paste">
      <div class="upload-grid">
        <div>
          <label class="inp">BEFORE</label>
          <textarea id="before" placeholder='{"device": "fw-01", "rules": [...]}'></textarea>
        </div>
        <div>
          <label class="inp">AFTER</label>
          <textarea id="after" placeholder='{"device": "fw-01", "rules": [...]}'></textarea>
        </div>
      </div>
    </div>

    <div id="mode-upload" style="display:none">
      <div class="upload-grid">
        <div>
          <label class="inp">BEFORE FILE <span class="format-badge">.json .yaml .acl .iptables</span></label>
          <div class="drop-zone" id="drop-before" onclick="document.getElementById('file-before').click()"
               ondragover="dragOver(event,'drop-before')" ondragleave="dragLeave('drop-before')" ondrop="dropFile(event,'before')">
            <div class="icon">&#128196;</div>
            <div class="label">Click or drag & drop</div>
            <div class="fname" id="fname-before"></div>
          </div>
          <input type="file" id="file-before" accept=".json,.yaml,.yml,.acl,.iptables" onchange="fileChosen(this,'before')">
        </div>
        <div>
          <label class="inp">AFTER FILE <span class="format-badge">.json .yaml .acl .iptables</span></label>
          <div class="drop-zone" id="drop-after" onclick="document.getElementById('file-after').click()"
               ondragover="dragOver(event,'drop-after')" ondragleave="dragLeave('drop-after')" ondrop="dropFile(event,'after')">
            <div class="icon">&#128196;</div>
            <div class="label">Click or drag & drop</div>
            <div class="fname" id="fname-after"></div>
          </div>
          <input type="file" id="file-after" accept=".json,.yaml,.yml,.acl,.iptables" onchange="fileChosen(this,'after')">
        </div>
      </div>
    </div>

    <div class="error" id="error"></div>
    <button class="analyze" onclick="analyze()">Analyze Changes</button>
  </div>

  <div class="spinner" id="spinner">Analyzing and looking up CVEs...</div>

  <div id="results">
    <div class="summary-grid">
      <div class="stat"><div class="num" id="s-total">0</div><div class="lbl">Total</div></div>
      <div class="stat"><div class="num" style="color:#86efac" id="s-added">0</div><div class="lbl">Added</div></div>
      <div class="stat"><div class="num" style="color:#fca5a5" id="s-removed">0</div><div class="lbl">Removed</div></div>
      <div class="stat"><div class="num" style="color:#7dd3fc" id="s-modified">0</div><div class="lbl">Modified</div></div>
    </div>
    <div class="card">
      <h2>Changes <span id="cve-note" style="font-size:.75rem;color:#64748b;font-weight:400;text-transform:none"></span></h2>
      <table>
        <thead><tr><th>Type</th><th>ID</th><th>Action</th><th>Source</th><th>Port</th><th>Risk</th><th>CVEs</th></tr></thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </div>
</main>
<script>
  let mode = 'paste';
  let fileContents = {before: null, after: null};
  let fileNames    = {before: null, after: null};

  function setMode(m) {
    mode = m;
    document.getElementById('mode-paste').style.display  = m === 'paste'  ? '' : 'none';
    document.getElementById('mode-upload').style.display = m === 'upload' ? '' : 'none';
    document.querySelectorAll('.tab').forEach((t,i) => t.classList.toggle('active', (m==='paste'&&i===0)||(m==='upload'&&i===1)));
  }

  function dragOver(e, id) { e.preventDefault(); document.getElementById(id).classList.add('drag'); }
  function dragLeave(id)   { document.getElementById(id).classList.remove('drag'); }

  function dropFile(e, side) {
    e.preventDefault();
    dragLeave('drop-' + side);
    const file = e.dataTransfer.files[0];
    if (file) readFile(file, side);
  }

  function fileChosen(input, side) {
    if (input.files[0]) readFile(input.files[0], side);
  }

  function readFile(file, side) {
    const reader = new FileReader();
    reader.onload = e => {
      fileContents[side] = e.target.result;
      fileNames[side]    = file.name;
      document.getElementById('fname-' + side).textContent = file.name;
      document.getElementById('drop-' + side).classList.add('loaded');
    };
    reader.readAsText(file);
  }

  async function analyze() {
    const errorEl = document.getElementById('error');
    errorEl.style.display = 'none';
    document.getElementById('results').style.display = 'none';
    document.getElementById('spinner').style.display = 'block';

    let body;
    if (mode === 'paste') {
      let before, after;
      try {
        before = JSON.parse(document.getElementById('before').value);
        after  = JSON.parse(document.getElementById('after').value);
      } catch(e) {
        document.getElementById('spinner').style.display = 'none';
        errorEl.textContent = 'Invalid JSON: ' + e.message;
        errorEl.style.display = 'block';
        return;
      }
      body = JSON.stringify({mode: 'json', before, after});
    } else {
      if (!fileContents.before || !fileContents.after) {
        document.getElementById('spinner').style.display = 'none';
        errorEl.textContent = 'Please upload both files.';
        errorEl.style.display = 'block';
        return;
      }
      body = JSON.stringify({
        mode: 'file',
        before_content: fileContents.before, before_name: fileNames.before,
        after_content:  fileContents.after,  after_name:  fileNames.after,
      });
    }

    const res  = await fetch('/api/analyze', {method:'POST', headers:{'Content-Type':'application/json'}, body});
    const data = await res.json();
    document.getElementById('spinner').style.display = 'none';

    if (data.error) { errorEl.textContent = data.error; errorEl.style.display = 'block'; return; }

    document.getElementById('s-total').textContent    = data.summary.total;
    document.getElementById('s-added').textContent    = data.summary.added;
    document.getElementById('s-removed').textContent  = data.summary.removed;
    document.getElementById('s-modified').textContent = data.summary.modified;

    const cveCount = data.changes.reduce((n,c) => n + (c.cves ? c.cves.length : 0), 0);
    document.getElementById('cve-note').textContent = cveCount ? '— ' + cveCount + ' CVE(s) found' : '';

    document.getElementById('tbody').innerHTML = data.changes.map(c => {
      const cveHtml = c.cves && c.cves.length
        ? '<div class="cve-list">' + c.cves.map(cv =>
            '<a class="cve-tag" href="https://nvd.nist.gov/vuln/detail/' + cv + '" target="_blank">' + cv + '</a>'
          ).join('') + '</div>'
        : '<span style="color:#334155">—</span>';
      return '<tr>' +
        '<td><span class="badge ' + c.type + '">' + c.type + '</span></td>' +
        '<td>' + c.id + '</td><td>' + c.action + '</td><td>' + c.source + '</td><td>' + c.port + '</td>' +
        '<td><span class="badge ' + c.risk + '">' + c.risk + '</span></td>' +
        '<td>' + cveHtml + '</td></tr>';
    }).join('');

    document.getElementById('results').style.display = 'block';
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
        data = request.get_json()
        mode = data.get("mode", "json")

        if mode == "file":
            results = {}
            for side in ("before", "after"):
                content  = data[f"{side}_content"]
                filename = data[f"{side}_name"]
                ext      = Path(filename).suffix.lower()
                with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8") as f:
                    f.write(content)
                    tmp_path = f.name
                results[side] = load_config(tmp_path)
                os.unlink(tmp_path)
            before_cfg = results["before"]
            after_cfg  = results["after"]
        else:
            before_cfg = data["before"]
            after_cfg  = data["after"]

        result = diff(before_cfg, after_cfg)

        # CVE lookup
        from nsca.cve import lookup_cves
        for change in result["changes"]:
            change["cves"] = lookup_cves(change.get("port", 0))

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    app.run(debug=True)
