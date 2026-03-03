#!/usr/bin/env python3
import os, json, http.server, socketserver
from datetime import datetime

REPORTS_DIR = "/opt/qrecon/reports"
PORT = 5000

def get_reports():
    reports = []
    if not os.path.exists(REPORTS_DIR):
        return reports
    for f in sorted(os.listdir(REPORTS_DIR), reverse=True):
        if not (f.endswith(".html") and f.startswith("qrecon_")): continue
        parts = f.replace("qrecon_","").replace(".html","").split("_")
        target = ".".join(parts[:-2]) if len(parts) > 2 else f
        date_raw = parts[-2] if len(parts) >= 2 else ""
        date_fmt = date_raw[:4]+"-"+date_raw[4:6]+"-"+date_raw[6:] if len(date_raw)==8 else date_raw
        log = os.path.join(REPORTS_DIR, f.replace(".html",".log"))
        score, rating = "N/A", "UNKNOWN"
        if os.path.exists(log):
            try:
                scores = []
                with open(log) as lf:
                    for line in lf:
                        d = json.loads(line)
                        sev = d.get("result",{}).get("severity","UNKNOWN")
                        scores.append({"CRITICAL":100,"HIGH":75,"MEDIUM":50,"LOW":25}.get(sev,10))
                if scores:
                    avg = sum(scores)/len(scores)
                    score = str(round(avg,1))
                    rating = "CRITICAL" if avg>=75 else "HIGH" if avg>=50 else "MEDIUM" if avg>=25 else "LOW"
            except: pass
        reports.append({"file":f,"target":target,"score":score,"rating":rating,"date":date_fmt})
    return reports

def build_page():
    reports = get_reports()
    total = len(reports)
    cc = sum(1 for r in reports if r["rating"]=="CRITICAL")
    hc = sum(1 for r in reports if r["rating"]=="HIGH")
    mc = sum(1 for r in reports if r["rating"]=="MEDIUM")
    lc = sum(1 for r in reports if r["rating"]=="LOW")

    sev_color = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308","LOW":"#22c55e","UNKNOWN":"#6b7280"}
    sev_bg    = {"CRITICAL":"#fef2f2","HIGH":"#fff7ed","MEDIUM":"#fefce8","LOW":"#f0fdf4","UNKNOWN":"#f9fafb"}

    rows = ""
    for r in reports:
        c = sev_color.get(r["rating"],"#6b7280")
        bg = sev_bg.get(r["rating"],"#f9fafb")
        rows += (
            "<tr>"
            "<td class=\"td-target\">" + r["target"] + "</td>"
            "<td class=\"td-date\">" + r["date"] + "</td>"
            "<td><span class=\"badge\" style=\"color:" + c + ";background:" + bg + "\">" + r["rating"] + "</span></td>"
            "<td class=\"td-score\">" + r["score"] + " <span>/100</span></td>"
            "<td><a class=\"btn\" href=\"/reports/" + r["file"] + "\" target=\"_blank\">View</a></td>"
            "</tr>"
        )
    if not rows:
        rows = "<tr><td colspan=\"5\" class=\"empty\">No reports yet. Run a scan first.</td></tr>"

    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Q-Recon Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Lora:wght@400;600&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#111111;color:#e5e5e5;font-size:15px;line-height:1.6;min-height:100vh}
.sidebar{position:fixed;top:0;left:0;width:220px;height:100vh;background:#0a0a0a;
  border-right:1px solid #222;padding:40px 28px;display:flex;flex-direction:column;gap:40px}
.logo{font-size:13px;font-weight:700;letter-spacing:3px;text-transform:uppercase;color:#fff}
.logo span{color:#6b7280}
.nav-label{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#4b5563;
  font-weight:600;margin-bottom:10px}
.nav a{display:block;font-size:13px;color:#9ca3af;text-decoration:none;
  padding:8px 12px;border-radius:6px;margin-bottom:2px}
.nav a.active{background:#1f1f1f;color:#fff}
.main{margin-left:220px;padding:52px 52px 80px}
.page-title{font-family:'Lora',serif;font-size:28px;font-weight:400;color:#fff;margin-bottom:4px}
.page-sub{font-size:13px;color:#6b7280;margin-bottom:40px;font-weight:300}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:48px}
.stat{background:#1a1a1a;border:1px solid #222;border-radius:12px;padding:24px}
.stat-n{font-family:'Lora',serif;font-size:40px;line-height:1;margin-bottom:6px}
.stat-l{font-size:11px;letter-spacing:1px;text-transform:uppercase;color:#6b7280;font-weight:500}
.sec-label{font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#6b7280;
  font-weight:600;border-bottom:1px solid #222;padding-bottom:10px;margin-bottom:0}
table{width:100%;border-collapse:collapse;background:#1a1a1a;
  border:1px solid #222;border-radius:12px;overflow:hidden;margin-top:0}
th{font-size:10px;letter-spacing:1px;text-transform:uppercase;color:#6b7280;
  font-weight:500;padding:14px 20px;text-align:left;border-bottom:1px solid #222;background:#141414}
td{padding:15px 20px;border-bottom:1px solid #1f1f1f;vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:#1f1f1f}
.td-target{font-weight:500;color:#fff;font-size:14px}
.td-date{font-size:13px;color:#6b7280}
.td-score{font-size:14px;font-weight:600;color:#fff}
.td-score span{font-size:12px;color:#6b7280;font-weight:400}
.badge{font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase;
  padding:4px 10px;border-radius:5px;white-space:nowrap}
.btn{font-size:12px;padding:6px 18px;border:1px solid #333;border-radius:6px;
  background:transparent;color:#9ca3af;text-decoration:none;display:inline-block;
  transition:all 0.15s}
.btn:hover{background:#fff;color:#111;border-color:#fff}
.empty{text-align:center;padding:60px;color:#4b5563;font-size:14px}
@media(max-width:768px){.sidebar{display:none}.main{margin-left:0;padding:24px}}
</style>
</head>
<body>
<div class="sidebar">
  <div class="logo">Q<span>-</span>RECON</div>
  <div>
    <div class="nav-label">Navigation</div>
    <div class="nav">
      <a href="/" class="active">Dashboard</a>
    </div>
  </div>
  <div style="margin-top:auto;font-size:11px;color:#374151;line-height:1.8">
    v1.0<br>Quantum Assessment<br>Framework
  </div>
</div>
<div class="main">
  <h1 class="page-title">Assessment Dashboard</h1>
  <p class="page-sub">All quantum-resilience assessment reports</p>
  <div class="stats">
    <div class="stat">
      <div class="stat-n" style="color:#fff">""" + str(total) + """</div>
      <div class="stat-l">Total Reports</div>
    </div>
    <div class="stat">
      <div class="stat-n" style="color:#ef4444">""" + str(cc) + """</div>
      <div class="stat-l">Critical Risk</div>
    </div>
    <div class="stat">
      <div class="stat-n" style="color:#eab308">""" + str(mc) + """</div>
      <div class="stat-l">Medium Risk</div>
    </div>
    <div class="stat">
      <div class="stat-n" style="color:#22c55e">""" + str(lc) + """</div>
      <div class="stat-l">Low Risk</div>
    </div>
  </div>
  <p class="sec-label">Reports</p>
  <table>
    <thead><tr><th>Target</th><th>Date</th><th>Risk Level</th><th>Score</th><th>Action</th></tr></thead>
    <tbody>""" + rows + """</tbody>
  </table>
</div>
</body>
</html>"""

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/dashboard"):
            self._respond(build_page())
        elif self.path.startswith("/reports/"):
            fpath = os.path.join(REPORTS_DIR, self.path.replace("/reports/",""))
            if os.path.exists(fpath):
                with open(fpath,"rb") as f: self._respond(f.read().decode(), content_type="text/html")
            else:
                self.send_response(404); self.end_headers()
        else:
            self.send_response(404); self.end_headers()

    def _respond(self, html, content_type="text/html"):
        self.send_response(200)
        self.send_header("Content-type", content_type)
        self.end_headers()
        self.wfile.write(html.encode())

    def log_message(self, fmt, *args):
        print("  [+] " + args[0])

if __name__ == "__main__":
    print()
    print("=" * 50)
    print("  Q-RECON DASHBOARD")
    print("=" * 50)
    print("  URL  : http://localhost:" + str(PORT))
    print("  Stop : Ctrl+C")
    print()
    with socketserver.TCPServer(("", PORT), Handler) as s:
        s.serve_forever()
