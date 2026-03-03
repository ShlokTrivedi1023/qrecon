
import os
from datetime import datetime

class ReportEngine:
    def __init__(self, target, results, output_dir):
        self.target = target
        self.results = results
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = self.target.replace(".", "_")
        for f in os.listdir(self.output_dir):
            if f.endswith(".html") or f.endswith(".txt"):
                try: os.remove(os.path.join(self.output_dir, f))
                except: pass
        txt = os.path.join(self.output_dir, "qrecon_" + safe + "_" + ts + ".txt")
        html = os.path.join(self.output_dir, "qrecon_" + safe + "_" + ts + ".html")
        with open(txt, "w") as f: f.write(self._text())
        with open(html, "w") as f: f.write(self._html())
        print("[OK] Report: " + html)
        return txt

    def _rating(self, s):
        if s >= 75: return "Critical"
        elif s >= 50: return "High"
        elif s >= 25: return "Medium"
        else: return "Low"

    def _sev_color(self, sev):
        return {"CRITICAL":"#b91c1c","HIGH":"#c2410c","MEDIUM":"#a16207",
                "LOW":"#15803d","INFO":"#1d4ed8","UNKNOWN":"#6b7280"}.get(sev,"#6b7280")

    def _sev_bg(self, sev):
        return {"CRITICAL":"#fff1f2","HIGH":"#fff7ed","MEDIUM":"#fefce8",
                "LOW":"#f0fdf4","INFO":"#eff6ff","UNKNOWN":"#f9fafb"}.get(sev,"#f9fafb")

    def _text(self):
        s = self.results.get("quantum_risk_score", 0)
        lines = ["Q-RECON REPORT", "="*60,
                 "Target : " + self.target,
                 "Date   : " + datetime.now().strftime("%Y-%m-%d %H:%M"),
                 "Score  : " + str(round(s,1)) + "/100 (" + self._rating(s) + " Risk)", ""]
        for k in ["rsa","ecc","dh","signature","symmetric","hash"]:
            if k in self.results:
                r = self.results[k]
                lines += ["-"*60, r.get("module",k),
                          "Severity : " + r.get("severity","N/A"),
                          "Finding  : " + r.get("finding","N/A")]
                for i,s2 in enumerate(r.get("remediation",[]),1):
                    lines.append("  " + str(i) + ". " + s2)
                lines.append("")
        return "\n".join(lines)

    def _html(self):
        score = self.results.get("quantum_risk_score", 0)
        rating = self._rating(score)
        now = datetime.now()
        ds = now.strftime("%d %B %Y")
        ts = now.strftime("%H:%M")
        rc = self._sev_color(rating.upper())

        sevs = [self.results[k].get("severity","UNKNOWN")
                for k in ["rsa","ecc","dh","signature","symmetric","hash"]
                if k in self.results]
        cc = sevs.count("CRITICAL")
        hc = sevs.count("HIGH")
        mc = sevs.count("MEDIUM")
        lc = sevs.count("LOW")

        mdefs = [
            ("rsa",       "RSA Cryptographic Assessment"),
            ("ecc",       "ECC Curve Exposure"),
            ("dh",        "Key Exchange Assessment"),
            ("signature", "Digital Signature Integrity"),
            ("symmetric", "Symmetric Encryption Strength"),
            ("hash",      "Hash Function Exposure"),
        ]

        rows = ""
        for k,t in mdefs:
            if k not in self.results: continue
            r = self.results[k]
            sev = r.get("severity","UNKNOWN")
            c = self._sev_color(sev)
            bg = self._sev_bg(sev)
            rows += (
                "<tr>"
                "<td class=\"td-name\">" + t + "</td>"
                "<td><span class=\"badge\" style=\"color:" + c + ";background:" + bg + "\">" + sev + "</span></td>"
                "<td class=\"td-find\">" + r.get("finding","") + "</td>"
                "</tr>"
            )

        cards = ""
        for i,(k,t) in enumerate(mdefs,1):
            if k not in self.results: continue
            r = self.results[k]
            sev = r.get("severity","UNKNOWN")
            c = self._sev_color(sev)
            bg = self._sev_bg(sev)
            risk = r.get("risk_description","")
            quantum = r.get("quantum_context","")
            rem = "".join("<li>" + s + "</li>" for s in r.get("remediation",[]))
            q_html = ("<div class=\"qbox\"><div class=\"qbox-icon\">&#x269B;</div><p>" + quantum + "</p></div>") if quantum else ""
            cards += (
                "<div class=\"card\">"
                "<div class=\"card-head\">"
                "<div class=\"card-left\">"
                "<span class=\"card-num\">" + str(i).zfill(2) + "</span>"
                "<h3>" + t + "</h3>"
                "</div>"
                "<span class=\"badge\" style=\"color:" + c + ";background:" + bg + "\">" + sev + "</span>"
                "</div>"
                "<p class=\"card-finding\">" + r.get("finding","") + "</p>"
                + ("<p class=\"card-risk\">" + risk + "</p>" if risk else "")
                + q_html
                + ("<div class=\"rem\"><p class=\"rem-title\">Recommended Actions</p><ol>" + rem + "</ol></div>" if rem else "")
                + "</div>"
            )

        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Q-Recon &mdash; """ + self.target + """</title>
<link href="https://fonts.googleapis.com/css2?family=Lora:wght@400;600&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#f8f7f4;color:#1a1a1a;font-size:16px;line-height:1.7}
.page{max-width:860px;margin:0 auto;padding:64px 48px 100px}

/* HEADER */
.hdr{display:flex;justify-content:space-between;align-items:flex-end;
  padding-bottom:28px;border-bottom:2px solid #1a1a1a;margin-bottom:56px;flex-wrap:wrap;gap:16px}
.brand{font-family:'Inter',sans-serif;font-size:11px;font-weight:600;
  letter-spacing:4px;text-transform:uppercase;color:#1a1a1a}
.brand span{color:#9ca3af}
.hdr-right{text-align:right}
.hdr-target{font-family:'Lora',serif;font-size:22px;color:#1a1a1a}
.hdr-date{font-size:12px;color:#9ca3af;margin-top:3px;font-weight:300}
.conf{display:inline-block;margin-top:6px;font-size:10px;letter-spacing:2px;
  text-transform:uppercase;color:#b91c1c;border:1px solid #fecaca;
  padding:2px 10px;border-radius:3px;font-weight:500}

/* SCORE HERO */
.score-hero{display:grid;grid-template-columns:1fr 1fr;gap:0;
  background:#1a1a1a;border-radius:16px;overflow:hidden;margin-bottom:48px}
.score-left{padding:48px;display:flex;flex-direction:column;justify-content:center}
.score-label{font-size:11px;letter-spacing:3px;text-transform:uppercase;
  color:#6b7280;font-weight:500;margin-bottom:12px}
.score-num{font-family:'Lora',serif;font-size:80px;line-height:1;color:""" + rc + """;margin-bottom:4px}
.score-denom{font-size:14px;color:#6b7280;margin-bottom:20px}
.score-rating{font-size:20px;font-weight:600;color:""" + rc + """}
.score-sublabel{font-size:13px;color:#6b7280;margin-top:4px;font-weight:300}
.score-right{padding:48px;border-left:1px solid #2d2d2d;display:flex;flex-direction:column;justify-content:center;gap:16px}
.count-row{display:flex;align-items:center;gap:14px}
.count-n{font-family:'Lora',serif;font-size:32px;line-height:1;min-width:40px}
.count-info{}
.count-label{font-size:11px;letter-spacing:1px;text-transform:uppercase;color:#6b7280;font-weight:500}
.count-bar{height:3px;border-radius:2px;margin-top:6px;min-width:8px}

/* SECTION LABEL */
.sec{font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#9ca3af;
  font-weight:600;border-bottom:1px solid #e5e5e1;padding-bottom:10px;
  margin-top:52px;margin-bottom:0}

/* SUMMARY TABLE */
table{width:100%;border-collapse:collapse;margin-top:0;background:#fff;
  border:1px solid #e5e5e1;border-radius:12px;overflow:hidden}
th{font-size:11px;letter-spacing:1px;text-transform:uppercase;color:#9ca3af;
  font-weight:500;padding:14px 20px;text-align:left;border-bottom:1px solid #f0f0ec;background:#fafaf8}
td{padding:14px 20px;border-bottom:1px solid #f5f5f1;vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:#fafaf8}
.td-name{font-weight:500;color:#1a1a1a;font-size:14px}
.td-find{font-size:13px;color:#6b7280}
.badge{font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase;
  padding:4px 10px;border-radius:5px;white-space:nowrap;font-family:'Inter',sans-serif}

/* DETAIL CARDS */
.card{background:#fff;border:1px solid #e5e5e1;border-radius:14px;
  padding:32px;margin-top:16px}
.card-head{display:flex;justify-content:space-between;align-items:flex-start;
  margin-bottom:16px;gap:16px;flex-wrap:wrap}
.card-left{display:flex;align-items:center;gap:14px}
.card-num{font-size:12px;color:#d1d5db;font-weight:500;font-family:'Inter',sans-serif;
  background:#f9f9f7;border:1px solid #e5e5e1;padding:3px 8px;border-radius:5px}
.card h3{font-family:'Lora',serif;font-size:19px;font-weight:600;color:#1a1a1a}
.card-finding{font-size:16px;font-weight:600;color:#1a1a1a;
  border-bottom:1px solid #f5f5f1;padding-bottom:14px;margin-bottom:14px}
.card-risk{font-size:14px;color:#6b7280;line-height:1.8;margin-bottom:16px}
.qbox{display:flex;gap:12px;background:#eff6ff;border:1px solid #bfdbfe;
  border-radius:10px;padding:14px 16px;margin-bottom:16px}
.qbox-icon{font-size:18px;flex-shrink:0;color:#2563eb;margin-top:2px}
.qbox p{font-size:13px;color:#1d4ed8;line-height:1.7}
.rem{padding-top:16px;border-top:1px solid #f5f5f1}
.rem-title{font-size:10px;letter-spacing:2px;text-transform:uppercase;
  color:#9ca3af;font-weight:600;margin-bottom:10px}
.rem ol{padding-left:18px}
.rem ol li{font-size:13px;color:#374151;line-height:1.8;margin-bottom:3px}

/* FOOTER */
.footer{margin-top:64px;padding-top:20px;border-top:1px solid #e5e5e1;
  display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}
.footer p{font-size:12px;color:#9ca3af;line-height:1.9;font-weight:300}

@media(max-width:640px){
  .page{padding:32px 20px 60px}
  .score-hero{grid-template-columns:1fr}
  .score-left{padding:32px}
  .score-right{padding:32px;border-left:none;border-top:1px solid #2d2d2d}
  .score-num{font-size:64px}
  .hdr{flex-direction:column}
  .hdr-right{text-align:left}
}
</style>
</head>
<body>
<div class="page">

<header class="hdr">
  <div class="brand">Q<span>-</span>RECON &nbsp;/&nbsp; QUANTUM ASSESSMENT</div>
  <div class="hdr-right">
    <div class="hdr-target">""" + self.target + """</div>
    <div class="hdr-date">""" + ds + """ &nbsp;&middot;&nbsp; """ + ts + """</div>
    <div class="conf">Confidential</div>
  </div>
</header>

<div class="score-hero">
  <div class="score-left">
    <p class="score-label">Quantum Risk Score</p>
    <div class="score-num">""" + str(round(score,1)) + """</div>
    <div class="score-denom">out of 100</div>
    <div class="score-rating">""" + rating + """ Risk</div>
    <div class="score-sublabel">Overall cryptographic quantum exposure</div>
  </div>
  <div class="score-right">
    <div class="count-row">
      <span class="count-n" style="color:#ef4444">""" + str(cc) + """</span>
      <div class="count-info">
        <div class="count-label">Critical</div>
        <div class="count-bar" style="background:#ef4444;width:""" + str(min(cc*40,160)) + """px"></div>
      </div>
    </div>
    <div class="count-row">
      <span class="count-n" style="color:#f97316">""" + str(hc) + """</span>
      <div class="count-info">
        <div class="count-label">High</div>
        <div class="count-bar" style="background:#f97316;width:""" + str(min(hc*40,160)) + """px"></div>
      </div>
    </div>
    <div class="count-row">
      <span class="count-n" style="color:#eab308">""" + str(mc) + """</span>
      <div class="count-info">
        <div class="count-label">Medium</div>
        <div class="count-bar" style="background:#eab308;width:""" + str(min(mc*40,160)) + """px"></div>
      </div>
    </div>
    <div class="count-row">
      <span class="count-n" style="color:#22c55e">""" + str(lc) + """</span>
      <div class="count-info">
        <div class="count-label">Low</div>
        <div class="count-bar" style="background:#22c55e;width:""" + str(min(lc*40,160)) + """px"></div>
      </div>
    </div>
  </div>
</div>

<p class="sec">Summary of Findings</p>
<table>
  <thead><tr><th>Assessment Module</th><th>Severity</th><th>Key Finding</th></tr></thead>
  <tbody>""" + rows + """</tbody>
</table>

<p class="sec">Detailed Analysis</p>
""" + cards + """

<footer class="footer">
  <p>Q-Recon v1.0 &nbsp;&middot;&nbsp; Quantum-Resilience Offensive Security Assessment<br>
  Report generated """ + ds + """ at """ + ts + """</p>
  <p style="text-align:right">For authorized security testing only.<br>
  Unauthorized use is illegal under applicable law.</p>
</footer>

</div>
</body>
</html>"""
