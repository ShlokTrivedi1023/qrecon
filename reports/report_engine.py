
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

    def _color(self, sev):
        return {"CRITICAL":"#c0392b","HIGH":"#d35400","MEDIUM":"#b7950b",
                "LOW":"#1e8449","INFO":"#1a5276","UNKNOWN":"#707070"}.get(sev,"#707070")

    def _text(self):
        s = self.results.get("quantum_risk_score", 0)
        lines = ["Q-RECON REPORT", "=" * 50,
                 "Target : " + self.target,
                 "Date   : " + datetime.now().strftime("%Y-%m-%d %H:%M"),
                 "Score  : " + str(round(s,1)) + "/100 (" + self._rating(s) + " Risk)", ""]
        for k in ["rsa","ecc","dh","signature","symmetric","hash"]:
            if k in self.results:
                r = self.results[k]
                lines += ["-"*50, r.get("module",k),
                          "Severity : " + r.get("severity","N/A"),
                          "Finding  : " + r.get("finding","N/A")]
                for i,s2 in enumerate(r.get("remediation",[]),1):
                    lines.append("  " + str(i) + ". " + s2)
                lines.append("")
        return "\n".join(lines)

    def _html(self):
        score = self.results.get("quantum_risk_score", 0)
        rating = self._rating(score)
        rc = self._color(rating.upper())
        now = datetime.now()
        ds = now.strftime("%d %B %Y")
        ts = now.strftime("%H:%M")

        sevs = [self.results[k].get("severity","UNKNOWN")
                for k in ["rsa","ecc","dh","signature","symmetric","hash"]
                if k in self.results]

        mdefs = [("rsa","RSA Assessment"),("ecc","ECC Exposure"),
                 ("dh","Key Exchange"),("signature","Digital Signatures"),
                 ("symmetric","Symmetric Encryption"),("hash","Hash Functions")]

        rows = ""
        for k,t in mdefs:
            if k not in self.results: continue
            r = self.results[k]
            sev = r.get("severity","UNKNOWN")
            c = self._color(sev)
            rows += ("<tr><td class=\"tn\">" + t + "</td>"
                     "<td><span style=\"color:" + c + ";font-weight:bold\">" + sev + "</span></td>"
                     "<td class=\"tf\">" + r.get("finding","") + "</td></tr>")

        cards = ""
        for i,(k,t) in enumerate(mdefs,1):
            if k not in self.results: continue
            r = self.results[k]
            sev = r.get("severity","UNKNOWN")
            c = self._color(sev)
            risk = r.get("risk_description","")
            quantum = r.get("quantum_context","")
            rem = "".join("<li>" + s + "</li>" for s in r.get("remediation",[]))
            qb = ("<div class=\"qnote\">Quantum context: " + quantum + "</div>") if quantum else ""
            cards += ("<div class=\"card\">"
                      "<div class=\"ch\"><span class=\"cn\">" + str(i) + "</span>"
                      "<h3 class=\"ct\">" + t + "</h3>"
                      "<span style=\"color:" + c + ";font-weight:bold;font-size:13px\">" + sev + "</span></div>"
                      "<p class=\"cf\">" + r.get("finding","") + "</p>"
                      + ("<p class=\"cr\">" + risk + "</p>" if risk else "")
                      + qb
                      + ("<div class=\"rem\"><p class=\"rl\">Recommended actions</p><ol>" + rem + "</ol></div>" if rem else "")
                      + "</div>")

        return ("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Q-Recon Report</title>
<style>
body{font-family:Georgia,serif;background:#fff;color:#111;font-size:16px;line-height:1.7;margin:0}
.page{max-width:800px;margin:0 auto;padding:64px 48px 96px}
.hdr{border-bottom:2px solid #111;padding-bottom:20px;margin-bottom:44px}
.htag{font-size:12px;letter-spacing:3px;text-transform:uppercase;color:#888;font-family:Arial,sans-serif;margin-bottom:6px}
.htarget{font-size:26px;font-weight:normal;color:#111;margin-bottom:4px}
.hmeta{font-size:13px;color:#888;font-family:Arial,sans-serif}
.snum{font-size:60px;font-weight:normal;line-height:1;color:""" + rc + """}
.srating{font-size:20px;color:""" + rc + """;margin-bottom:4px}
.ssub{font-size:14px;color:#555;font-family:Arial,sans-serif;margin-bottom:32px}
.counts{display:flex;border:1px solid #ddd;margin-bottom:48px;font-family:Arial,sans-serif}
.cc{flex:1;padding:14px 16px;border-right:1px solid #ddd;text-align:center}
.cc:last-child{border-right:none}
.cn2{font-size:26px;font-weight:bold;display:block;margin-bottom:2px}
.cl{font-size:11px;letter-spacing:1px;text-transform:uppercase;color:#888}
.slbl{font-size:11px;letter-spacing:3px;text-transform:uppercase;color:#888;font-family:Arial,sans-serif;border-bottom:1px solid #ddd;padding-bottom:8px;margin-top:48px;margin-bottom:0}
table{width:100%;border-collapse:collapse;font-family:Arial,sans-serif;font-size:14px}
th{font-size:11px;letter-spacing:1px;text-transform:uppercase;color:#888;font-weight:normal;padding:11px 14px;text-align:left;border-bottom:1px solid #ddd;background:#fafafa}
td{padding:12px 14px;border-bottom:1px solid #eee;vertical-align:top}
tr:last-child td{border-bottom:none}
.tn{font-weight:bold;color:#111;white-space:nowrap}
.tf{color:#444;font-size:13px}
.card{padding:28px 0;border-bottom:1px solid #eee}
.card:last-child{border-bottom:none}
.ch{display:flex;align-items:baseline;gap:12px;margin-bottom:12px;flex-wrap:wrap}
.cn{font-size:13px;color:#bbb;font-family:Arial,sans-serif;min-width:18px}
.ct{font-size:17px;font-weight:normal;color:#111;flex:1}
.cf{font-size:15px;font-weight:bold;color:#111;margin-bottom:8px;padding-left:30px}
.cr{font-size:14px;color:#444;line-height:1.75;margin-bottom:12px;padding-left:30px}
.qnote{font-size:13px;color:#1a5276;background:#eaf2ff;border-left:3px solid #1a5276;padding:10px 14px;margin:12px 0 12px 30px;font-family:Arial,sans-serif;line-height:1.65}
.rem{padding-left:30px;margin-top:14px}
.rl{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#888;font-family:Arial,sans-serif;margin-bottom:8px}
ol{padding-left:16px}
ol li{font-size:13px;color:#333;line-height:1.75;margin-bottom:3px;font-family:Arial,sans-serif}
.footer{margin-top:56px;padding-top:18px;border-top:1px solid #ddd;font-size:12px;color:#aaa;font-family:Arial,sans-serif;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;line-height:1.9}
@media(max-width:600px){.page{padding:28px 16px 60px}.counts{flex-wrap:wrap}.cc{min-width:50%}}
</style>
</head>
<body><div class="page">
<div class="hdr">
<p class="htag">Quantum Resilience Assessment Report</p>
<h1 class="htarget">""" + self.target + """</h1>
<p class="hmeta">""" + ds + """ &middot; """ + ts + """ &middot; Confidential</p>
</div>
<p class="snum">""" + str(round(score,1)) + """</p>
<p class="srating">""" + rating + """ Risk</p>
<p class="ssub">Overall quantum vulnerability score out of 100</p>
<div class="counts">
<div class="cc"><span class="cn2" style="color:#c0392b">""" + str(sevs.count("CRITICAL")) + """</span><span class="cl">Critical</span></div>
<div class="cc"><span class="cn2" style="color:#d35400">""" + str(sevs.count("HIGH")) + """</span><span class="cl">High</span></div>
<div class="cc"><span class="cn2" style="color:#b7950b">""" + str(sevs.count("MEDIUM")) + """</span><span class="cl">Medium</span></div>
<div class="cc"><span class="cn2" style="color:#1e8449">""" + str(sevs.count("LOW")) + """</span><span class="cl">Low</span></div>
</div>
<p class="slbl">Summary</p>
<table><thead><tr><th>Assessment</th><th>Severity</th><th>Key Finding</th></tr></thead>
<tbody>""" + rows + """</tbody></table>
<p class="slbl">Detailed Findings</p>
""" + cards + """
<div class="footer">
<div>Q-Recon v1.0 &middot; Quantum-Resilience Security Assessment<br>Generated """ + ds + """ at """ + ts + """</div>
<div style="text-align:right">Authorized security testing only.<br>Unauthorized use is illegal.</div>
</div>
</div></body></html>""")
