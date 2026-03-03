import os

BASE = "/opt/qrecon"

def write(path, content):
    full = os.path.join(BASE, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as f:
        f.write(content)
    print("[OK] " + path)

write("utils/__init__.py", "")
write("modules/__init__.py", "")
write("reports/__init__.py", "")
write("config/__init__.py", "")

write("utils/banner.py", """
def print_banner():
    print("\\033[96m")
    print(" Q-RECON: Quantum-Resilience Assessment Framework")
    print(" Version 1.0 | Authorized Penetration Testing ONLY")
    print("\\033[0m")
""")

write("utils/authorization.py", """
class AuthorizationGate:
    def __init__(self, target):
        self.target = target
    def verify(self):
        print()
        print("=" * 60)
        print("  AUTHORIZATION VERIFICATION - MANDATORY")
        print("=" * 60)
        print()
        print("  Target: " + self.target)
        print()
        print("  [1] Written authorization from target owner")
        print("  [2] Target is within agreed testing scope")
        print("  [3] You accept full legal responsibility")
        print()
        qs = [
            "Written authorization confirmed? (yes/no): ",
            "Target within authorized scope?    (yes/no): ",
            "Accept full legal responsibility?  (yes/no): ",
        ]
        responses = [input("  " + q).strip().lower() for q in qs]
        if all(r == "yes" for r in responses):
            print()
            print("  [OK] Authorization confirmed.")
            print("=" * 60)
            return True
        return False
""")

write("utils/logger.py", """
import os, json
from datetime import datetime

class QLogger:
    def __init__(self, target, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(output_dir, "qrecon_" + target.replace(".","_") + "_" + ts + ".log")
    def log_module_result(self, name, result):
        with open(self.log_file, "a") as f:
            f.write(json.dumps({"module": name, "result": result}) + "\\n")
""")

write("modules/enumerator.py", """
import ssl, socket

class TargetEnumerator:
    def __init__(self, target, port, verbose=False):
        self.target = target
        self.port = port
        self.verbose = verbose

    def run(self):
        r = {"target": self.target, "port": self.port, "reachable": False,
             "ip": None, "tls_version": None, "cipher_suite": None,
             "certificate": None, "raw_cert": None}
        try:
            r["ip"] = socket.gethostbyname(self.target)
            print("    [+] IP       : " + r["ip"])
        except Exception as e:
            print("    [!] DNS fail : " + str(e))
            return r
        try:
            socket.create_connection((self.target, self.port), timeout=10).close()
            r["reachable"] = True
            print("    [+] Port     : OPEN")
        except Exception as e:
            print("    [!] Port err : " + str(e))
            return r
        if self.port in [443, 8443]:
            r.update(self._tls())
        return r

    def _tls(self):
        info = {"tls_version": None, "cipher_suite": None, "certificate": None, "raw_cert": None}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.target, self.port), timeout=10) as s:
                with ctx.wrap_socket(s, server_hostname=self.target) as ss:
                    info["tls_version"] = ss.version()
                    print("    [+] TLS      : " + str(info["tls_version"]))
                    c = ss.cipher()
                    if c:
                        info["cipher_suite"] = c[0]
                        print("    [+] Cipher   : " + c[0])
                    cert = ss.getpeercert()
                    info["certificate"] = cert
                    info["raw_cert"] = ss.getpeercert(binary_form=True)
                    if cert:
                        subj = dict(x[0] for x in cert.get("subject", []))
                        print("    [+] Subject  : " + subj.get("commonName", "N/A"))
                        print("    [+] Expiry   : " + cert.get("notAfter", "N/A"))
        except Exception as e:
            print("    [!] TLS err  : " + str(e))
        return info
""")

write("modules/rsa_assessor.py", """
class RSAAssessor:
    def __init__(self, target, port, enum_results, verbose=False):
        self.enum_results = enum_results
    def run(self):
        r = {"module": "RSA Assessment", "severity": "UNKNOWN",
             "finding": "No data", "risk_description": "", "remediation": [], "quantum_context": ""}
        raw = self.enum_results.get("raw_cert")
        if not raw:
            r["finding"] = "No certificate found"
            return r
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa, ec
            pub = x509.load_der_x509_certificate(raw).public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                size = pub.key_size
                if size <= 2048:
                    r["severity"] = "CRITICAL"
                    r["finding"] = "RSA-" + str(size) + " detected - quantum vulnerable within 5-10 years"
                    r["risk_description"] = "Shor's algorithm breaks RSA-2048 with ~4000 qubits. NIST mandates migration by 2030."
                    r["remediation"] = ["Migrate to CRYSTALS-Kyber (NIST FIPS 203)", "Minimum interim: upgrade to RSA-4096"]
                elif size <= 4096:
                    r["severity"] = "MEDIUM"
                    r["finding"] = "RSA-" + str(size) + " - quantum vulnerable long term"
                    r["remediation"] = ["Plan post-quantum migration within 5 years"]
                else:
                    r["severity"] = "LOW"
                    r["finding"] = "RSA-" + str(size) + " - begin PQC migration planning"
                    r["remediation"] = ["Begin post-quantum migration planning"]
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                r["severity"] = "INFO"
                r["finding"] = "Certificate uses ECC not RSA"
            else:
                r["severity"] = "INFO"
                r["finding"] = "Non-RSA key type detected"
        except Exception as e:
            r["finding"] = "Could not parse certificate: " + str(e)
        return r
""")

write("modules/ecc_assessor.py", """
class ECCAssessor:
    def __init__(self, target, port, enum_results, verbose=False):
        self.enum_results = enum_results
    def run(self):
        r = {"module": "ECC Exposure Assessment", "severity": "UNKNOWN",
             "finding": "", "risk_description": "", "remediation": [], "quantum_context": ""}
        raw = self.enum_results.get("raw_cert")
        cipher = self.enum_results.get("cipher_suite", "")
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import ec
            pub = x509.load_der_x509_certificate(raw).public_key()
            if isinstance(pub, ec.EllipticCurvePublicKey):
                curve = pub.curve.name
                r["severity"] = "CRITICAL"
                r["finding"] = "ECC curve " + curve + " detected - quantum vulnerable"
                r["risk_description"] = "All ECC is broken by Shor's algorithm. ECDLP solved in polynomial quantum time."
                r["quantum_context"] = "256-bit ECC requires ~2500 logical qubits to break."
                r["remediation"] = ["Replace ECDH with CRYSTALS-Kyber", "Replace ECDSA with CRYSTALS-Dilithium"]
                return r
        except Exception:
            pass
        if "ECDH" in cipher.upper() or "ECDSA" in cipher.upper():
            r["severity"] = "CRITICAL"
            r["finding"] = "ECC detected in cipher suite - quantum vulnerable"
            r["remediation"] = ["Migrate to NIST post-quantum standards"]
        else:
            r["severity"] = "INFO"
            r["finding"] = "ECC not detected"
        return r
""")

write("modules/dh_assessor.py", """
class DHAssessor:
    def __init__(self, target, port, enum_results, verbose=False):
        self.enum_results = enum_results
    def run(self):
        r = {"module": "Key Exchange Assessment", "severity": "UNKNOWN",
             "finding": "", "risk_description": "", "remediation": [], "quantum_context": ""}
        cipher = self.enum_results.get("cipher_suite", "").upper()
        if "DHE" in cipher or "EDH" in cipher:
            r["severity"] = "CRITICAL"
            r["finding"] = "DHE key exchange - quantum vulnerable"
            r["risk_description"] = "Discrete logarithm problem solved by Shor's algorithm."
            r["remediation"] = ["Replace with CRYSTALS-Kyber", "Enable TLS 1.3"]
        elif "ECDH" in cipher:
            r["severity"] = "CRITICAL"
            r["finding"] = "ECDH key exchange - quantum vulnerable"
            r["remediation"] = ["Replace ECDH with CRYSTALS-Kyber (NIST FIPS 203)"]
        elif "RSA" in cipher:
            r["severity"] = "CRITICAL"
            r["finding"] = "Static RSA key exchange - no forward secrecy"
            r["risk_description"] = "Harvest-now-decrypt-later attack possible."
            r["quantum_context"] = "Adversaries recording traffic now to decrypt when quantum computers arrive."
            r["remediation"] = ["Disable static RSA key exchange immediately", "Migrate to TLS 1.3"]
        else:
            r["severity"] = "INFO"
            r["finding"] = "Key exchange: " + cipher
        return r
""")

write("modules/assessors.py", """
class SignatureAssessor:
    def __init__(self, target, port, enum_results, verbose=False):
        self.enum_results = enum_results
    def run(self):
        r = {"module": "Digital Signature Assessment", "severity": "UNKNOWN",
             "finding": "", "risk_description": "", "remediation": [], "quantum_context": ""}
        raw = self.enum_results.get("raw_cert")
        alg = "UNKNOWN"
        if raw:
            try:
                from cryptography import x509
                alg = x509.load_der_x509_certificate(raw).signature_hash_algorithm.name.upper()
            except Exception:
                pass
        if "MD5" in alg or "SHA1" in alg:
            r["severity"] = "CRITICAL"
            r["finding"] = "Weak signature: " + alg
            r["remediation"] = ["Replace immediately with SHA-256+", "Migrate to CRYSTALS-Dilithium"]
        elif "RSA" in alg:
            r["severity"] = "CRITICAL"
            r["finding"] = "RSA signature " + alg + " - quantum forgeable"
            r["risk_description"] = "Shor's algorithm recovers private key from public key."
            r["remediation"] = ["Migrate to CRYSTALS-Dilithium (NIST FIPS 204)"]
        elif "ECDSA" in alg or "EC" in alg:
            r["severity"] = "CRITICAL"
            r["finding"] = "ECDSA signature - quantum forgeable"
            r["remediation"] = ["Replace with CRYSTALS-Dilithium or FALCON"]
        else:
            r["severity"] = "MEDIUM"
            r["finding"] = "Signature: " + alg
            r["remediation"] = ["Evaluate against NIST PQC standards"]
        return r

class SymmetricAssessor:
    def __init__(self, target, port, enum_results, verbose=False):
        self.enum_results = enum_results
    def run(self):
        r = {"module": "Symmetric Encryption Assessment", "severity": "UNKNOWN",
             "finding": "", "risk_description": "", "remediation": [], "quantum_context": ""}
        cipher = self.enum_results.get("cipher_suite", "").upper()
        if "AES_256" in cipher or "AES256" in cipher:
            r["severity"] = "LOW"
            r["finding"] = "AES-256 - adequate quantum resistance"
            r["risk_description"] = "Grover's reduces to 128-bit effective security. Currently acceptable."
            r["remediation"] = ["Current config is quantum-resistant", "Use AES-256-GCM mode"]
        elif "AES_128" in cipher or "AES128" in cipher:
            r["severity"] = "HIGH"
            r["finding"] = "AES-128 - Grover's reduces to 64-bit security"
            r["risk_description"] = "Grover's algorithm halves key strength. AES-128 becomes 64-bit equivalent."
            r["remediation"] = ["Upgrade to AES-256 immediately", "Use AES-256-GCM"]
        elif "3DES" in cipher or "DES" in cipher:
            r["severity"] = "CRITICAL"
            r["finding"] = "3DES/DES detected - broken"
            r["remediation"] = ["Disable 3DES immediately", "Replace with AES-256-GCM"]
        elif "CHACHA20" in cipher:
            r["severity"] = "LOW"
            r["finding"] = "ChaCha20-256 - good quantum resistance"
            r["remediation"] = ["Current config is adequate"]
        else:
            r["severity"] = "UNKNOWN"
            r["finding"] = "Symmetric algorithm unclear: " + cipher
        return r

class HashAssessor:
    def __init__(self, target, port, enum_results, verbose=False):
        self.enum_results = enum_results
    def run(self):
        r = {"module": "Hash Function Assessment", "severity": "UNKNOWN",
             "finding": "", "risk_description": "", "remediation": [], "quantum_context": ""}
        raw = self.enum_results.get("raw_cert")
        cipher = self.enum_results.get("cipher_suite", "").upper()
        alg = "UNKNOWN"
        if raw:
            try:
                from cryptography import x509
                alg = x509.load_der_x509_certificate(raw).signature_hash_algorithm.name.upper()
            except Exception:
                pass
        if alg == "UNKNOWN":
            if "SHA384" in cipher: alg = "SHA384"
            elif "SHA256" in cipher: alg = "SHA256"
            elif "SHA" in cipher: alg = "SHA1"
        if "MD5" in alg:
            r["severity"] = "CRITICAL"
            r["finding"] = "MD5 detected - broken"
            r["remediation"] = ["Replace with SHA-256 minimum immediately"]
        elif "SHA1" in alg:
            r["severity"] = "CRITICAL"
            r["finding"] = "SHA-1 - Grover's reduces to 80-bit security"
            r["remediation"] = ["Replace SHA-1 with SHA-256 immediately"]
        elif "SHA256" in alg:
            r["severity"] = "MEDIUM"
            r["finding"] = "SHA-256 - Grover's reduces to 128-bit effective security"
            r["remediation"] = ["Consider upgrading to SHA-384"]
        elif "SHA384" in alg:
            r["severity"] = "LOW"
            r["finding"] = "SHA-384 - good quantum resistance"
            r["remediation"] = ["Current hash config is quantum-resistant"]
        elif "SHA512" in alg:
            r["severity"] = "LOW"
            r["finding"] = "SHA-512 - strong quantum resistance"
            r["remediation"] = ["Current hash config is quantum-safe"]
        else:
            r["severity"] = "UNKNOWN"
            r["finding"] = "Hash unclear: " + alg
        return r
""")

write("modules/signature_assessor.py", "from modules.assessors import SignatureAssessor\n")
write("modules/symmetric_assessor.py", "from modules.assessors import SymmetricAssessor\n")
write("modules/hash_assessor.py",      "from modules.assessors import HashAssessor\n")

write("reports/report_engine.py", """
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
        return "\\n".join(lines)

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
            rows += ("<tr><td class=\\"tn\\">" + t + "</td>"
                     "<td><span style=\\"color:" + c + ";font-weight:bold\\">" + sev + "</span></td>"
                     "<td class=\\"tf\\">" + r.get("finding","") + "</td></tr>")

        cards = ""
        for i,(k,t) in enumerate(mdefs,1):
            if k not in self.results: continue
            r = self.results[k]
            sev = r.get("severity","UNKNOWN")
            c = self._color(sev)
            risk = r.get("risk_description","")
            quantum = r.get("quantum_context","")
            rem = "".join("<li>" + s + "</li>" for s in r.get("remediation",[]))
            qb = ("<div class=\\"qnote\\">Quantum context: " + quantum + "</div>") if quantum else ""
            cards += ("<div class=\\"card\\">"
                      "<div class=\\"ch\\"><span class=\\"cn\\">" + str(i) + "</span>"
                      "<h3 class=\\"ct\\">" + t + "</h3>"
                      "<span style=\\"color:" + c + ";font-weight:bold;font-size:13px\\">" + sev + "</span></div>"
                      "<p class=\\"cf\\">" + r.get("finding","") + "</p>"
                      + ("<p class=\\"cr\\">" + risk + "</p>" if risk else "")
                      + qb
                      + ("<div class=\\"rem\\"><p class=\\"rl\\">Recommended actions</p><ol>" + rem + "</ol></div>" if rem else "")
                      + "</div>")

        return (\"\"\"<!DOCTYPE html>
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
.snum{font-size:60px;font-weight:normal;line-height:1;color:\"\"\" + rc + \"\"\"}
.srating{font-size:20px;color:\"\"\" + rc + \"\"\";margin-bottom:4px}
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
<h1 class="htarget">\"\"\" + self.target + \"\"\"</h1>
<p class="hmeta">\"\"\" + ds + \"\"\" &middot; \"\"\" + ts + \"\"\" &middot; Confidential</p>
</div>
<p class="snum">\"\"\" + str(round(score,1)) + \"\"\"</p>
<p class="srating">\"\"\" + rating + \"\"\" Risk</p>
<p class="ssub">Overall quantum vulnerability score out of 100</p>
<div class="counts">
<div class="cc"><span class="cn2" style="color:#c0392b">\"\"\" + str(sevs.count("CRITICAL")) + \"\"\"</span><span class="cl">Critical</span></div>
<div class="cc"><span class="cn2" style="color:#d35400">\"\"\" + str(sevs.count("HIGH")) + \"\"\"</span><span class="cl">High</span></div>
<div class="cc"><span class="cn2" style="color:#b7950b">\"\"\" + str(sevs.count("MEDIUM")) + \"\"\"</span><span class="cl">Medium</span></div>
<div class="cc"><span class="cn2" style="color:#1e8449">\"\"\" + str(sevs.count("LOW")) + \"\"\"</span><span class="cl">Low</span></div>
</div>
<p class="slbl">Summary</p>
<table><thead><tr><th>Assessment</th><th>Severity</th><th>Key Finding</th></tr></thead>
<tbody>\"\"\" + rows + \"\"\"</tbody></table>
<p class="slbl">Detailed Findings</p>
\"\"\" + cards + \"\"\"
<div class="footer">
<div>Q-Recon v1.0 &middot; Quantum-Resilience Security Assessment<br>Generated \"\"\" + ds + \"\"\" at \"\"\" + ts + \"\"\"</div>
<div style="text-align:right">Authorized security testing only.<br>Unauthorized use is illegal.</div>
</div>
</div></body></html>\"\"\")
""")

write("qrecon.py", """
#!/usr/bin/env python3
import argparse, sys, os
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils.banner import print_banner
from utils.authorization import AuthorizationGate
from utils.logger import QLogger
from modules.enumerator import TargetEnumerator
from modules.rsa_assessor import RSAAssessor
from modules.ecc_assessor import ECCAssessor
from modules.dh_assessor import DHAssessor
from modules.signature_assessor import SignatureAssessor
from modules.symmetric_assessor import SymmetricAssessor
from modules.hash_assessor import HashAssessor
from reports.report_engine import ReportEngine

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-t","--target",required=True)
    p.add_argument("-p","--port",type=int,default=443)
    p.add_argument("-o","--output",default="reports")
    p.add_argument("--skip-auth",action="store_true")
    p.add_argument("--verbose",action="store_true")
    return p.parse_args()

def print_summary(r):
    colors = {"CRITICAL":"\\033[91m","HIGH":"\\033[93m","MEDIUM":"\\033[94m","LOW":"\\033[92m","UNKNOWN":"\\033[97m"}
    reset = "\\033[0m"
    sev = r.get("severity","UNKNOWN")
    print("    Status  : " + colors.get(sev,reset) + sev + reset)
    print("    Finding : " + str(r.get("finding","N/A")))

def main():
    print_banner()
    args = parse_args()
    if not args.skip_auth:
        if not AuthorizationGate(args.target).verify():
            print("[!] Authorization not confirmed. Exiting.")
            sys.exit(0)
    logger = QLogger(args.target, args.output)
    print()
    print("[*] Target : " + args.target)
    print("[*] Time   : " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print()
    print("=" * 55)
    print("  PHASE 1: TARGET ENUMERATION")
    print("=" * 55)
    enum = TargetEnumerator(args.target, args.port, args.verbose)
    enum_results = enum.run()
    if not enum_results.get("reachable"):
        print("[!] Target unreachable. Exiting.")
        sys.exit(1)
    print()
    print("=" * 55)
    print("  PHASE 2: CRYPTOGRAPHIC ASSESSMENT")
    print("=" * 55)
    modules = [
        ("rsa","RSA Assessment",RSAAssessor),
        ("ecc","ECC Exposure",ECCAssessor),
        ("dh","Key Exchange",DHAssessor),
        ("signature","Digital Signatures",SignatureAssessor),
        ("symmetric","Symmetric Encryption",SymmetricAssessor),
        ("hash","Hash Functions",HashAssessor),
    ]
    results = {}
    for key,name,Cls in modules:
        print()
        print("[+] " + name)
        print("-" * 40)
        r = Cls(args.target, args.port, enum_results, args.verbose).run()
        results[key] = r
        print_summary(r)
        logger.log_module_result(key, r)
    weights = {"CRITICAL":100,"HIGH":75,"MEDIUM":50,"LOW":25,"SAFE":0,"UNKNOWN":10}
    scores = [weights.get(results[k].get("severity","UNKNOWN"),10) for k in results]
    avg = sum(scores)/len(scores) if scores else 0
    results["quantum_risk_score"] = avg
    reset = "\\033[0m"
    if avg>=75: col="\\033[91m"; rat="CRITICAL"
    elif avg>=50: col="\\033[93m"; rat="HIGH"
    elif avg>=25: col="\\033[94m"; rat="MEDIUM"
    else: col="\\033[92m"; rat="LOW"
    print()
    print("=" * 55)
    print("  QUANTUM RISK SCORE")
    print("=" * 55)
    print("  Score  : " + col + str(round(avg,1)) + "/100" + reset)
    print("  Rating : " + col + rat + reset)
    print()
    print("=" * 55)
    path = ReportEngine(args.target, results, args.output).generate()
    print("[OK] Done : " + path)
    print()

if __name__ == "__main__":
    main()
""")

print()
print("=" * 40)
print("Q-Recon installed successfully!")
print("Run: python3 /opt/qrecon/qrecon.py -t google.com")
print("=" * 40)
