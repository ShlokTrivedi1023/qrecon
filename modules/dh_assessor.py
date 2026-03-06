
class DHAssessor:
    def __init__(self, target, port, enum_results, verbose=False):
        self.enum_results = enum_results
    def run(self):
        r = {"module": "Key Exchange Assessment", "severity": "UNKNOWN",
             "finding": "", "risk_description": "", "remediation": [], "quantum_context": ""}
        cipher = (self.enum_results.get("cipher_suite") or "").upper()
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
