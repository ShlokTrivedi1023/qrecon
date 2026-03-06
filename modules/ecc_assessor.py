
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
        if cipher and ("ECDH" in cipher.upper() or "ECDSA" in cipher.upper()):
            r["severity"] = "CRITICAL"
            r["finding"] = "ECC detected in cipher suite - quantum vulnerable"
            r["remediation"] = ["Migrate to NIST post-quantum standards"]
        else:
            r["severity"] = "INFO"
            r["finding"] = "ECC not detected"
        return r
