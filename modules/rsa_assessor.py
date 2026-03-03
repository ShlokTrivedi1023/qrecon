
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
