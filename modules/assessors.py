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
        elif alg == "UNKNOWN":
            r["severity"] = "UNKNOWN"
            r["finding"] = "Could not retrieve certificate for signature analysis"
            r["remediation"] = ["Manually verify certificate signature algorithm"]
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
        cipher = (self.enum_results.get("cipher_suite") or "").upper()
        if "AES_256" in cipher or "AES256" in cipher:
            r["severity"] = "LOW"
            r["finding"] = "AES-256 - adequate quantum resistance"
            r["risk_description"] = "Grover's reduces to 128-bit effective security. Currently acceptable."
            r["remediation"] = ["Current config is quantum-resistant", "Use AES-256-GCM mode"]
        elif "AES_128" in cipher or "AES128" in cipher:
            r["severity"] = "HIGH"
            r["finding"] = "AES-128 - Grover's reduces to 64-bit security"
            r["remediation"] = ["Upgrade to AES-256 immediately"]
        elif "3DES" in cipher or "DES" in cipher:
            r["severity"] = "CRITICAL"
            r["finding"] = "3DES/DES detected - broken"
            r["remediation"] = ["Disable 3DES immediately", "Replace with AES-256-GCM"]
        elif "CHACHA20" in cipher:
            r["severity"] = "LOW"
            r["finding"] = "ChaCha20-256 - good quantum resistance"
            r["remediation"] = ["Current config is adequate"]
        elif not cipher:
            r["severity"] = "UNKNOWN"
            r["finding"] = "Could not retrieve cipher suite"
            r["remediation"] = ["Manually verify symmetric encryption configuration"]
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
        cipher = (self.enum_results.get("cipher_suite") or "").upper()
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
            r["finding"] = "Could not retrieve hash algorithm"
            r["remediation"] = ["Manually verify hash function configuration"]
        return r
