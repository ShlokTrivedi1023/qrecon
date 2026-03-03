import socket
import ssl

class STARTTLSAssessor:
    PROTOCOLS = {
        "smtp": 25,
        "submission": 587,
        "imap": 143,
        "ldap": 389,
    }

    def __init__(self, target, port=None, protocol="smtp", verbose=False):
        self.target = target
        self.protocol = protocol.lower()
        self.port = port or self.PROTOCOLS.get(self.protocol, 25)
        self.verbose = verbose

    def run(self):
        result = {
            "module": "STARTTLS Assessment (" + self.protocol.upper() + ")",
            "severity": "UNKNOWN",
            "finding": "",
            "risk_description": "",
            "technical_details": {},
            "remediation": [],
            "quantum_context": ""
        }
        print("    [*] Protocol : " + self.protocol.upper())
        print("    [*] Port     : " + str(self.port))

        raw_cert = self._get_starttls_cert()
        if not raw_cert:
            result["severity"] = "UNKNOWN"
            result["finding"] = "Could not retrieve certificate via STARTTLS"
            return result

        result["technical_details"]["raw_cert"] = raw_cert
        return self._assess_cert(result, raw_cert)

    def _get_starttls_cert(self):
        try:
            sock = socket.create_connection((self.target, self.port), timeout=10)
            banner = sock.recv(1024).decode(errors="ignore")
            print("    [+] Banner   : " + banner.strip()[:60])

            if self.protocol in ("smtp", "submission"):
                sock.sendall(b"EHLO qrecon\r\n")
                sock.recv(1024)
                sock.sendall(b"STARTTLS\r\n")
                resp = sock.recv(1024).decode(errors="ignore")
                if "220" not in resp:
                    print("    [!] STARTTLS not supported")
                    return None

            elif self.protocol == "imap":
                sock.sendall(b"a001 STARTTLS\r\n")
                resp = sock.recv(1024).decode(errors="ignore")
                if "OK" not in resp:
                    print("    [!] STARTTLS not supported")
                    return None

            elif self.protocol == "ldap":
                print("    [!] LDAP STARTTLS requires extended request — skipping for now")
                return None

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls_sock = ctx.wrap_socket(sock, server_hostname=self.target)
            raw_cert = tls_sock.getpeercert(binary_form=True)
            tls_version = tls_sock.version()
            cipher = tls_sock.cipher()
            print("    [+] TLS      : " + str(tls_version))
            if cipher:
                print("    [+] Cipher   : " + cipher[0])
            tls_sock.close()
            return raw_cert

        except Exception as e:
            print("    [!] Error    : " + str(e))
            return None

    def _assess_cert(self, result, raw_cert):
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa, ec
            cert = x509.load_der_x509_certificate(raw_cert)
            pub = cert.public_key()

            if isinstance(pub, rsa.RSAPublicKey):
                size = pub.key_size
                print("    [+] Key Type : RSA-" + str(size))
                if size <= 2048:
                    result["severity"] = "CRITICAL"
                    result["finding"] = "RSA-" + str(size) + " on " + self.protocol.upper() + " — quantum vulnerable"
                    result["risk_description"] = "Email servers using RSA-2048 are vulnerable to harvest-now-decrypt-later attacks. Adversaries record encrypted emails today to decrypt later with quantum computers."
                    result["quantum_context"] = "Emails intercepted today remain sensitive for years — exactly the harvest-now-decrypt-later threat window."
                    result["remediation"] = [
                        "Replace certificate with RSA-4096 minimum immediately",
                        "Plan migration to CRYSTALS-Dilithium (NIST FIPS 204)",
                        "Enable Perfect Forward Secrecy on mail server",
                        "Enforce TLS 1.3 minimum for all mail connections"
                    ]
                else:
                    result["severity"] = "MEDIUM"
                    result["finding"] = "RSA-" + str(size) + " on " + self.protocol.upper() + " — plan PQC migration"
                    result["remediation"] = ["Migrate to CRYSTALS-Dilithium within 5 years"]

            elif isinstance(pub, ec.EllipticCurvePublicKey):
                curve = pub.curve.name
                print("    [+] Key Type : ECC " + curve)
                result["severity"] = "CRITICAL"
                result["finding"] = "ECC " + curve + " on " + self.protocol.upper() + " — quantum vulnerable"
                result["risk_description"] = "All ECC is broken by Shor's algorithm. Email traffic is exposed."
                result["remediation"] = [
                    "Replace with CRYSTALS-Kyber for key exchange",
                    "Replace with CRYSTALS-Dilithium for signatures"
                ]
            else:
                result["severity"] = "UNKNOWN"
                result["finding"] = "Unknown key type on " + self.protocol.upper()

        except Exception as e:
            result["severity"] = "UNKNOWN"
            result["finding"] = "Could not parse certificate: " + str(e)

        return result
