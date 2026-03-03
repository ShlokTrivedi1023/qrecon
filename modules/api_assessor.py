import socket
import ssl
import urllib.request
import urllib.error
import json

class APIAssessor:
    def __init__(self, target, port=443, endpoints=None, verbose=False):
        self.target = target
        self.port = port
        self.verbose = verbose
        self.endpoints = endpoints or [
            "/api",
            "/api/v1",
            "/api/v2",
            "/rest",
            "/graphql",
            "/swagger.json",
            "/openapi.json",
            "/.well-known/openid-configuration",
        ]

    def run(self):
        result = {
            "module": "API Endpoint Scanner",
            "severity": "UNKNOWN",
            "finding": "",
            "risk_description": "",
            "technical_details": {},
            "remediation": [],
            "quantum_context": "",
            "endpoints_found": [],
            "endpoints_checked": 0
        }

        print("    [*] Scanning " + str(len(self.endpoints)) + " common API endpoints")

        found = []
        tls_info = self._get_tls_info()
        result["technical_details"]["tls"] = tls_info

        for endpoint in self.endpoints:
            url = "https://" + self.target
            if self.port != 443:
                url += ":" + str(self.port)
            url += endpoint

            status = self._probe_endpoint(url)
            result["endpoints_checked"] += 1

            if status and status < 500:
                found.append({"endpoint": endpoint, "status": status})
                print("    [+] Found    : " + endpoint + " (" + str(status) + ")")
            else:
                if self.verbose:
                    print("    [-] Not found: " + endpoint)

        result["endpoints_found"] = found

        if not found:
            result["severity"] = "INFO"
            result["finding"] = "No common API endpoints detected on " + self.target
            return result

        return self._assess(result, found, tls_info)

    def _probe_endpoint(self, url):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "QRecon/1.0"})
            with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return None

    def _get_tls_info(self):
        info = {"key_type": "UNKNOWN", "key_size": 0, "tls_version": "UNKNOWN"}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.target, self.port), timeout=10) as s:
                with ctx.wrap_socket(s, server_hostname=self.target) as ss:
                    info["tls_version"] = ss.version()
                    raw = ss.getpeercert(binary_form=True)
                    if raw:
                        from cryptography import x509
                        from cryptography.hazmat.primitives.asymmetric import rsa, ec
                        pub = x509.load_der_x509_certificate(raw).public_key()
                        if isinstance(pub, rsa.RSAPublicKey):
                            info["key_type"] = "RSA"
                            info["key_size"] = pub.key_size
                        elif isinstance(pub, ec.EllipticCurvePublicKey):
                            info["key_type"] = "ECC"
                            info["key_size"] = pub.key_size
                            info["curve"] = pub.curve.name
        except Exception as e:
            if self.verbose:
                print("    [!] TLS info error: " + str(e))
        return info

    def _assess(self, result, found, tls_info):
        key_type = tls_info.get("key_type", "UNKNOWN")
        key_size = tls_info.get("key_size", 0)
        endpoints_count = len(found)

        result["finding"] = (str(endpoints_count) + " API endpoint(s) found — " +
                            key_type + "-" + str(key_size) + " certificate detected")

        if key_type == "RSA" and key_size <= 2048:
            result["severity"] = "CRITICAL"
            result["risk_description"] = ("API endpoints are exposed with RSA-" + str(key_size) +
                " encryption. All API traffic — including authentication tokens, session keys, " +
                "and sensitive data — is vulnerable to harvest-now-decrypt-later attacks.")
            result["quantum_context"] = ("API tokens and session keys intercepted today can be " +
                "decrypted once quantum computers arrive. APIs are high-value targets.")
            result["remediation"] = [
                "Replace API TLS certificate with RSA-4096 minimum",
                "Migrate to CRYSTALS-Kyber for key exchange (NIST FIPS 203)",
                "Implement API authentication using quantum-safe algorithms",
                "Enable Perfect Forward Secrecy on all API endpoints",
                "Audit all " + str(endpoints_count) + " exposed endpoints for sensitive data"
            ]
        elif key_type == "ECC":
            result["severity"] = "CRITICAL"
            result["risk_description"] = ("ECC on API endpoints is broken by Shor's algorithm. " +
                "All API traffic is vulnerable.")
            result["remediation"] = [
                "Replace ECDH with CRYSTALS-Kyber on API server",
                "Replace ECDSA signatures with CRYSTALS-Dilithium"
            ]
        elif key_type == "RSA" and key_size > 2048:
            result["severity"] = "MEDIUM"
            result["risk_description"] = "RSA-" + str(key_size) + " provides interim protection but requires PQC migration."
            result["remediation"] = ["Plan migration to CRYSTALS-Kyber within 5 years"]
        else:
            result["severity"] = "MEDIUM"
            result["finding"] = str(endpoints_count) + " API endpoints found — assess TLS manually"
            result["remediation"] = ["Manually review TLS configuration on API server"]

        return result
