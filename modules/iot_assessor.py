import socket
import ssl
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

class IoTAssessor:
    COMMON_IOT_PORTS = [
        (443,  "HTTPS"),
        (8443, "HTTPS-ALT"),
        (8080, "HTTP-ALT"),
        (8888, "HTTP-ALT2"),
        (9443, "HTTPS-ALT3"),
        (1883, "MQTT"),
        (8883, "MQTT-TLS"),
        (5683, "CoAP"),
        (23,   "TELNET"),
        (22,   "SSH"),
    ]

    def __init__(self, target, verbose=False):
        self.target = target
        self.verbose = verbose
        self.devices_found = []

    def run(self):
        result = {
            "module": "IoT Device Assessment",
            "severity": "UNKNOWN",
            "finding": "",
            "risk_description": "",
            "technical_details": {},
            "remediation": [],
            "quantum_context": "",
            "devices": []
        }

        print("    [*] Scanning IoT ports on : " + self.target)
        print("    [*] Checking " + str(len(self.COMMON_IOT_PORTS)) + " common IoT ports")

        open_ports = self._scan_ports()

        if not open_ports:
            result["severity"] = "INFO"
            result["finding"] = "No common IoT ports found on " + self.target
            return result

        print("    [+] Open ports found : " + str(len(open_ports)))

        tls_findings = []
        for port, service in open_ports:
            print("    [*] Checking " + service + " on port " + str(port))
            finding = self._check_tls(port, service)
            if finding:
                tls_findings.append(finding)
                print("    [+] " + service + ":" + str(port) + " -> " + finding["key_type"] + " " + finding.get("detail",""))

        result["technical_details"]["open_ports"] = [{"port": p, "service": s} for p,s in open_ports]
        result["technical_details"]["tls_findings"] = tls_findings
        result["devices"] = tls_findings

        return self._assess(result, open_ports, tls_findings)

    def _scan_ports(self):
        open_ports = []
        for port, service in self.COMMON_IOT_PORTS:
            try:
                sock = socket.create_connection((self.target, port), timeout=2)
                sock.close()
                open_ports.append((port, service))
                print("    [+] Port " + str(port) + " (" + service + ") : OPEN")
            except Exception:
                if self.verbose:
                    print("    [-] Port " + str(port) + " (" + service + ") : CLOSED")
        return open_ports

    def _check_tls(self, port, service):
        if service not in ("HTTPS", "HTTPS-ALT", "HTTPS-ALT2", "HTTPS-ALT3", "MQTT-TLS"):
            return {"port": port, "service": service, "key_type": "NO-TLS",
                    "detail": "Unencrypted protocol — plaintext IoT traffic"}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.target, port), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname=self.target) as ss:
                    raw = ss.getpeercert(binary_form=True)
                    tls_ver = ss.version()
                    if raw:
                        from cryptography import x509
                        from cryptography.hazmat.primitives.asymmetric import rsa, ec
                        pub = x509.load_der_x509_certificate(raw).public_key()
                        if isinstance(pub, rsa.RSAPublicKey):
                            return {"port": port, "service": service,
                                    "key_type": "RSA", "key_size": pub.key_size,
                                    "tls_version": tls_ver,
                                    "detail": "RSA-" + str(pub.key_size)}
                        elif isinstance(pub, ec.EllipticCurvePublicKey):
                            return {"port": port, "service": service,
                                    "key_type": "ECC", "key_size": pub.key_size,
                                    "curve": pub.curve.name,
                                    "tls_version": tls_ver,
                                    "detail": "ECC-" + pub.curve.name}
        except Exception as e:
            if self.verbose:
                print("    [!] TLS error on " + str(port) + ": " + str(e))
        return None

    def _assess(self, result, open_ports, tls_findings):
        unencrypted = [f for f in tls_findings if f.get("key_type") == "NO-TLS"]
        rsa_weak    = [f for f in tls_findings if f.get("key_type") == "RSA" and f.get("key_size",0) <= 2048]
        ecc_found   = [f for f in tls_findings if f.get("key_type") == "ECC"]

        if unencrypted:
            result["severity"] = "CRITICAL"
            result["finding"] = (str(len(unencrypted)) + " unencrypted IoT protocol(s) detected — " +
                                str(len(open_ports)) + " ports open")
            result["risk_description"] = ("Unencrypted IoT protocols transmit data in plaintext. " +
                "Device credentials, sensor data, and commands are fully exposed. " +
                "Quantum computers make any weak encryption trivially breakable.")
            result["quantum_context"] = ("IoT devices often run for 10-20 years. Quantum computers " +
                "will arrive within that lifecycle — making today's weak crypto a future catastrophe.")
            result["remediation"] = [
                "Immediately disable Telnet — replace with SSH",
                "Disable unencrypted MQTT (port 1883) — use MQTT-TLS (port 8883)",
                "Upgrade all IoT firmware to support TLS 1.3",
                "Replace all RSA-2048 certificates with RSA-4096 minimum",
                "Plan migration to CRYSTALS-Kyber for all IoT key exchange",
                "Segment IoT devices on isolated network VLAN"
            ]
        elif rsa_weak:
            result["severity"] = "CRITICAL"
            result["finding"] = (str(len(rsa_weak)) + " IoT device(s) with RSA-2048 — quantum vulnerable")
            result["risk_description"] = "IoT devices with RSA-2048 certificates are quantum vulnerable."
            result["remediation"] = [
                "Replace IoT certificates with RSA-4096 minimum",
                "Plan firmware updates with post-quantum cryptography",
                "Isolate vulnerable IoT devices on separate network segment"
            ]
        elif ecc_found:
            result["severity"] = "CRITICAL"
            result["finding"] = str(len(ecc_found)) + " IoT device(s) with ECC — quantum vulnerable"
            result["remediation"] = ["Migrate IoT devices to post-quantum cryptography"]
        else:
            result["severity"] = "MEDIUM"
            result["finding"] = str(len(open_ports)) + " IoT port(s) open — manual TLS review needed"
            result["remediation"] = ["Manually audit TLS on all open IoT ports"]

        return result
