
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
