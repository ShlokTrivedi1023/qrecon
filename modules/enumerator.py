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
        # Try multiple SSL contexts from most modern to most compatible
        attempts = []

        ctx1 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx1.check_hostname = False
        ctx1.verify_mode = ssl.CERT_NONE
        ctx1.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx1.maximum_version = ssl.TLSVersion.TLSv1_3
        attempts.append(("TLS1.2-1.3", ctx1))

        ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        ctx2.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx2.maximum_version = ssl.TLSVersion.TLSv1_2
        attempts.append(("TLS1.2-only", ctx2))

        ctx3 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx3.check_hostname = False
        ctx3.verify_mode = ssl.CERT_NONE
        ctx3.set_ciphers("ALL:@SECLEVEL=0")
        attempts.append(("TLS-compat", ctx3))

        for label, ctx in attempts:
            try:
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
                            print("    [+] Subject  : " + subj.get("commonName","N/A"))
                            print("    [+] Expiry   : " + cert.get("notAfter","N/A"))
                        return info
            except Exception as e:
                if self.verbose:
                    print("    [!] TLS (" + label + ") : " + str(e))
                continue

        print("    [!] TLS      : Could not complete handshake with any method")
        return info
