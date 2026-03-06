# Q-Recon — Quantum-Resilience Offensive Security Assessment Framework

> The first open-source offensive security framework designed to assess cryptographic resilience against quantum computing attacks.

![Python](https://img.shields.io/badge/python-3.8+-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Platform](https://img.shields.io/badge/platform-Kali%20Linux-red) ![Black Hat Arsenal](https://img.shields.io/badge/Black%20Hat-Arsenal%202026-black)

---

## Table of Contents
- [Overview](#overview)
- [The Quantum Threat](#the-quantum-threat)
- [Why Q-Recon](#why-q-recon)
- [Architecture](#architecture)
- [Modules](#modules)
- [Installation](#installation)
- [Usage](#usage)
- [Sample Output](#sample-output)
- [Reporting](#reporting)
- [Legal Disclaimer](#legal-disclaimer)
- [Authors and Contributors](#authors-and-contributors)
- [License](#license)

---

## Overview

Q-Recon is a purpose-built, modular offensive security assessment framework that identifies cryptographic weaknesses in systems, services, and infrastructure that are vulnerable to quantum computing attacks. Unlike conventional security scanners that focus on classical vulnerabilities, Q-Recon specifically targets post-quantum readiness — evaluating whether deployed cryptographic primitives can withstand attacks from quantum adversaries.

Q-Recon was built for:

- Penetration testers assessing enterprise quantum readiness
- Security researchers studying real-world post-quantum migration gaps
- Red teams identifying cryptographic attack surfaces
- Organizations benchmarking their quantum resilience posture

Q-Recon is written in Python 3, runs natively on Kali Linux, and requires no external cloud dependencies — all assessments are performed locally.

---

## The Quantum Threat

The advent of large-scale quantum computers poses an existential threat to the cryptographic infrastructure underpinning modern security. Shor's algorithm, running on a sufficiently powerful quantum computer, can factor large integers and solve discrete logarithm problems in polynomial time — breaking RSA, ECC, Diffie-Hellman, and other widely deployed asymmetric cryptosystems entirely.

The timeline is accelerating:

- **2024:** IBM, Google, and others demonstrated quantum processors exceeding 1,000 qubits
- **2024:** NIST finalized the first Post-Quantum Cryptography (PQC) standards — FIPS 203, FIPS 204, and FIPS 205
- **2030 (projected):** Cryptographically relevant quantum computers (CRQCs) capable of breaking 2048-bit RSA

The security community faces a critical window: systems must be identified, assessed, and migrated to quantum-safe algorithms before this threshold is crossed. Q-Recon exists to accelerate this identification process.

**Harvest Now, Decrypt Later (HNDL)** attacks are already underway — adversaries are recording encrypted traffic today with the intent to decrypt it once quantum hardware matures. This makes assessment urgent even now.

---

## Why Q-Recon

Existing security tools such as testssl.sh, SSLyze, and Nmap assess classical vulnerabilities but have no awareness of quantum risk. They cannot answer:

- Whether RSA key sizes are vulnerable to Shor's algorithm on a near-future CRQC
- Whether ECC curves are broken by quantum attacks regardless of key size
- Whether Diffie-Hellman parameters provide any quantum resistance
- Whether hash functions provide adequate post-quantum security margins
- Whether symmetric key lengths meet post-quantum requirements

A system can pass every classical security check and simultaneously carry a **CRITICAL** quantum risk rating. Q-Recon is the first unified framework that bridges this gap by combining:

- Active service enumeration
- Cryptographic primitive extraction
- Quantum-risk scoring per algorithm
- NIST PQC migration recommendations
- Automated HTML and plain text reporting

---

## Architecture
```
qrecon/
├── qrecon.py                  # Main entry point and CLI
├── dashboard.py               # Interactive dashboard
├── install.py                 # Dependency installer
├── config/
│   └── __init__.py            # Global configuration
├── modules/
│   ├── __init__.py
│   ├── enumerator.py          # Service and port enumeration
│   ├── assessors.py           # Base assessor class
│   ├── rsa_assessor.py        # RSA quantum-risk analysis
│   ├── ecc_assessor.py        # ECC curve quantum-risk analysis
│   ├── dh_assessor.py         # Diffie-Hellman assessment
│   ├── symmetric_assessor.py  # Symmetric key strength analysis
│   ├── hash_assessor.py       # Hash function quantum-risk analysis
│   ├── signature_assessor.py  # Digital signature assessment
│   ├── api_assessor.py        # REST and API endpoint assessment
│   ├── iot_assessor.py        # IoT device cryptographic assessment
│   └── starttls_assessor.py   # STARTTLS and mail server assessment
├── reports/
│   ├── __init__.py
│   └── report_engine.py       # HTML and plain text report generation
└── utils/
    ├── __init__.py
    ├── authorization.py       # Scope and authorization management
    ├── banner.py              # Tool banner and branding
    └── logger.py              # Logging engine
```

---

## Modules

### Enumerator (enumerator.py)
Performs active service discovery and port enumeration on the target. Identifies running services, extracts TLS/SSL handshake data, and fingerprints cryptographic configurations exposed by each service. Feeds structured data into all downstream assessment modules.

### RSA Assessor (rsa_assessor.py)
Extracts RSA public key parameters from TLS certificates and evaluates key sizes against quantum-safety thresholds:
- Less than 2048-bit: Classically weak, immediately vulnerable
- 2048-bit: Classical standard, quantum-broken by Shor's algorithm
- 4096-bit: Extended runway, still fully quantum-vulnerable

Flags all RSA usage and recommends migration to CRYSTALS-Kyber (FIPS 203) and CRYSTALS-Dilithium (FIPS 204).

### ECC Assessor (ecc_assessor.py)
Identifies elliptic curve parameters in use across services. Evaluates named curves (P-256, P-384, secp256k1, Curve25519, and others) for quantum vulnerability. All current ECC curves are broken by Shor's algorithm on a CRQC regardless of key size. Recommends migration to NIST PQC standards.

### Diffie-Hellman Assessor (dh_assessor.py)
Detects DH and ECDH key exchange in TLS handshakes. Assesses parameter sizes and known weak groups. Flags ephemeral vs static DH usage. All classical DH variants are quantum-vulnerable via Shor's algorithm.

### Symmetric Assessor (symmetric_assessor.py)
Evaluates symmetric cipher suites in use. Applies Grover's algorithm analysis — quantum computers halve the effective security of symmetric keys:
- AES-128: Reduces to approximately 64-bit effective security post-quantum (insufficient)
- AES-256: Reduces to approximately 128-bit effective security post-quantum (acceptable)
- Flags 3DES, RC4, and other deprecated ciphers

### Hash Assessor (hash_assessor.py)
Identifies hash functions in use across services and certificates. Evaluates quantum resistance:
- MD5, SHA-1: Broken classically and critically weak post-quantum
- SHA-256: Grover-reduced to approximately 128-bit (marginal post-quantum)
- SHA-384, SHA-512: Acceptable post-quantum security margins

Recommends SHA-3 family for quantum-resilient deployments.

### Signature Assessor (signature_assessor.py)
Inspects digital signature schemes used in certificates, code signing, and authentication. All RSA and ECDSA signatures are quantum-vulnerable. Recommends CRYSTALS-Dilithium (FIPS 204) or FALCON as quantum-safe alternatives.

### API Assessor (api_assessor.py)
Assesses REST API endpoints for cryptographic weaknesses. Inspects TLS configuration, token algorithms (JWT RS256 vs HS256), API key lengths, and transport-layer security configurations.

### IoT Assessor (iot_assessor.py)
Specialized module for IoT device cryptographic assessment. Scans common IoT ports (MQTT, CoAP, HTTPS-ALT, Telnet, SSH) and evaluates cryptographic configurations. IoT devices frequently implement constrained cryptographic protocols with reduced key sizes, pre-shared keys, and legacy cipher suites — creating concentrated quantum risk surfaces.

### STARTTLS Assessor (starttls_assessor.py)
Targets mail servers and services using STARTTLS (SMTP, IMAP, POP3). Extracts cipher suites and certificates from opportunistic TLS deployments. Mail infrastructure is frequently overlooked in security assessments and commonly carries legacy cryptographic configurations with significant quantum exposure.

---

## Installation

### Requirements
- Kali Linux (recommended) or any Debian-based Linux
- Python 3.8 or higher
- Root or sudo privileges for raw socket operations

### Quick Install
```bash
git clone https://github.com/ShlokTrivedi1023/qrecon.git
cd qrecon
sudo python3 install.py
```

### Manual Dependency Install
```bash
sudo pip3 install -r requirements.txt
```

---

## Usage

### Basic Scan
```bash
sudo python3 qrecon.py -t <target>
```

### Scan with Verbose Output
```bash
sudo python3 qrecon.py -t <target> --verbose
```

### Scan on Specific Port
```bash
sudo python3 qrecon.py -t <target> -p 8443 --verbose
```

### Scan with Report Output
```bash
sudo python3 qrecon.py -t <target> -o report.txt --verbose
```

### Skip Authorization Prompt
```bash
sudo python3 qrecon.py -t <target> --skip-auth --verbose
```

### Interactive Dashboard
```bash
sudo python3 dashboard.py
```

### Options

| Flag | Description |
|------|-------------|
| `-t` / `--target` | Target IP or hostname |
| `-p` / `--port` | Target specific port |
| `-o` / `--output` | Output file for report |
| `--skip-auth` | Skip authorization confirmation prompt |
| `--verbose` | Verbose output |

---

## Sample Output
```
=======================================================
  Q-RECON: Quantum-Resilience Assessment Framework
  Version 1.0 | Authorized Penetration Testing ONLY
=======================================================

[*] Target : authorized-target.com
[*] Time   : 2026-03-06 15:29:04

=======================================================
  PHASE 1: TARGET ENUMERATION
=======================================================
    [+] IP       : 162.241.85.135
    [+] Port     : OPEN
    [+] TLS      : TLSv1.2
    [+] Cipher   : ECDHE-RSA-AES128-GCM-SHA256

=======================================================
  PHASE 2: CRYPTOGRAPHIC ASSESSMENT
=======================================================

[+] RSA Assessment
----------------------------------------
    Status  : CRITICAL
    Finding : RSA-2048 detected - quantum vulnerable within 5-10 years

[+] ECC Exposure
----------------------------------------
    Status  : CRITICAL
    Finding : ECC detected in cipher suite - quantum vulnerable

[+] Key Exchange
----------------------------------------
    Status  : CRITICAL
    Finding : DHE key exchange - quantum vulnerable

[+] Digital Signatures
----------------------------------------
    Status  : MEDIUM
    Finding : Signature: SHA256 - Grover reduces to 128-bit effective security

[+] Symmetric Encryption
----------------------------------------
    Status  : HIGH
    Finding : AES-128 - Grover reduces to 64-bit effective security

[+] Hash Functions
----------------------------------------
    Status  : MEDIUM
    Finding : SHA-256 - Grover reduces to 128-bit effective security

[+] API Assessment
----------------------------------------
    [*] Scanning 8 common API endpoints
    Status  : HIGH
    Finding : Quantum-vulnerable TLS configuration detected on API endpoints

[+] IoT Assessment
----------------------------------------
    [*] Scanning IoT ports on : authorized-target.com
    [*] Checking 10 common IoT ports
    Status  : CRITICAL
    Finding : 1 unencrypted IoT protocol(s) detected — 2 ports open

[+] STARTTLS Assessment
----------------------------------------
    [*] Protocol : SMTP
    [*] Port     : 25
    Status  : CRITICAL
    Finding : RSA-2048 detected via STARTTLS — quantum vulnerable

=======================================================
  QUANTUM RISK SCORE
=======================================================
  Score  : 79.2/100
  Rating : CRITICAL

=======================================================
[OK] Report : reports/qrecon_authorized_target_20260306_152904.html
[OK] Done   : reports/qrecon_authorized_target_20260306_152904.txt
```

---

## Reporting

Q-Recon automatically generates reports in both HTML and plain text formats after every scan. Reports are saved to the `reports/` directory and include:

- Executive summary with overall quantum risk score
- Per-service cryptographic findings
- Algorithm-level vulnerability breakdown
- NIST PQC migration recommendations mapped to each finding
- Remediation priority ordering

To open the HTML report in a browser:
```bash
xdg-open reports/<report_filename>.html
```

To view the plain text report in the terminal:
```bash
cat reports/<report_filename>.txt
```

To list all generated reports:
```bash
ls -la reports/
```

---

## Legal Disclaimer

Q-Recon is designed for authorized security assessments only. Use of this tool against systems without explicit written permission from the system owner is illegal and unethical. The authors accept no liability for misuse of this tool.

Q-Recon includes a built-in authorization verification prompt (`utils/authorization.py`) that requires the user to confirm:

- Written authorization from the target owner
- That the target falls within agreed testing scope
- Full legal responsibility for the assessment

This prompt must be answered affirmatively before any scan begins. It can be bypassed only with the `--skip-auth` flag in controlled lab environments.

---

## Authors and Contributors

**Shlok Trivedi** — Author
- GitHub: [@ShlokTrivedi1023](https://github.com/ShlokTrivedi1023)
- Email: shloktrivedi1023@gmail.com

**Shreeya Shah** — Contributor
- Email: shreeyashah001@gmail.com

Submitted to: **Black Hat USA — Arsenal 2026**

---

## License

MIT License — see [LICENSE](LICENSE) file for details.

---

> **Q-Recon — Because the quantum threat is not coming. It is already here.**
