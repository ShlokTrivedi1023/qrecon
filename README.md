# Q-Recon — Quantum-Resilience Offensive Security Assessment Framework

> **The first open-source offensive security framework designed to assess cryptographic resilience against quantum computing attacks.**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-red)
![Black Hat Arsenal](https://img.shields.io/badge/Black%20Hat-Arsenal%202026-black)

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
- **Penetration testers** assessing enterprise quantum readiness
- **Security researchers** studying real-world post-quantum migration gaps
- **Red teams** identifying cryptographic attack surfaces
- **Organizations** benchmarking their quantum resilience posture

Q-Recon is written in Python, runs natively on Kali Linux, and requires no external cloud dependencies — all assessments are performed locally.

---

## The Quantum Threat

The advent of large-scale quantum computers poses an existential threat to the cryptographic infrastructure underpinning modern security. Shor's algorithm, running on a sufficiently powerful quantum computer, can factor large integers and solve discrete logarithm problems in polynomial time — breaking RSA, ECC, Diffie-Hellman, and other widely deployed asymmetric cryptosystems entirely.

The timeline is accelerating:
- **2024:** IBM, Google, and others demonstrated quantum processors exceeding 1,000 qubits
- **2024:** NIST finalized the first set of Post-Quantum Cryptography (PQC) standards (FIPS 203, 204, 205)
- **2030 (projected):** Cryptographically relevant quantum computers (CRQCs) capable of breaking 2048-bit RSA

The security community faces a critical window: systems must be identified, assessed, and migrated to quantum-safe algorithms **before** this threshold is crossed. Q-Recon exists to accelerate this identification process.

**Harvest Now, Decrypt Later (HNDL)** attacks are already underway — adversaries are recording encrypted traffic today with the intent to decrypt it once quantum hardware matures. This makes assessment urgent even now.

---

## Why Q-Recon

Existing security tools such as testssl.sh, SSLyze, and Nmap do not assess quantum resilience. They flag classical weaknesses but have no awareness of:

- Whether RSA key sizes are quantum-safe
- Whether ECC curves are vulnerable to quantum attacks
- Whether Diffie-Hellman parameters are at risk from quantum algorithms
- Whether hash functions provide adequate post-quantum security margins
- Whether symmetric key lengths meet post-quantum requirements

Q-Recon fills this gap. It is the first unified framework that combines:

1. Active service enumeration
2. Cryptographic primitive extraction
3. Quantum-risk scoring per algorithm
4. PQC migration recommendations
5. Automated HTML and text reporting

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
│   └── report_engine.py       # HTML and text report generation
└── utils/
    ├── __init__.py
    ├── authorization.py       # Scope and authorization management
    ├── banner.py              # Tool banner and branding
    └── logger.py              # Logging engine
```

---

## Modules

### Enumerator (`enumerator.py`)
Performs active service discovery and port enumeration on the target. Identifies running services, extracts TLS/SSL handshake data, and fingerprints cryptographic configurations exposed by each service. Feeds structured data into all assessment modules.

### RSA Assessor (`rsa_assessor.py`)
Extracts RSA public keys from TLS certificates and other sources. Evaluates key sizes against quantum-safety thresholds:
- Less than 2048-bit: Classically weak, immediately vulnerable
- 2048-bit: Classical standard, quantum-broken by Shor's algorithm
- 4096-bit: Extended runway, still quantum-vulnerable
- Flags all RSA usage and recommends migration to CRYSTALS-Kyber / CRYSTALS-Dilithium

### ECC Assessor (`ecc_assessor.py`)
Identifies elliptic curve parameters in use across services. Evaluates named curves (P-256, P-384, secp256k1, Curve25519, etc.) for quantum vulnerability. All current ECC curves are broken by Shor's algorithm on a CRQC. Recommends migration to NIST PQC standards.

### Diffie-Hellman Assessor (`dh_assessor.py`)
Detects DH and ECDH key exchange in TLS handshakes. Assesses parameter sizes and known weak groups. Flags ephemeral vs static DH usage. All classical DH is quantum-vulnerable via Shor's algorithm.

### Symmetric Assessor (`symmetric_assessor.py`)
Evaluates symmetric cipher suites in use. Applies Grover's algorithm analysis — quantum computers halve the effective security of symmetric keys:
- AES-128: Reduces to approximately 64-bit effective security post-quantum (insufficient)
- AES-256: Reduces to approximately 128-bit effective security post-quantum (acceptable)
- Flags 3DES, RC4, and other weak symmetric ciphers

### Hash Assessor (`hash_assessor.py`)
Identifies hash functions in use across services and certificates. Evaluates quantum resistance:
- MD5, SHA-1: Broken classically, critically weak post-quantum
- SHA-256: Grover-reduced to approximately 128-bit (marginal post-quantum)
- SHA-384/512: Acceptable post-quantum security margins
- Recommends SHA-3 family for quantum-resilient deployments

### Signature Assessor (`signature_assessor.py`)
Inspects digital signature schemes used in certificates, code signing, and authentication. All RSA and ECDSA signatures are quantum-vulnerable. Assesses algorithm selection and recommends CRYSTALS-Dilithium or FALCON as quantum-safe alternatives.

### API Assessor (`api_assessor.py`)
Assesses REST API endpoints for cryptographic weaknesses. Inspects TLS configuration, token algorithms (JWT RS256 vs HS256), API key lengths, and transport-layer security. Identifies APIs transmitting data under quantum-vulnerable encryption.

### IoT Assessor (`iot_assessor.py`)
Specialized module for IoT device assessment. Many IoT devices run constrained cryptographic implementations — lightweight RSA, short ECC keys, or pre-shared keys. This module identifies and scores the quantum risk of IoT cryptographic configurations.

### STARTTLS Assessor (`starttls_assessor.py`)
Targets mail servers and services using STARTTLS (SMTP, IMAP, POP3). Extracts cipher suites and certificates from opportunistic TLS deployments. Mail infrastructure is frequently under-assessed and often carries legacy cryptography.

---

## Installation

### Requirements
- Kali Linux (recommended) or any Debian-based Linux
- Python 3.8+
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
============================================================
  Q-RECON: Quantum-Resilience Assessment Framework
  Version 1.0 | Authorized Penetration Testing ONLY
============================================================

[*] Target : google.com
[*] Time   : 2026-03-03 14:19:50

=======================================================
  PHASE 1: TARGET ENUMERATION
=======================================================
    [+] IP       : 142.251.220.14
    [+] Port     : OPEN
    [+] TLS      : TLSv1.3
    [+] Cipher   : TLS_AES_256_GCM_SHA384

=======================================================
  PHASE 2: CRYPTOGRAPHIC ASSESSMENT
=======================================================
[+] RSA Assessment
----------------------------------------
    Status  : INFO
    Finding : Certificate uses ECC not RSA

[+] ECC Exposure
----------------------------------------
    Status  : CRITICAL
    Finding : ECC curve secp256r1 detected - quantum vulnerable

[+] Key Exchange
----------------------------------------
    Status  : INFO
    Finding : Key exchange: TLS_AES_256_GCM_SHA384

[+] Digital Signatures
----------------------------------------
    Status  : MEDIUM
    Finding : Signature: SHA256

[+] Symmetric Encryption
----------------------------------------
    Status  : LOW
    Finding : AES-256 - adequate quantum resistance

[+] Hash Functions
----------------------------------------
    Status  : MEDIUM
    Finding : SHA-256 - Grover's reduces to 128-bit effective security

=======================================================
  QUANTUM RISK SCORE
=======================================================
  Score  : 40.8/100
  Rating : MEDIUM

=======================================================
[OK] Report: reports/qrecon_google_com_20260303_141952.html
[OK] Done  : reports/qrecon_google_com_20260303_141952.txt
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

---

## Legal Disclaimer

Q-Recon is designed for **authorized security assessments only**. Use of this tool against systems without explicit written permission is illegal and unethical. The authors accept no liability for misuse.

Q-Recon includes a built-in authorization verification prompt (`utils/authorization.py`) that requires the user to confirm written authorization, scope, and legal responsibility before any scan begins. This can be bypassed only with the `--skip-auth` flag in controlled lab environments.

---

## Authors and Contributors

**Shlok Trivedi** — Author 
- GitHub: [@ShlokTrivedi1023](https://github.com/ShlokTrivedi1023)
- Email: shloktrivedi1023@gmail.com

**Shreeya Shah** — Contributor
- Email: shreeyashah001@gmail.com

*Submitted to: Black Hat USA — Arsenal and Briefings 2026*

---

## License

MIT License — see LICENSE file for details.

---

*Q-Recon — Because the quantum threat is not coming. It is already here.*
