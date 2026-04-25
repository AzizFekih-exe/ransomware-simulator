# Tools and Phases — Ransomware Simulator
**IT360 Project 14 | Phase 2**

---

## 1. Full Tools Table

| Tool | Purpose | Owner |
|---|---|---|
| Python 3.11 | Core language for all modules | P1, P2, P3 |
| `cryptography` lib | AES-256-CBC encryption, RSA-2048 OAEP key wrapping | P1 |
| Flask 3.x | C2 HTTP server — REST API endpoints | P2 |
| pyOpenSSL / SSL Context | Self-signed TLS certificate for HTTPS transport | P2 |
| VirtualBox | VM isolation — host-only network between attacker and victim | P5 |
| GitHub Actions | CI/CD pipeline — runs flake8 and bandit on every PR | P3 |
| flake8 | Python linter — enforces code style (max line length 100) | P3 |
| bandit | Python security scanner — flags high/medium severity issues | P3 |
| MITRE ATT&CK Navigator | TTP mapping and attack layer JSON export | P4 |
| Wireshark | Network traffic analysis inside the VM lab | P5 |

---

## 2. C2 Component — Tools Detail
**Owner: P2 — C2 & Network Engineer**

### Flask
Flask is a lightweight Python web framework used to build the C2 server REST API.
It hosts the `/register`, `/getkey/<victim_id>`, and `/status` endpoints,
receives simulated victim registration data, and serves encrypted AES keys to the admin.

### pyOpenSSL / SSL Context
Provides HTTPS transport for all C2 communication. A self-signed certificate
(`cert.pem`) and private key (`key.pem`) are generated for local testing and
loaded into Flask's SSL context. This ensures the RSA-wrapped AES key is never
transmitted in plaintext, even in the simulation.

### HTTPS Rationale
All communication between the dropper and C2 involves encryption key material.
Plain HTTP would expose this in transit. TLS ensures confidentiality and integrity
at the transport layer. A self-signed certificate is adequate for the Host-Only
VM network — a production deployment would require a CA-signed certificate.

---

## 3. Encryptor Component — Tools Detail
**Owner: P1 — Malware Developer**

### `cryptography` Library
The `cryptography` package (OpenSSL wrapper) is used for all cryptographic operations:
- AES-256-CBC for file content encryption via `cryptography.hazmat.primitives.ciphers`
- PKCS7 padding to align plaintext to the 128-bit AES block boundary
- RSA-2048 OAEP with SHA-256 for AES session key wrapping in `dropper.py`

This library is preferred over `pycryptodome` for its FIPS alignment and
professional adoption in production security tooling.

---

## 4. CI/CD Pipeline — Tools Detail
**Owner: P3 — Systems Architect**

### GitHub Actions
A CI pipeline runs automatically on every pull request targeting `main`.
It spins up a fresh Ubuntu environment, installs dependencies, and runs
both flake8 and bandit against the `src/` directory.

### flake8
Enforces Python code style with a maximum line length of 100 characters.
Configured via `.flake8` to exclude `__pycache__`, `.git`, and virtual environments.

### bandit
Scans Python source code for common security issues. Configured via `.bandit`
to skip B101 (assert statements) and exclude test and virtual environment directories.
Only medium and high severity findings (`-ll`) are flagged to avoid noise.

---

## 5. VM Lab — Tools Detail
**Owner: P5 — Environment & QA Specialist**

### VirtualBox
Hosts two isolated virtual machines connected via a Host-Only network adapter:
- **Kali Linux 2024.x** — attacker machine, runs the C2 server
- **Windows 10 22H2** — victim machine, runs the dropper and encryptor

The victim VM has no NAT or bridged adapter — it cannot reach the internet.
A clean snapshot (`CLEAN_BASELINE`) is taken after OS install and restored
between test runs to ensure a reproducible test environment.

### Wireshark
Used during Phase 3 testing to capture network traffic on the Host-Only interface.
Will be used to demonstrate that the RSA-wrapped AES key is transmitted as
ciphertext — not recoverable without the attacker's private key.