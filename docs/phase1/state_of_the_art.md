# State of the Art — Ransomware Families
**IT360 — Project 14 | P4: Threat Intelligence Analyst**
`docs/phase1/state_of_the_art.md`

---

## 1. Overview

This document surveys five major ransomware families that define the current
state of the art in cryptoviral extortion. Each case study examines the
technical architecture, operational model, and key innovations that influenced
subsequent ransomware development — including the design decisions made in
this simulator.

The families are presented chronologically to illustrate the evolution of
ransomware from opportunistic commodity malware to sophisticated, state-adjacent
criminal enterprises.

---

## 2. WannaCry (2017)

### Background
WannaCry was a self-propagating ransomware worm that infected approximately
200,000 systems across 150 countries in May 2017, causing estimated damages
between USD 4 billion and USD 8 billion. It is attributed to the Lazarus Group,
a threat actor with ties to the Democratic People's Republic of Korea.

### Technical Architecture

**Propagation — EternalBlue (CVE-2017-0144):**
WannaCry's defining characteristic was its worm component, which exploited
EternalBlue — an NSA-developed exploit leaked by the Shadow Brokers in April
2017. EternalBlue targeted a buffer overflow vulnerability in Microsoft's
SMBv1 protocol (`ms17-010`), allowing unauthenticated remote code execution.
Once inside a network, WannaCry scanned for other hosts with port 445 open
and self-replicated without any user interaction — making it the first major
ransomware worm at scale.

**Encryption:**
WannaCry used a hybrid encryption model: AES-128-CBC for file content
encryption and RSA-2048 for key wrapping. Each infected host generated a
unique AES key, which was encrypted with an embedded RSA public key and
stored locally. A critical implementation flaw, however, allowed free
decryption tools (such as WanaKiwi) to recover keys from memory on unrebooted
Windows XP systems — because the RSA prime factors were not securely cleared
from RAM after use.

**The Kill-Switch Domain:**
Before executing its payload, WannaCry queried a hardcoded, unregistered domain.
If the domain resolved (i.e. returned any response), the malware exited
immediately. Security researcher Marcus Hutchins registered this domain for
approximately USD 10, halting the global spread within hours. This mechanism
was likely intended as an anti-sandbox check — sandbox environments often
resolve all DNS queries — but it functioned as an accidental global kill-switch.

**Relevance to this simulator:**
Our `dropper.py` implements a direct analogue of WannaCry's kill-switch: if the
file `DO_NOT_RUN.flag` exists in the working directory, the dropper exits
immediately. This is documented in `config.py` as `KILL_SWITCH_FILENAME`.

### CVE Reference
- **CVE-2017-0144** — Windows SMB Remote Code Execution (EternalBlue)
- **CVE-2017-0145** — Windows SMB Remote Code Execution (EternalRomance)

---

## 3. REvil / Sodinokibi (2019–2021)

### Background
REvil (also known as Sodinokibi) emerged in April 2019 as a Ransomware-as-a-Service
(RaaS) operation, widely believed to be a successor to GandCrab. At its peak,
REvil was responsible for approximately 37% of all ransomware attacks globally.
The group was disrupted in October 2021 following a multinational law enforcement
operation that seized their Tor-based infrastructure.

### Technical Architecture

**Ransomware-as-a-Service (RaaS) Model:**
REvil operated as a criminal franchise. The core developers maintained the
malware and C2 infrastructure, while affiliates — independent criminal actors —
paid a subscription or revenue share (typically 20–30%) to deploy REvil against
targets of their choosing. This separation of development and operations made
attribution and takedown significantly more complex.

**C2 Architecture — Tor Hidden Services:**
REvil used Tor hidden services (`.onion` addresses) for key negotiation and
victim communication. This provided strong anonymity for the C2 infrastructure
and made domain seizure ineffective — unlike WannaCry's clearnet kill-switch
domain, a Tor hidden service cannot be "registered away." Victim payments were
demanded in Monero (XMR) rather than Bitcoin for enhanced transaction anonymity.

**Key Exfiltration — HTTPS POST:**
Key exfiltration was performed over HTTPS POST requests to the C2, avoiding
deep packet inspection (DPI) by blending with normal web traffic. This is the
exact protocol choice made in this simulator — our `dropper.py` sends the
RSA-wrapped AES key via HTTPS POST to `server.py` on the C2.

**The Kaseya Attack (July 2021):**
REvil's most significant operation exploited a zero-day vulnerability
(CVE-2021-30116) in Kaseya VSA, an IT management platform used by managed
service providers (MSPs). By compromising a single Kaseya server, REvil
simultaneously encrypted systems at approximately 1,500 downstream businesses.
This supply-chain attack demonstrated how RaaS operators could achieve massive
scale through a single entry point, rather than individually targeting victims.

### CVE Reference
- **CVE-2021-30116** — Kaseya VSA Credential Disclosure and Business Logic Flaw

---

## 4. LockBit 3.0 (2022–present)

### Background
LockBit is the most prolific ransomware operation of the 2020s, responsible for
more confirmed attacks than any other group. LockBit 3.0 (also called LockBit
Black) was released in June 2022 and represented a significant technical leap
over its predecessors, partially incorporating code from the leaked Conti source.

### Technical Architecture

**Speed Optimisation:**
LockBit 3.0's primary technical differentiator is encryption speed. It uses a
combination of AES and RSA, but optimises the encryption loop through
multi-threading and partial file encryption — only encrypting the first N bytes
of large files rather than the full content. This makes file recovery from
partial backups impossible while dramatically reducing encryption time.
LockBit reportedly encrypts at rates exceeding 25,000 files per minute on
modern hardware.

**Extension Blacklisting:**
LockBit implements an explicit blacklist of system-critical file extensions
(`.exe`, `.dll`, `.sys`) to preserve OS functionality and ensure the victim
can still access the ransom note and payment portal. This simulator implements
the same pattern via `EXTENSION_BLACKLIST` in `config.py`.

**Bug Bounty Programme:**
In an unprecedented move for criminal malware, LockBit 3.0 launched a public
bug bounty programme — offering payments of USD 1,000 to USD 1,000,000 for
vulnerabilities in their malware or infrastructure. This demonstrated a level
of operational maturity that blurred the line between criminal enterprise and
legitimate software development practice.

**Web-Based Admin Panel:**
Unlike REvil's Tor-based model, LockBit 3.0 used a web-based affiliate
management panel for affiliate tracking, victim management, and negotiation.
This is the architecture referenced in `docs/phase1/c2_architecture_review.md`
(P2's deliverable).

### CVE Reference
- **CVE-2023-44487** — HTTP/2 Rapid Reset (used by LockBit-affiliated actors
  for DDoS-based extortion alongside ransomware campaigns)

---

## 5. Conti (2020–2022)

### Background
Conti was one of the most sophisticated and well-organised ransomware groups
ever documented. Operating from approximately 2020 until its dissolution in
May 2022, Conti attacked over 1,000 organisations including the Irish Health
Service Executive (HSE) and the Costa Rican government. The group's downfall
came after an internal dispute led a disgruntled affiliate to leak approximately
60,000 internal chat messages and the complete Conti source code.

### Lessons from the Leaked Source Code

The Conti leak provided the security research community with unprecedented
visibility into professional ransomware engineering:

- **Modular architecture:** Conti separated the encryptor, network scanner,
  and C2 communication into distinct modules — the same separation of concerns
  adopted in this simulator (`encryptor.py`, `dropper.py`, `server.py`).
- **Multi-threaded encryption:** Conti used Windows I/O Completion Ports
  (IOCP) for parallel file encryption, achieving high throughput on multi-core
  systems.
- **Targeted deployment:** Unlike worms, Conti was deployed manually by
  operators after gaining network access — a "big game hunting" model
  targeting organisations rather than mass consumers.
- **The leak as a security resource:** The Conti source code is now widely
  studied by defenders and threat intelligence analysts to understand
  professional-grade ransomware internals. Its architectural patterns
  influenced the design of LockBit 3.0.

---

## 6. BlackCat / ALPHV (2021–2024)

### Background
BlackCat (also known as ALPHV) was the first major ransomware family written
entirely in Rust, appearing in November 2021. It operated as a RaaS and
targeted organisations across critical infrastructure sectors. The FBI
disrupted BlackCat's infrastructure in December 2023, seizing their leak site
and obtaining a decryption tool for approximately 500 victims, but the group
briefly resurged before dissolving in March 2024 following an alleged exit scam.

### Technical Architecture

**Rust-Based, Cross-Platform:**
BlackCat's decision to implement in Rust was significant for several reasons:

- **Cross-platform:** A single codebase compiled to native executables for
  Windows, Linux, and VMware ESXi — allowing attacks on virtualisation
  infrastructure, which hosts multiple victim systems per physical server.
- **Memory safety:** Rust's ownership model eliminates entire classes of
  memory corruption bugs that have historically allowed decryptors to recover
  keys from flawed implementations (as with WannaCry on Windows XP).
- **Detection evasion:** Rust binaries are less commonly analysed than C or
  C++ malware, and produce unfamiliar binary patterns that some legacy
  signature-based AV tools failed to detect on initial deployment.

**ECC Key Exchange — Curve25519:**
BlackCat moved beyond RSA for key exchange, adopting Curve25519 (X25519 ECDH)
for session key establishment. Curve25519 provides equivalent security to
RSA-3072 with a 256-bit key, produces smaller ciphertexts, and is faster —
particularly relevant for high-throughput encryption operations.

This represents the current direction of ransomware cryptography. Our simulator
uses RSA-2048 (the previous-generation standard) as documented in
`docs/phase1/crypto_rationale.md` — a deliberate choice for clarity and
tooling availability in an academic context.

**Relevance to this simulator:**
BlackCat's architecture illustrates the trajectory from RSA toward ECC-based
key exchange. The `crypto_rationale.md` document (P1) notes Curve25519 as
the forward-looking alternative to our RSA-2048 implementation.

---

## 7. Comparative Summary

| Family | Year | Language | Encryption | Key Exchange | C2 Model | RaaS |
|---|---|---|---|---|---|---|
| WannaCry | 2017 | C | AES-128-CBC | RSA-2048 | Tor + clearnet | No |
| REvil | 2019 | C | AES-256 | RSA-2048 | Tor hidden service | Yes |
| LockBit 3.0 | 2022 | C/C++ | AES + partial | RSA-2048 | Web panel | Yes |
| Conti | 2020 | C++ | AES-256 | RSA-2048 | Multi-tier | Yes |
| BlackCat | 2021 | Rust | AES-256/ChaCha20 | Curve25519 | Tor + web | Yes |
| **This simulator** | **2026** | **Python** | **AES-256-CBC** | **RSA-2048 OAEP** | **Flask HTTPS** | **No** |

---

## 8. Academic References

- Young, A. & Yung, M. (1996). *Cryptovirology: Extortion-Based Security Threats
  and Countermeasures.* IEEE Symposium on Security and Privacy.
- Mohurle, S. & Patil, M. (2017). *A brief study of WannaCry threat: Ransomware
  attack 2017.* International Journal of Advanced Research in Computer Science, 8(5).
- Coveware (2022). *Ransomware as a Service: The REvil/Sodinokibi case study.*
  Quarterly Ransomware Report Q1 2022.
- Brewer, R. (2016). *Ransomware attacks: detection, prevention and cure.*
  Network Security, 2016(9), 5–9.
- Liska, A. & Gallo, T. (2022). *Ransomware: Understand. Prevent. Recover.*
  O'Reilly Media.
- CISA Alert AA22-040A (2022). *2021 Trends Show Increased Globalized Threat
  of Ransomware.* Cybersecurity and Infrastructure Security Agency.
- FBI Flash CU-000167-MW (2022). *Indicators of Compromise Associated with
  BlackCat/ALPHV Ransomware.* Federal Bureau of Investigation.
- CVE-2017-0144: https://nvd.nist.gov/vuln/detail/CVE-2017-0144
- CVE-2021-30116: https://nvd.nist.gov/vuln/detail/CVE-2021-30116