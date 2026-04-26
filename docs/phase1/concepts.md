# Ransomware — Core Concepts
**IT360 — Project 14 | P4: Threat Intelligence Analyst**
`docs/phase1/concepts.md`

---

## 1. What Is Ransomware?

Ransomware is a category of malicious software that denies victims access to their
own data — typically through encryption — and demands payment in exchange for
restoring that access. The term combines "ransom" and "software," but the underlying
model is more precisely described as **cryptoviral extortion**, a concept first
formalised by Adam Young and Moti Yung in their 1996 IEEE paper
*"Cryptovirology: Extortion-Based Security Threats and Countermeasures."*

Young and Yung's theoretical framework defined a three-step attack:

1. The adversary generates an asymmetric key pair and embeds the public key in the malware.
2. The malware encrypts the victim's files using the embedded public key (or a
   symmetric key wrapped by it), making decryption impossible without the adversary's
   private key.
3. The adversary demands payment and provides the private key (or the wrapped
   symmetric key) only upon receipt.

This model — written as theory in 1996 — became the operational blueprint for every
major ransomware family from CryptoLocker (2013) onward, and it is the exact model
implemented in this simulator.

---

## 2. The Kill Chain

Modern ransomware does not simply encrypt files. It follows a structured attack
sequence — often called the kill chain — that mirrors the broader MITRE ATT&CK
framework. The simulator implements all stages of this chain:

### Stage 1 — Initial Access
In the real world, the adversary delivers a dropper to the victim machine via
phishing email, exploit, or compromised supply chain. In this simulator,
`dropper.py` is placed on the victim VM manually to represent the post-delivery
state — the point at which the adversary already has execution on the victim machine.

### Stage 2 — Execution
`dropper.py` is executed. Before anything else, it checks for the kill-switch
file (`DO_NOT_RUN.flag`). If this file is present, the dropper exits immediately
with no effect. This mirrors the domain kill-switch implemented in WannaCry (2017),
where the malware checked for a specific unregistered domain before proceeding.

### Stage 3 — Discovery
The dropper calls `encryptor.py`, which uses `os.walk()` to recursively enumerate
the target directory. Every file is evaluated against two lists defined in
`config.py`:

- `TARGET_EXTENSIONS` — files to encrypt: `.txt`, `.docx`, `.pdf`, `.jpg`, `.png`, `.xlsx`
- `EXTENSION_BLACKLIST` — files to never touch: `.exe`, `.dll`, `.sys`, `.ini`, `.bat`, `.ps1`, `.lnk`, `.locked`

The blacklist is not accidental — real ransomware families including LockBit avoid
encrypting system files to ensure the victim machine remains bootable. A victim who
cannot reach the ransom note or the payment portal cannot pay.

### Stage 4 — Encryption
Each discovered file is encrypted using AES-256-CBC with a randomly generated
256-bit session key and 128-bit IV (both generated via `os.urandom()`). The IV is
prepended to the ciphertext. The original file is securely overwritten, and the
encrypted output is saved with the `.locked` extension appended to the original filename.

Before encryption begins, `encryptor.py` builds a SHA-256 hash manifest of all
target files. This manifest is itself encrypted and saved as `.manifest.enc`. The
decryptor uses this manifest to verify file integrity after restoration — confirming
that decryption was bit-perfect and no data was corrupted.

### Stage 5 — Exfiltration
The AES session key cannot remain on the victim machine — a defender with memory
access could recover it. Instead, the dropper:

1. Wraps (encrypts) the AES session key using the attacker's RSA-2048 public key
   (hardcoded in `config.py` as `RSA_PUBLIC_KEY_PEM`), with OAEP-SHA256 padding.
2. Generates a `victim_id` from a SHA-256 hash of the machine's hostname and MAC address.
3. Sends an HTTPS POST to `https://192.168.56.101:5000/register` with the payload:
   `{victim_id, rsa_encrypted_aes_key, hostname, timestamp}`.

The RSA-wrapped key is ciphertext — even if the POST request is intercepted by a
network monitor (e.g. Wireshark on the Host-Only interface), the AES key cannot
be recovered without the attacker's RSA private key, which never leaves the C2 server.

### Stage 6 — Extortion
After encryption and key exfiltration, `dropper.py` drops a `README_RESTORE.txt`
file in every affected directory. The note contains the victim's `victim_id` and
simulated payment instructions. This is the adversary's extortion demand — without
the AES session key (held by the C2 server), the victim cannot decrypt their files.

### Stage 7 — Decryption (Post-Payment)
When the simulated payment is acknowledged, the C2 operator calls
`POST /release/<victim_id>` on `server.py`. The `decryptor.py` module then:

1. Sends `GET /getkey/<victim_id>` to the C2 server (authenticated with `Admin-Token`).
2. Receives the RSA-wrapped AES key and decrypts it using the RSA private key.
3. Walks the target directory, decrypts each `.locked` file, and restores the
   original filename.
4. Verifies each restored file's SHA-256 hash against the `.manifest.enc` record.

---

## 3. Key Components

| Component | File | Role in Kill Chain |
|---|---|---|
| Dropper | `src/dropper/dropper.py` | Orchestrates all stages; generates victim_id; handles C2 registration |
| Encryptor | `src/encryptor/encryptor.py` | AES-256-CBC file encryption; manifest generation |
| Decryptor | `src/encryptor/decryptor.py` | File restoration; manifest integrity verification |
| C2 Server | `src/c2_server/server.py` | Receives RSA-wrapped keys; serves keys post-payment |
| Key Store | `src/c2_server/key_store.py` | In-memory store mapping victim_id → encrypted key data |
| Config | `src/common/config.py` | Single source of truth for all constants |

---

## 4. Hybrid Encryption Model

This simulator implements the **hybrid encryption model** — the standard used by
every serious ransomware family since CryptoLocker (2013).

The model solves a fundamental tension between two requirements:

- **Speed:** RSA is too slow to encrypt large files directly.
- **Security:** Symmetric-only encryption (a single AES key for all files,
  stored anywhere on the victim machine) is recoverable by a forensic analyst.

The solution is to combine both algorithms:

```
AES-256 session key  ──encrypt files──►  .locked files (fast, bulk)
        │
        └──RSA-2048 public key──►  256-byte ciphertext blob
                                        │
                                        └──HTTPS POST──►  C2 key store
```

**Why this is secure:**
The adversary's RSA private key never leaves the C2 server. The AES session key
never remains on the victim machine. Even full forensic access to the victim's
disk and memory (after the dropper exits) reveals nothing recoverable.

**Why this is the industry standard:**
The 2021 REvil takedown demonstrated this model's strength in reverse — law
enforcement recovered decryption keys only by gaining direct access to REvil's
private key server infrastructure. The cryptography itself was not broken.

### Key Lifecycle

| Phase | Key Material | Location | Protected By |
|---|---|---|---|
| Generation | AES-256 key + IV | Victim RAM only | In-memory, never written to disk |
| Encryption | AES-256 key | Victim RAM | Consumed during encryption loop |
| Exfiltration | RSA-wrapped AES key | HTTPS POST body | RSA-2048 OAEP + TLS |
| At rest (C2) | RSA-wrapped AES key | `key_store.py` | RSA-2048 (private key on C2 only) |
| Recovery | AES key | HTTPS GET response | TLS |

---

## 5. Persistence Mechanisms

Real ransomware families implement persistence to survive reboots — ensuring the
malware can re-encrypt any files the victim restores from backup before paying.

Common techniques include:

- **Registry Run Keys** (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) —
  adds an entry that re-launches the dropper on every user login. Maps to
  MITRE ATT&CK T1547.001.
- **Scheduled Tasks** — creates a Windows Task Scheduler job that fires the
  dropper on a schedule or system event.
- **Startup Folder** — places a shortcut or script in
  `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`.

**This simulator deliberately does not implement any persistence mechanism.**
Registry writes and scheduled task creation outside the isolated VM environment
represent an unacceptable safety risk. This is documented explicitly to demonstrate
professional engineering judgment — a red team tool should implement only what is
necessary within the stated scope, not everything that is technically possible.

This deliberate exclusion is noted in the MITRE ATT&CK mapping (T1547.001) as
"documented, not implemented."

---

## 6. MITRE ATT&CK Technique Summary

The following techniques are addressed in this simulator. Full mapping is in
`docs/phase1/mitre_initial_mapping.md` and finalised in `docs/phase3/mitre_final_mapping.md`.

| Technique ID | Name | Implemented |
|---|---|---|
| T1486 | Data Encrypted for Impact | Yes — AES-256-CBC encryption loop |
| T1041 | Exfiltration Over C2 Channel | Yes — HTTPS POST of RSA-wrapped key |
| T1083 | File and Directory Discovery | Yes — `os.walk()` with extension filter |
| T1070 | Indicator Removal | Yes — original file overwrite |
| T1547.001 | Boot/Logon Autostart — Registry Run Keys | Documented only, not implemented |

---

## References

- Young, A. & Yung, M. (1996). *Cryptovirology: Extortion-Based Security Threats and Countermeasures.* IEEE Symposium on Security and Privacy.
- MITRE ATT&CK Framework — https://attack.mitre.org
- NIST Special Publication 800-57 — Recommendation for Key Management
- Cannell, J. (2013). *CryptoLocker: An in-depth analysis.* Malwarebytes Labs.
- Europol (2021). *REvil ransomware infrastructure taken down.* Press release.