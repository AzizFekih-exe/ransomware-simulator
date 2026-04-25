# Encryptor Component Specification
**IT360 Project 14 | Phase 2**



## Component Overview

| Field | Detail |
|---|---|
| Component Name | Encryptor / Decryptor |
| Language | Python 3.11+ |
| Library | `cryptography` (OpenSSL wrapper) |
| Files | `src/encryptor/encryptor.py`, `src/encryptor/decryptor.py` |



## Inputs

| Input | Source | Description |
|---|---|---|
| `target_dir` | `config.py` | Root directory to walk for target files |
| `TARGET_EXTENSIONS` | `config.py` | Tuple of extensions to encrypt |
| `EXTENSION_BLACKLIST` | `config.py` | Extensions never to touch |
| `KILL_SWITCH_FILENAME` | `config.py` | Flag file path — halts execution if present |
| `aes_key_hex` | C2 server (via dropper) | Decryptor only — key returned after payment |


## Outputs

| Output | Consumer | Description |
|---|---|---|
| `*.locked` files | Victim filesystem | AES-256-CBC ciphertext with IV prepended |
| `.manifest.enc` | Decryptor | Encrypted SHA-256 hash manifest |
| `payload dict` | `dropper.py` (P1+P2) | `{aes_key_hex, iv_hex, files_encrypted, manifest_path}` |



## Encryption Algorithm

* **Algorithm** : AES-256-CBC
* **Key size** : 256 bits (32 bytes) — generated fresh per execution
* **IV size** : 128 bits (16 bytes) — generated fresh per execution
* **Padding** : PKCS7 (aligns plaintext to 128-bit block boundary)
* **IV storage** : Prepended to ciphertext in .locked file (first 16 bytes)
* **Library** : `cryptography.hazmat.primitives.ciphers`


## Key Lifecycle

1. `os.urandom(32)` → AES session key (exists in memory only)
2. `os.urandom(16)` → IV
3. Files encrypted with AES key
4. AES key returned to dropper as hex string
5. Dropper passes to P2 C2 module for RSA-wrapping + exfiltration
6. AES key zeroed from memory after handoff (future hardening)

---

## Integrity Verification (SHA-256 Manifest)

Before encryption, SHA-256 is computed for every target file and stored in
`.manifest.enc` (itself AES-encrypted with the session key). After decryption,
the decryptor recomputes SHA-256 for each restored file and compares against
the manifest. A mismatch indicates corruption.

This mirrors the reliability guarantee real ransomware operators must provide —
victims will not pay for a decryptor that corrupts their files.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Implementation |
|---|---|---|
| T1486 | Data Encrypted for Impact | AES-256-CBC encryption loop |
| T1083 | File and Directory Discovery | `os.walk()` with extension filter |
| T1005 | Data from Local System | File read before encryption |
| T1070.004 | File Deletion | Zero-overwrite + `os.remove()` |

## File Targeting Logic

```text
os.walk(target_dir)
└── for each file:
    if extension in EXTENSION_BLACKLIST → skip
    if extension in TARGET_EXTENSIONS   → encrypt
    else                                → ignore

