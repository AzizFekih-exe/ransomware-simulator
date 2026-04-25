# High-Level Design — Ransomware Simulator
**IT360 Project 14 | Phase 2**

---

## 1. Architecture Overview

The simulator consists of two machines connected over a Host-Only network:
- **Victim Machine (Windows 10)** — runs the dropper, encryptor, and decryptor
- **Attacker Machine (Kali Linux)** — runs the C2 server and key store

```mermaid
graph TD
    subgraph Victim Machine
        A[dropper.py] --> B[encryptor.py]
        A --> C[C2 Client - HTTPS POST]
        B --> D[.locked files]
        B --> E[.manifest.enc]
        F[decryptor.py] --> G[Restored files]
    end

    subgraph Attacker Machine
        H[server.py - Flask HTTPS]
        I[key_store.py - In-memory store]
        H --> I
    end

    C -->|POST /register - RSA-wrapped AES key| H
    H -->|GET /getkey - AES key returned| F
```

---

## 2. Component Table

| Component | Purpose | Language / Framework | Inputs | Outputs | Interfaces |
|---|---|---|---|---|---|
| `dropper.py` | Orchestrates the full kill chain | Python 3.11 | `config.py` constants, RSA public key | RSA-wrapped AES key, C2 registration | Calls `encryptor.py`, calls C2 `/register` |
| `encryptor.py` | Encrypts target files with AES-256-CBC | Python 3.11 + `cryptography` | Target directory, AES key + IV | `.locked` files, `.manifest.enc`, payload dict | Called by `dropper.py` |
| `decryptor.py` | Restores encrypted files after key recovery | Python 3.11 + `cryptography` | AES key hex (from C2), `.locked` files | Restored plaintext files | Called by `dropper.py` or standalone |
| `server.py` | C2 server — receives and serves keys | Python 3.11 + Flask + HTTPS | POST `/register` payload, GET `/getkey` request | JSON responses, stored key data | Exposes REST API over HTTPS port 5000 |
| `key_store.py` | In-memory store for victim key data | Python 3.11 | `store_agent()`, `get_agent()` calls | Victim key records | Called by `server.py` |
| `config.py` | Shared constants — single source of truth | Python 3.11 | N/A | C2 URL, extensions, RSA public key, kill-switch path | Imported by all modules |

---

## 3. Data Flow & Message Exchange

```mermaid
sequenceDiagram
    participant D as dropper.py (Victim)
    participant E as encryptor.py (Victim)
    participant FS as Filesystem (Victim)
    participant C2 as server.py (Kali C2)
    participant KS as key_store.py

    D->>D: Check kill-switch (DO_NOT_RUN.flag)
    D->>E: run_encryption(target_dir)
    E->>E: Generate AES-256 key + IV (os.urandom)
    E->>FS: os.walk() — discover target files
    E->>E: Build SHA-256 manifest
    E->>FS: Encrypt each file → .locked (IV + ciphertext)
    E->>FS: Secure-delete originals
    E->>FS: Save .manifest.enc (AES-encrypted)
    E-->>D: Return payload {aes_key_hex, iv_hex, files_encrypted}

    D->>D: RSA-wrap AES key with public key (OAEP + SHA-256)
    D->>D: Generate victim_id (SHA-256 of hostname + MAC)
    D->>C2: HTTPS POST /register {victim_id, rsa_encrypted_aes_key, hostname, timestamp}
    C2->>KS: store_agent(victim_id, data)
    C2-->>D: 200 OK {status: registered}

    Note over C2: Admin triggers simulated payment

    D->>C2: GET /getkey/<victim_id> + Admin-Token header
    C2->>KS: get_agent(victim_id)
    KS-->>C2: Return stored key data
    C2-->>D: 200 OK {aes_key: rsa_encrypted_aes_key}
    D->>E: run_decryption(target_dir, aes_key_hex)
    E->>FS: Decrypt each .locked file → restore original
    E->>E: Verify SHA-256 integrity against manifest
```

---

## 4. Security Boundaries

| Stage | Data in Transit | Encryption State | Notes |
|---|---|---|---|
| File encryption | Plaintext → `.locked` | AES-256-CBC | IV prepended to ciphertext, original securely deleted |
| Manifest storage | File hashes → `.manifest.enc` | AES-256-CBC | Same session key, IV prepended |
| AES key in memory | Raw bytes | Unencrypted | Exists in memory only during execution |
| AES key to C2 | `rsa_encrypted_aes_key` field | RSA-2048 OAEP | Intercepting this packet reveals nothing without private key |
| C2 transport layer | Full HTTP payload | TLS (self-signed cert) | HTTPS on port 5000, cert in `src/c2_server/certs/` |
| Key at rest on C2 | Stored in `key_store.py` | RSA-encrypted | Private key never leaves the C2 server |
| Key returned to victim | `aes_key` in response | TLS only | Returned as RSA-encrypted blob, dropper decrypts with private key |

### Security Boundary Diagram

```mermaid
graph LR
    A[Plaintext Files] -->|AES-256-CBC| B[.locked Files]
    C[AES Session Key] -->|RSA-2048 OAEP| D[Encrypted Key Blob]
    D -->|TLS HTTPS| E[C2 Key Store]
    E -->|TLS HTTPS| F[Decryptor]
    F -->|AES-256-CBC| G[Restored Files]
```