# Component Specification — Ransomware Simulator
**IT360 Project 14 | Phase 2**

---

## 1. Encryptor / Decryptor Component
**Owner: P1 — Malware Developer**

| Field | Detail |
|---|---|
| Files | `src/encryptor/encryptor.py`, `src/encryptor/decryptor.py` |
| Language | Python 3.11 |
| Library | `cryptography` |

### Inputs
| Input | Source | Description |
|---|---|---|
| `target_dir` | `config.py` | Root directory to walk for target files |
| `TARGET_EXTENSIONS` | `config.py` | Tuple of extensions to encrypt |
| `EXTENSION_BLACKLIST` | `config.py` | Extensions never to touch |
| `KILL_SWITCH_FILENAME` | `config.py` | Halts execution if present |
| `aes_key_hex` | C2 server via dropper | Decryptor only — key returned after payment |

### Outputs
| Output | Consumer | Description |
|---|---|---|
| `*.locked` files | Victim filesystem | AES-256-CBC ciphertext with IV prepended |
| `.manifest.enc` | Decryptor | Encrypted SHA-256 hash manifest |
| `payload dict` | `dropper.py` | `{aes_key_hex, iv_hex, files_encrypted, manifest_path}` |

### Key Lifecycle
1. `os.urandom(32)` → AES session key (in memory only)
2. `os.urandom(16)` → IV
3. Files encrypted with AES-256-CBC
4. AES key returned to dropper as hex string
5. Dropper passes to C2 module for RSA-wrapping and exfiltration

---

## 2. C2 Server Component
**Owner: P2 — C2 & Network Engineer**

| Field | Detail |
|---|---|
| Files | `src/c2_server/server.py`, `src/c2_server/key_store.py` |
| Language | Python 3.11 |
| Framework | Flask 3.x + HTTPS (self-signed cert) |

### Inputs
| Input | Source | Description |
|---|---|---|
| POST `/register` payload | `dropper.py` | `{victim_id, rsa_encrypted_aes_key, hostname, timestamp}` |
| GET `/getkey/<victim_id>` | Admin operator | Requires `Admin-Token` header |
| GET `/status` | Admin operator | Requires `Admin-Token` header |

### Outputs
| Output | Consumer | Description |
|---|---|---|
| `{status: registered}` | `dropper.py` | Confirms successful registration |
| `{aes_key: ...}` | Admin / decryptor | Returns RSA-encrypted AES key |
| `key_store` contents | Admin | Full list of registered victims |

### API Endpoints
| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/register` | POST | None | Victim registers and submits wrapped AES key |
| `/getkey/<victim_id>` | GET | Admin-Token | Returns stored AES key for victim |
| `/status` | GET | Admin-Token | Lists all registered victims |

---

## 3. Dropper Component
**Owner: P1 + P2**

| Field | Detail |
|---|---|
| File | `src/dropper/dropper.py` |
| Language | Python 3.11 |
| Libraries | `cryptography`, `requests` |

### Responsibilities
- Generates `victim_id` from SHA-256 hash of hostname + MAC address
- RSA-wraps the AES session key using the public key from `config.py`
- POSTs registration payload to C2 server over HTTPS

---

## 4. Shared Configuration
**Owner: P3 — Systems Architect**

| Field | Detail |
|---|---|
| File | `src/common/config.py` |
| Language | Python 3.11 |

### Constants
| Constant | Owner | Description |
|---|---|---|
| `C2_HOST`, `C2_PORT` | P2 | C2 server address |
| `C2_REGISTER_ENDPOINT` | P2 | Full registration URL |
| `TARGET_EXTENSIONS` | P1 | File types to encrypt |
| `EXTENSION_BLACKLIST` | P1 | File types never to touch |
| `KILL_SWITCH_FILENAME` | P1 | Safety flag file path |
| `RSA_PUBLIC_KEY_PEM` | P2 | Attacker's public key |
| `ADMIN_TOKEN` | P2 | Protects admin endpoints |