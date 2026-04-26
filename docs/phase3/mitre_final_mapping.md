# MITRE ATT&CK Final Mapping — Phase 3
**IT360 — Project 14 | P4: Threat Intelligence Analyst**
`docs/phase3/mitre_final_mapping.md`

> This is the finalised ATT&CK mapping for the ransomware simulator, expanded
> from the 5-technique Phase 1 draft to 10 confirmed techniques. Each entry
> documents the technique ID, tactic, implementation in the simulator, the
> Blue Team detection opportunity, and the real-world ransomware families that
> use the same technique. The machine-readable ATT&CK Navigator layer is
> exported in `docs/phase3/attack_layer.json`.

---

## 1. Full Mapping Table

| Tactic | Technique ID | Technique Name | Implemented |
|---|---|---|---|
| Execution | T1059.006 | Command and Scripting Interpreter: Python | ✅ Yes |
| Discovery | T1083 | File and Directory Discovery | ✅ Yes |
| Collection | T1005 | Data from Local System | ✅ Yes |
| Impact | T1486 | Data Encrypted for Impact | ✅ Yes |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | ✅ Yes |
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | ✅ Yes |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | ✅ Yes |
| Impact | T1490 | Inhibit System Recovery | ⚠️ Documented only |
| Persistence | T1547.001 | Boot/Logon Autostart: Registry Run Keys | ⚠️ Documented only |
| Defense Evasion | T1027 | Obfuscated Files or Information | ⚠️ Partial |

---

## 2. Technique Detail

---

### T1059.006 — Command and Scripting Interpreter: Python

**Tactic:** Execution
**Platform:** Windows, Linux, macOS

**Simulator implementation:**
The entire simulator is implemented in Python 3.11. The dropper
(`src/dropper/dropper.py`) is the initial execution entry point,
calling `encryptor.py` for file operations and `requests` for C2
communication. Python's interpreted nature makes the code portable
across platforms and easy to audit — a deliberate academic choice.

Real-world ransomware families (BlackCat, some REvil variants) use
compiled languages (Rust, C++) to avoid interpreter dependency and
reduce detection surface. Python is used here for clarity and
tooling availability.

**Real-world families:** PyLocky (2018) used Python; academic and
proof-of-concept ransomware implementations commonly use Python.

**Blue Team detection opportunity:**
- Alert on `python.exe` or `python3` processes spawning file I/O
  operations across multiple directories in rapid succession.
- Monitor for Python processes making outbound HTTPS connections —
  legitimate Python scripts rarely do this outside development
  environments.
- Application whitelisting (AppLocker, WDAC) can block unauthorised
  Python interpreter usage on managed endpoints.

---

### T1083 — File and Directory Discovery

**Tactic:** Discovery
**Platform:** Windows, Linux, macOS

**Simulator implementation:**
`encryptor.py` uses `os.walk(TARGET_DIRECTORY)` to recursively
enumerate the target directory tree. Each file's extension is
checked against `TARGET_EXTENSIONS` (allow list) and
`EXTENSION_BLACKLIST` (deny list) defined in `config.py`.
Only files matching the allow list and not on the deny list are
added to the encryption target queue.

The blacklist (`EXTENSION_BLACKLIST`) explicitly excludes `.exe`,
`.dll`, `.sys`, `.ini`, `.bat`, `.ps1`, `.lnk`, and `.locked` —
preserving OS functionality and preventing double-encryption.

**Real-world families:** All major families — WannaCry, REvil,
LockBit 3.0, Conti, BlackCat.

**Blue Team detection opportunity:**
- Alert on processes calling `FindFirstFile`/`FindNextFile`
  (Windows API equivalent of `os.walk`) across multiple top-level
  directories within seconds.
- Correlate with subsequent file modification events — discovery
  immediately followed by bulk writes is a strong ransomware signal.

---

### T1005 — Data from Local System

**Tactic:** Collection
**Platform:** Windows, Linux, macOS

**Simulator implementation:**
`encryptor.py` reads the complete byte content of each target file
before encryption (`open(filepath, "rb").read()`). The file content
is the "data collected" — it is then encrypted and the original
is destroyed. Additionally, `build_manifest()` reads each file to
compute its SHA-256 hash before encryption, creating a pre-encryption
record of all file contents.

This technique overlaps with T1083 in execution but is classified
separately because it involves actively reading file content, not
just enumerating names and paths.

**Real-world families:** All ransomware families that perform
double extortion (exfiltrating data before encrypting) — REvil,
Conti, BlackCat — explicitly implement T1005 for the exfiltration
phase. This simulator does not exfiltrate file content (only the
AES key), so T1005 applies only to the local read operation.

**Blue Team detection opportunity:**
- Monitor for processes opening large numbers of files for read
  access in rapid succession across multiple directories.
- File access auditing (Windows Security Event 4663) can log
  every file open operation — a sudden spike from an unfamiliar
  process is anomalous.

---

### T1486 — Data Encrypted for Impact

**Tactic:** Impact
**Platform:** Windows, Linux, macOS

**Simulator implementation:**
`encryptor.py` encrypts each target file with AES-256-CBC. A fresh
256-bit session key and 128-bit IV are generated via `os.urandom()`
at the start of each execution. The IV is prepended to the ciphertext
in each `.locked` file. PKCS7 padding aligns plaintext to the 128-bit
AES block boundary.

A SHA-256 manifest of all pre-encryption file hashes is built by
`build_manifest()` and encrypted with the same session key, saved
as `.manifest.enc`. The decryptor uses this manifest to verify
byte-perfect restoration after key recovery.

After encryption, `dropper.py` drops `README_RESTORE.txt` in every
affected directory — the extortion demand containing the `victim_id`
and simulated payment instructions.

**Real-world families:** Every ransomware family. WannaCry (AES-128),
REvil (AES-256), LockBit 3.0 (AES-256 + partial), Conti (AES-256),
BlackCat (AES-256 / ChaCha20).

**Blue Team detection opportunity:**
- Alert on high-volume file rename events appending a consistent
  new extension (`.locked`) within a short time window (< 30s).
- Monitor for processes writing files significantly larger or
  smaller than the originals — padding and IV prepending alter
  file sizes slightly.
- EDR behavioural rule: flag any process that modifies > 20 files
  per second with extension changes.

---

### T1041 — Exfiltration Over C2 Channel

**Tactic:** Exfiltration
**Platform:** Windows, Linux, macOS

**Simulator implementation:**
`dropper.py` wraps the AES session key with the attacker's
RSA-2048 public key (OAEP-SHA256 padding, loaded from
`config.py::RSA_PUBLIC_KEY_PEM`). The wrapped key is
base64-encoded and included in a JSON payload sent via
HTTPS POST to `https://192.168.56.101:5000/register`:

```json
{
  "victim_id": "<sha256(hostname+mac)>",
  "rsa_encrypted_aes_key": "<base64(RSA_OAEP(aes_key))>",
  "hostname": "SimulatedPC",
  "timestamp": "<uuid1>"
}
```

The RSA-wrapped key is ciphertext — intercepting this packet
reveals nothing without the attacker's RSA private key, which
never leaves `server.py` on the Kali C2 VM.

**Real-world families:** REvil (HTTPS to Tor), LockBit 3.0
(HTTPS to web panel), Conti (HTTPS to multi-tier C2).

**Blue Team detection opportunity:**
- Correlate disk I/O spike (encryption) with outbound HTTPS POST
  occurring within seconds — this two-event sequence is the
  encryption + exfiltration signature.
- Alert on HTTPS connections to bare IP addresses (no hostname)
  from non-browser processes.
- TLS inspection (enterprise proxy): the POST body contains a
  large base64 blob consistent with an encrypted key blob.

---

### T1070.004 — Indicator Removal: File Deletion

**Tactic:** Defense Evasion
**Platform:** Windows, Linux, macOS

**Simulator implementation:**
`encryptor.py::_secure_delete()` overwrites each original file
with zero bytes (`b"\x00" * size`), calls `os.fsync()` to flush
to disk, then deletes the file with `os.remove()`. This single-pass
zero-overwrite prevents plaintext recovery with standard forensic
tools (Autopsy, Recuva) that scan for file carving patterns.

This is a deliberately simplified implementation — production
ransomware (Conti, LockBit) performs multi-pass overwrite or
uses `MoveFileEx` with `MOVEFILE_DELAY_UNTIL_REBOOT` to defer
deletion, making forensic recovery harder.

**Real-world families:** Conti, LockBit 3.0, REvil (all
overwrite or securely delete originals post-encryption).

**Blue Team detection opportunity:**
- Monitor for processes writing uniform byte patterns (all zeros,
  all `0xFF`) to files immediately before deletion — consistent
  with secure overwrite behaviour.
- File system forensics: zero-overwritten files leave a distinct
  pattern in unallocated clusters distinguishable from normal
  file deletion.

---

### T1071.001 — Application Layer Protocol: Web Protocols

**Tactic:** Command and Control
**Platform:** Windows, Linux, macOS

**Simulator implementation:**
`server.py` implements a Flask HTTPS server on port 5000.
All C2 communication uses HTTPS (HTTP over TLS) with a self-signed
certificate loaded from `src/c2_server/certs/cert.pem`. Three
endpoints are exposed:

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/register` | POST | None | Victim submits RSA-wrapped AES key |
| `/getkey/<victim_id>` | GET | Admin-Token | Returns stored key post-payment |
| `/status` | GET | Admin-Token | Lists all registered victims |

HTTPS blends C2 traffic with normal web traffic, evading
protocol-based detection. TLS encryption prevents payload
inspection by network middleboxes without certificate pinning.

**Real-world families:** REvil (HTTPS to Tor hidden service),
LockBit 3.0 (HTTPS to web panel), most modern RaaS families.

**Blue Team detection opportunity:**
- Alert on TLS connections using self-signed certificates
  (absent from certificate transparency logs).
- Monitor for HTTPS traffic to IP addresses (not domain names)
  from non-browser, non-updater processes.
- JA3 fingerprinting: Python's `requests` library produces a
  distinctive TLS client hello fingerprint detectable by
  network security monitoring tools.

---

### T1490 — Inhibit System Recovery

**Tactic:** Impact
**Platform:** Windows

**Simulator implementation: ⚠️ Documented only — not implemented.**

In real ransomware, this technique involves deleting Volume Shadow
Copies to prevent the victim from restoring files without paying:
```
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
```
Conti, LockBit 3.0, REvil, and WannaCry all implement this as a
standard pre-encryption step. Without shadow copies, Windows System
Restore and Previous Versions are unavailable to the victim.

**Reason for exclusion:** Shadow copy deletion is irreversible
outside the VM and would cause permanent data loss on the host
machine if the dropper were accidentally executed outside VirtualBox.
This is documented for Blue Team awareness and MITRE completeness.

**Blue Team detection opportunity:**
- Alert on any execution of `vssadmin.exe delete` or
  `wmic shadowcopy delete` outside a known maintenance window.
- Monitor for `IVssBackupComponents::DeleteSnapshots` API calls
  from non-backup processes.
- MITRE ATT&CK T1490 detection is high-confidence — there are
  very few legitimate reasons for non-administrative processes
  to delete shadow copies.

---

### T1547.001 — Boot/Logon Autostart: Registry Run Keys

**Tactic:** Persistence
**Platform:** Windows

**Simulator implementation: ⚠️ Documented only — not implemented.**

Real ransomware writes to registry run keys to survive reboots:
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

This ensures the dropper re-executes on every login, re-encrypting
any files the victim restored from backup before the ransom is paid.
Modern families like LockBit 3.0 often skip persistence in targeted
attacks — they encrypt fast and exit, since persistence increases
detection dwell time.

**Reason for exclusion:** Registry writes outside the VM could
cause the dropper to persist on the host machine across reboots —
an unacceptable safety risk in an academic setting.

**Blue Team detection opportunity:**
- Alert on new entries written to `Run` or `RunOnce` registry
  keys by processes that are not installers or update agents.
- Monitor `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
  for new file creation.

---

### T1027 — Obfuscated Files or Information

**Tactic:** Defense Evasion
**Platform:** Windows, Linux, macOS

**Simulator implementation: ⚠️ Partial.**

The RSA-wrapped AES key is base64-encoded before being embedded
in the JSON POST body (`dropper.py`). Base64 encoding is a minimal
form of obfuscation — the key material is not transmitted as raw
bytes or readable hex, but as an encoded string that obscures
the binary nature of the payload from casual inspection.

More significantly, all file content is encrypted (AES-256-CBC),
making encrypted files unrecognisable — a forensic analyst cannot
determine the original file type from the `.locked` ciphertext
without the AES key.

**Real-world families:** REvil encoded payloads in base64 within
registry entries. LockBit 3.0 encrypted its configuration block.
BlackCat encrypted its entire configuration with a hardcoded key
embedded in the binary.

**Blue Team detection opportunity:**
- Entropy analysis: encrypted files have near-maximum entropy
  (~8.0 bits/byte). Alert on processes producing high-entropy
  output files across many files in rapid succession.
- YARA rules can detect high-entropy file content consistent
  with encryption — widely used in EDR tools for ransomware
  detection before signature updates are available.

---

## 3. Comparison Against Real Ransomware Families

### vs. WannaCry (2017)

| TTP | WannaCry | This Simulator |
|---|---|---|
| Propagation | EternalBlue (SMBv1) worm | Manual deployment |
| Encryption | AES-128-CBC | AES-256-CBC |
| Key wrapping | RSA-2048 | RSA-2048 OAEP |
| Kill-switch | DNS domain check | `DO_NOT_RUN.flag` file |
| Shadow copy deletion | Yes (T1490) | Documented only |
| C2 | Tor | Flask HTTPS |

**Match:** Kill-switch concept, hybrid encryption model, RSA key wrapping.
**Intentional simplification:** No propagation module; AES key size increased
to 256-bit; kill-switch uses local file rather than DNS to avoid network
dependency in the VM lab.

---

### vs. LockBit 3.0 (2022)

| TTP | LockBit 3.0 | This Simulator |
|---|---|---|
| Execution | Compiled C++ | Python 3.11 |
| Encryption speed | 25,000+ files/min (multi-threaded) | Single-threaded |
| File targeting | Extension blacklist | Extension blacklist (identical concept) |
| Key wrapping | RSA-2048 | RSA-2048 OAEP |
| C2 | Web panel HTTPS | Flask HTTPS |
| Shadow copy deletion | Yes | Documented only |
| Persistence | Optional (often skipped) | Documented only |

**Match:** Extension blacklisting (identical logic — `EXTENSION_BLACKLIST` in
`config.py` mirrors LockBit's approach), HTTPS C2, RSA key wrapping,
deliberate persistence exclusion in targeted deployments.
**Intentional simplification:** Single-threaded encryption; Python interpreter
dependency; no multi-pass overwrite; no RaaS affiliate infrastructure.

---

## 4. Defensive Countermeasures Appendix

For each implemented technique, the following table provides the detection
rule a SOC analyst would write, mapped to the corresponding TTP.

| Technique | Detection Rule | Mapped TTP |
|---|---|---|
| Python dropper execution | Alert: `python.exe` spawning file I/O + outbound HTTPS within 60s | T1059.006 |
| File discovery | Alert: process calls `FindFirstFile` on > 5 directories within 10s | T1083 |
| Bulk file read | Alert: process opens > 50 files for read in < 30s | T1005 |
| Encryption loop | Alert: > 20 file renames with new extension within 30s | T1486 |
| Key exfiltration | Alert: HTTPS POST to bare IP address from non-browser process | T1041 |
| Secure file deletion | Alert: process writes uniform bytes to file then calls DeleteFile | T1070.004 |
| C2 over HTTPS | Alert: TLS connection to self-signed cert from non-browser process | T1071.001 |
| High-entropy output | YARA: files with entropy > 7.8 bits/byte produced in bulk | T1027 |

---

## References

- MITRE ATT&CK Framework: https://attack.mitre.org
- ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
- T1059.006: https://attack.mitre.org/techniques/T1059/006/
- T1083: https://attack.mitre.org/techniques/T1083/
- T1005: https://attack.mitre.org/techniques/T1005/
- T1486: https://attack.mitre.org/techniques/T1486/
- T1041: https://attack.mitre.org/techniques/T1041/
- T1070.004: https://attack.mitre.org/techniques/T1070/004/
- T1071.001: https://attack.mitre.org/techniques/T1071/001/
- T1490: https://attack.mitre.org/techniques/T1490/
- T1547.001: https://attack.mitre.org/techniques/T1547/001/
- T1027: https://attack.mitre.org/techniques/T1027/
- ATT&CK Navigator layer: `docs/phase3/attack_layer.json`