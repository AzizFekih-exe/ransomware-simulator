# MITRE ATT&CK Initial Mapping — Phase 1
**IT360 — Project 14 | P4: Threat Intelligence Analyst**
`docs/phase1/mitre_initial_mapping.md`

> **Note:** This is the Phase 1 draft mapping covering the 5 core techniques
> identified during the design phase. It will be expanded to 8–10 techniques
> in Phase 2 and finalised with the ATT&CK Navigator layer export in Phase 3
> (`docs/phase3/mitre_final_mapping.md`).

---

## Mapping Table

| Tactic | Technique ID | Technique Name | Simulator Implementation | Implemented |
|---|---|---|---|---|
| Impact | T1486 | Data Encrypted for Impact | AES-256-CBC encryption loop in `encryptor.py` targeting `.txt`, `.docx`, `.pdf`, `.jpg`, `.png`, `.xlsx`. Files renamed with `.locked` extension. Original files securely overwritten. | ✅ Yes |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | RSA-2048-OAEP-wrapped AES session key sent via HTTPS `POST /register` to `server.py`. Plaintext key never transmitted — only the 256-byte RSA ciphertext blob crosses the wire. | ✅ Yes |
| Discovery | T1083 | File and Directory Discovery | `encryptor.py` uses `os.walk()` to recursively enumerate `TARGET_DIRECTORY`. Files filtered against `TARGET_EXTENSIONS` and `EXTENSION_BLACKLIST` defined in `config.py`. | ✅ Yes |
| Defense Evasion | T1070 | Indicator Removal | Original file content overwritten in place before the `.locked` copy is written. Prevents trivial file recovery from disk. Shadow copy deletion and log clearing are real-world extensions — not implemented here for safety. | ✅ Yes |
| Persistence | T1547.001 | Boot/Logon Autostart — Registry Run Keys | Registry run key persistence documented as a potential technique. **Not implemented** — writing outside the VM to registry run keys represents an unacceptable safety risk in an academic setting. Noted for awareness and Blue Team detection purposes. | ⚠️ Documented only |

---

## Technique Detail

### T1486 — Data Encrypted for Impact

**Tactic:** Impact
**Platforms:** Windows, Linux, macOS

**Description:**
Adversaries encrypt files on target systems to interrupt availability and
demand ransom payment for the decryption key. This is the defining action
of ransomware and the primary impact technique in the kill chain.

**Simulator implementation:**
`encryptor.py` generates a random 256-bit AES session key and 128-bit IV
via `os.urandom()` on each execution. Each discovered file is read, padded
to the AES block boundary using PKCS7, encrypted with AES-256-CBC, and
written back with the `.locked` extension appended. The IV is prepended
to the ciphertext for use during decryption. The original file is
overwritten and deleted.

**Real-world examples:**
WannaCry (2017), REvil (2019–2021), LockBit 3.0 (2022–present),
Conti (2020–2022), BlackCat/ALPHV (2021–2024).

**Blue Team detection opportunity:**
- Alert on high-volume file rename events adding `.locked` (or any
  consistent) extension within a short time window (< 30 seconds).
- Monitor for processes reading and writing large numbers of files in
  rapid succession — anomalous disk I/O pattern.
- Endpoint Detection and Response (EDR) rule: flag any process that
  renames > 20 files with a non-standard extension within 10 seconds.

---

### T1041 — Exfiltration Over C2 Channel

**Tactic:** Exfiltration
**Platforms:** Windows, Linux, macOS

**Description:**
Adversaries exfiltrate data over the same command and control channel
used for other communications, blending key exfiltration with normal
C2 traffic to evade network-based detection.

**Simulator implementation:**
`dropper.py` constructs a JSON payload containing `victim_id`
(SHA-256 hash of hostname + MAC address), `rsa_encrypted_aes_key`
(the AES session key wrapped with the attacker's RSA-2048 public key
using OAEP-SHA256 padding), `hostname`, and `timestamp`. This payload
is sent via HTTPS POST to `https://192.168.56.101:5000/register`.
TLS encryption (self-signed certificate in `src/c2_server/certs/`)
wraps the entire HTTP layer — the RSA-encrypted key is therefore
protected at two levels: RSA wrapping + TLS transport.

**Real-world examples:**
REvil used HTTPS POST to Tor hidden services. LockBit used HTTPS to
web panel endpoints. Both blend with legitimate HTTPS traffic to
avoid DPI-based detection.

**Blue Team detection opportunity:**
- Alert on anomalous HTTPS POST requests to previously unseen external
  IP addresses, especially shortly after a spike in disk I/O activity.
- Correlate: high disk I/O (encryption) followed immediately by an
  outbound HTTPS POST is a strong indicator of key exfiltration.
- Network baseline deviation: flag any process making outbound HTTPS
  connections that has not done so in its observed history.

---

### T1083 — File and Directory Discovery

**Tactic:** Discovery
**Platforms:** Windows, Linux, macOS

**Description:**
Adversaries enumerate files and directories on the victim system to
identify targets for encryption, exfiltration, or lateral movement.

**Simulator implementation:**
`encryptor.py` calls `os.walk(TARGET_DIRECTORY)` to recursively
traverse the target directory tree. For each file encountered, the
extension is checked against `TARGET_EXTENSIONS` (allow list) and
`EXTENSION_BLACKLIST` (deny list), both defined in `config.py`.
System-critical extensions (`.exe`, `.dll`, `.sys`) are explicitly
excluded to preserve OS functionality — the same approach used by
LockBit 3.0 to keep the victim machine bootable.

**Real-world examples:**
All major ransomware families perform file discovery before encryption.
LockBit 3.0 additionally scans network shares. Conti included a
network scanner module for lateral discovery.

**Blue Team detection opportunity:**
- Alert on processes performing recursive directory enumeration
  across multiple top-level folders in rapid succession.
- Flag `os.walk()`-equivalent syscall patterns (e.g. `FindFirstFile`
  / `FindNextFile` API calls in rapid sequence on Windows) from
  non-administrative processes.

---

### T1070 — Indicator Removal

**Tactic:** Defense Evasion
**Platforms:** Windows, Linux, macOS

**Description:**
Adversaries delete or modify artifacts on a host system to remove
evidence of their actions and hinder forensic investigation and
incident response.

**Simulator implementation:**
After encrypting each file, `encryptor.py` overwrites the original
file content before deletion, preventing straightforward file
carving recovery. In real-world ransomware, T1070 also commonly
includes deletion of Volume Shadow Copies
(`vssadmin delete shadows /all /quiet` — T1490) and clearing of
Windows Event Logs. These sub-techniques are deliberately excluded
from this simulator for safety — they would cause irreversible
data loss outside the VM environment.

**Real-world examples:**
WannaCry deleted shadow copies. Conti and LockBit 3.0 both
systematically cleared event logs and deleted shadow copies as
standard pre-encryption steps.

**Blue Team detection opportunity:**
- Alert on `vssadmin` or `wmic shadowcopy delete` command execution
  by non-administrative processes.
- Monitor for processes opening and writing to files immediately
  before those files are deleted — pattern consistent with
  secure overwrite behaviour.

---

### T1547.001 — Boot/Logon Autostart: Registry Run Keys / Startup Folder

**Tactic:** Persistence
**Platforms:** Windows

**Description:**
Adversaries add entries to registry Run keys or the Startup folder
to achieve persistence, causing their malware to execute automatically
on system boot or user login.

**Simulator implementation:**
**Not implemented.** Registry writes outside the isolated VM
environment represent an unacceptable safety risk in an academic
context — a mistake could cause the dropper to execute on the
host machine after a reboot.

This technique is documented here for completeness and Blue Team
awareness. In a real deployment, the dropper would write to:
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
with a value pointing to the dropper executable path.

**Real-world examples:**
Early ransomware families (CryptoLocker, CryptoWall) relied heavily
on run key persistence. Modern families like LockBit 3.0 often avoid
persistence entirely in targeted attacks — they encrypt as fast as
possible and exit, since persistence increases detection risk.

**Blue Team detection opportunity:**
- Alert on new entries written to `Run` or `RunOnce` registry keys
  by non-standard processes.
- Monitor for new files placed in
  `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`.

---

## ATT&CK Navigator Note

A machine-readable ATT&CK Navigator layer file (`attack_layer.json`)
will be generated and committed to `docs/phase3/` in Phase 3,
covering the full expanded set of 8–10 mapped techniques. The Navigator
layer can be imported at https://mitre-attack.github.io/attack-navigator/
to produce a visual heatmap of the techniques implemented by this simulator.

---

## References

- MITRE ATT&CK T1486: https://attack.mitre.org/techniques/T1486/
- MITRE ATT&CK T1041: https://attack.mitre.org/techniques/T1041/
- MITRE ATT&CK T1083: https://attack.mitre.org/techniques/T1083/
- MITRE ATT&CK T1070: https://attack.mitre.org/techniques/T1070/
- MITRE ATT&CK T1547.001: https://attack.mitre.org/techniques/T1547/001/