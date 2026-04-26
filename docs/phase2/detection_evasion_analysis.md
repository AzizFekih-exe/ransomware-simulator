# Detection Evasion Analysis — Appendix to HLD
**IT360 — Project 14 | P4: Threat Intelligence Analyst**
`docs/phase2/detection_evasion_analysis.md`

> This document serves as the detection evasion appendix referenced in
> `docs/phase2/HLD.md`. It analyses the evasion techniques used by real
> ransomware families, identifies which techniques this simulator implements,
> and explicitly documents which are excluded and why. This dual treatment —
> implemented vs. deliberately excluded — demonstrates professional engineering
> judgment in an academic red team context.

---

## 1. Overview

Detection evasion is the capability that separates sophisticated ransomware from
amateur implementations. A ransomware family that encrypts files quickly but
triggers every EDR rule within seconds of execution will never collect a ransom.
Real operators invest heavily in anti-detection measures across the full kill chain.

This analysis examines evasion techniques across six categories, maps each to
MITRE ATT&CK, and evaluates this simulator's position on each.

---

## 2. Evasion Technique Analysis

### 2.1 Process Injection (T1055)

**What it is:**
Process injection allows malware to execute code inside the address space of a
legitimate, trusted process — for example, `explorer.exe` or `svchost.exe`.
Because the malicious code runs under the trusted process's identity, most
endpoint security tools attribute its network connections, file operations,
and registry writes to the trusted process rather than the malware.

**How real ransomware uses it:**
Conti injected shellcode into running processes to evade process-level monitoring.
LockBit 3.0 used process hollowing — creating a legitimate process in a suspended
state, replacing its memory with malicious code, and resuming execution. This
technique causes the malicious code to inherit the parent process's security token,
making its actions appear legitimate to kernel-level monitors.

**Simulator status: ❌ Not implemented.**

**Reason for exclusion:**
Process injection requires low-level Windows API calls (`VirtualAllocEx`,
`WriteProcessMemory`, `CreateRemoteThread`) that operate at the kernel boundary.
Implementing this in the simulator would produce a tool capable of evading
production EDR systems — well beyond the academic scope of this project. The
simulator's dropper runs as its own clearly identifiable Python process, making
it immediately visible to any process monitor.

**Blue Team detection:**
Monitor for `CreateRemoteThread` calls targeting processes the parent did not
spawn. Alert on memory allocation in remote processes (`VirtualAllocEx` +
`WriteProcessMemory` sequence). EDR tools (CrowdStrike, SentinelOne) detect
this pattern reliably on modern Windows systems.

---

### 2.2 Living Off the Land Binaries (LOLBAS) (T1218)

**What it is:**
Living Off the Land Binaries (LOLBAS) are legitimate Windows system executables
that attackers repurpose to execute malicious actions. Because these binaries are
signed by Microsoft and expected to run on any Windows system, they are
frequently whitelisted by application control policies and generate less
suspicion in process logs.

**How real ransomware uses it:**
REvil used `wmic.exe` to delete Volume Shadow Copies:
`wmic shadowcopy delete`. LockBit 3.0 used `vssadmin.exe` for the same purpose
and `certutil.exe` for base64-decoding payloads. Conti used `net.exe` for
network share enumeration. BlackCat used `fsutil.exe` to set the sparse flag
on files during partial encryption.

**Simulator status: ❌ Not implemented.**

**Reason for exclusion:**
LOLBAS techniques target Windows system components and could cause unintended
side effects outside the isolated VM environment. Shadow copy deletion
(`vssadmin delete shadows /all`) is irreversible and would destroy legitimate
backup data if executed on the host machine by accident. The simulator performs
all operations through Python's standard library (`os`, `cryptography`) with no
system binary invocations.

**Blue Team detection:**
Alert on `vssadmin.exe` or `wmic.exe shadowcopy delete` executed by any
non-administrative process or outside a known maintenance window. Monitor for
`certutil.exe -decode` usage — a well-known LOLBin abuse pattern for payload
staging. MITRE ATT&CK T1490 (Inhibit System Recovery) covers shadow copy
deletion specifically.

---

### 2.3 Timestomping (T1070.006)

**What it is:**
Timestomping is the modification of a file's MACB timestamps (Modified, Accessed,
Changed, Born) to make malicious files appear to have been created at a different
time. This technique hinders forensic timeline analysis — an investigator building
a timeline of events may fail to identify when the malware was first introduced
to the system.

**How real ransomware uses it:**
Conti operators routinely timestomped dropper executables to match the creation
dates of legitimate system files in the same directory, making the dropper appear
to be a long-standing system component. REvil affiliates timestomped staging
files during the dwell period before encryption began.

**Simulator status: ❌ Not implemented.**

**Reason for exclusion:**
Timestomping requires direct manipulation of NTFS metadata — either through the
Windows `SetFileTime` API or direct hex editing of the Master File Table (MFT).
This technique is irrelevant to the simulator's academic purpose: demonstrating
the encryption and key management cycle. Implementing it would add complexity
without educational value, and could complicate the VM restore procedure for P5.

**Blue Team detection:**
Compare filesystem timestamps against event log entries — a file "created" in
2019 that appears in event logs from 2026 is a clear indicator. Tools like
Autopsy and Plaso reconstruct MACB timelines from the MFT independently of
the timestamps reported by the OS, exposing timestomping. Monitor for
`SetFileTime` API calls from processes that have no business modifying
system file metadata.

---

### 2.4 Encryption Speed Optimisation (T1486 variant)

**What it is:**
Modern ransomware families optimise their encryption loops to complete before
EDR behaviour-based detection rules trigger. Rules typically alert on sustained
high-volume file modification over a time window — so faster encryption means
fewer files remain unencrypted when the alert fires, and less time for automated
response to intervene.

**How real ransomware uses it:**
LockBit 3.0 achieves encryption speeds exceeding 25,000 files per minute through
multi-threading (one thread per CPU core) and partial file encryption — only
the first 4 KB of files larger than a threshold are encrypted, which is
sufficient to render files unrecoverable while dramatically reducing I/O time.
BlackCat (written in Rust) uses async I/O and the ChaCha20 stream cipher
(faster than AES on systems without AES-NI hardware acceleration) for the
same effect.

**Simulator status: ⚠️ Partially implemented.**

**What the simulator does:**
`encryptor.py` encrypts the complete content of each file with AES-256-CBC
in a single-threaded sequential loop. This is the correct design for an academic
simulator — it is simple, auditable, and produces reliably decryptable output.
However, it is significantly slower than production ransomware and would trigger
time-window-based EDR rules long before completing on a large filesystem.

**What is deliberately excluded:**
Multi-threading, partial file encryption, and stream cipher substitution
(ChaCha20) are not implemented. These optimisations would make the simulator
harder to study, harder to stop during testing, and would reduce educational
clarity with no academic benefit.

**Blue Team detection:**
Alert on high-volume file modification events (> 100 files with a new
extension within 30 seconds). Even the simulator's single-threaded loop
will trigger this rule on a moderately sized test directory. Network-level
detection: correlate the disk I/O spike with an outbound HTTPS POST occurring
immediately after — this two-event sequence is the encryption + exfiltration
pattern common to all ransomware families.

---

### 2.5 Anti-Analysis and Sandbox Evasion (T1497)

**What it is:**
Sandbox evasion techniques cause malware to behave benignly when executed in
an automated analysis environment (such as Cuckoo Sandbox or Any.run), and
maliciously only when running on a genuine victim machine. Common checks include
detecting virtual machine artefacts (VMware registry keys, VirtualBox drivers),
checking for the presence of analysis tools (Wireshark, Process Monitor), or
delaying execution until after the sandbox's analysis window has expired.

**How real ransomware uses it:**
REvil checked for the system language — if the victim machine's locale was set
to a CIS country (Russia, Belarus, Ukraine, Kazakhstan), the malware exited
without encrypting. This was both a geopolitical choice and a sandbox evasion
technique, since many sandbox environments run in Russian-language Windows
instances. LockBit 3.0 performed similar locale checks and additionally
detected the presence of analysis tools in the running process list before
proceeding.

**Simulator status: ❌ Not implemented.**

**Reason for exclusion:**
Anti-analysis techniques serve no purpose in an academic simulator that is
intentionally run in a controlled VM environment and examined by instructors
and team members. Implementing VM detection would cause the simulator to exit
immediately in VirtualBox — the exact environment P5 has configured — making
the project untestable.

The kill-switch (`DO_NOT_RUN.flag`) serves a similar structural role — a
condition that causes the dropper to exit harmlessly — but is an explicit
safety mechanism rather than an evasion technique.

**Blue Team detection:**
Monitor for processes querying VM-specific registry keys
(`HKLM\SOFTWARE\VMware, Inc.\`) or WMI queries for `Win32_ComputerSystem`
manufacturer fields. Alert on processes enumerating the running process list
within the first seconds of execution — a pattern consistent with sandbox/tool
detection rather than legitimate application behaviour.

---

### 2.6 C2 Traffic Obfuscation (T1001)

**What it is:**
C2 traffic obfuscation disguises command and control communications to appear
as legitimate network traffic, evading network-based detection systems
(IDS/IPS, DPI, proxy inspection). Techniques include domain fronting (routing
C2 traffic through legitimate CDN infrastructure), protocol mimicry (making
C2 packets resemble legitimate HTTP/HTTPS traffic), and using legitimate
cloud services (Dropbox, Pastebin, Discord) as C2 channels.

**How real ransomware uses it:**
REvil used Tor hidden services to anonymise C2 infrastructure entirely.
LockBit 3.0 used HTTPS to web panel endpoints that mimicked legitimate
web application traffic. BlackCat used customisable network profiles
(similar to Cobalt Strike malleable C2) to shape traffic to match specific
legitimate services.

**Simulator status: ⚠️ Partially implemented.**

**What the simulator does:**
`server.py` uses HTTPS (TLS with a self-signed certificate) for all C2
communication. This provides transport-layer encryption, ensuring the
RSA-wrapped AES key is not visible to a passive network observer. The use
of HTTPS on port 5000 — rather than raw TCP — means the traffic blends
structurally with legitimate HTTPS traffic, and DPI cannot inspect the
payload without breaking TLS.

**What is deliberately excluded:**
Domain fronting, Tor routing, and protocol mimicry are not implemented.
The C2 IP (`192.168.56.101`) is hardcoded in `config.py` — in a real
deployment this would be immediately identified as a C2 indicator in
network logs. Tor and domain fronting are excluded because they would
require additional infrastructure beyond the Host-Only VM network
and are not necessary to demonstrate the key management mechanism.

**Blue Team detection:**
Alert on TLS connections to self-signed certificates (certificate
transparency logs will not contain them). Monitor for outbound HTTPS
to IP addresses rather than domain names — legitimate services
almost universally use DNS names. Correlate: a HTTPS POST to a bare
IP address immediately after high-volume file modification is a
high-confidence ransomware indicator.

---

## 3. Summary Table

| Technique | MITRE ID | Real Ransomware | Simulator | Reason if Excluded |
|---|---|---|---|---|
| Process injection | T1055 | Conti, LockBit 3.0 | ❌ Not implemented | Kernel-level; out of academic scope |
| LOLBAS abuse | T1218 | REvil, LockBit 3.0, Conti | ❌ Not implemented | Irreversible system side-effects |
| Timestomping | T1070.006 | Conti, REvil affiliates | ❌ Not implemented | No educational value; complicates VM restore |
| Encryption speed optimisation | T1486 | LockBit 3.0, BlackCat | ⚠️ Partial | Single-threaded; full-file only |
| Sandbox / VM evasion | T1497 | REvil, LockBit 3.0 | ❌ Not implemented | Would break VirtualBox test environment |
| C2 traffic obfuscation | T1001 | REvil, LockBit 3.0, BlackCat | ⚠️ Partial | HTTPS implemented; Tor/fronting excluded |
| File extension blacklisting | T1486 | LockBit 3.0, REvil | ✅ Implemented | `EXTENSION_BLACKLIST` in `config.py` |
| Kill-switch | T1486 | WannaCry | ✅ Implemented | `DO_NOT_RUN.flag` in `config.py` |
| RSA key wrapping | T1486 | All major families | ✅ Implemented | `dropper.py` + RSA-OAEP |
| HTTPS C2 transport | T1071.001 | REvil, LockBit 3.0 | ✅ Implemented | `server.py` + self-signed TLS |

---

## 4. Professional Judgment Statement

The deliberate exclusion of process injection, LOLBAS, timestomping, and
sandbox evasion is not a limitation — it is a design choice. A responsible
red team tool implements only what is necessary to demonstrate the mechanism
under study, within the stated safety boundaries.

This simulator's purpose is to demonstrate the hybrid encryption and key
management lifecycle: key generation, file encryption, RSA wrapping, C2
exfiltration, and verified decryption. Every implemented technique serves
this purpose directly. Every excluded technique either introduces irreversible
system risk, extends beyond the VM boundary, or adds complexity without
proportionate educational value.

This boundary — knowing what to build and what not to build — is the
defining characteristic of professional security engineering.

---

## References

- MITRE ATT&CK T1055 (Process Injection): https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1218 (System Binary Proxy Execution): https://attack.mitre.org/techniques/T1218/
- MITRE ATT&CK T1070.006 (Timestomping): https://attack.mitre.org/techniques/T1070/006/
- MITRE ATT&CK T1497 (Virtualisation/Sandbox Evasion): https://attack.mitre.org/techniques/T1497/
- MITRE ATT&CK T1001 (Data Obfuscation): https://attack.mitre.org/techniques/T1001/
- LOLBAS Project: https://lolbas-project.github.io/
- Mandiant (2022). *Conti Ransomware: Inside a Criminal Enterprise.*
- Secureworks (2022). *LockBit 3.0 Technical Analysis.*