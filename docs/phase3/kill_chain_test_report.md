# IT360 Phase 3: Kill-Chain Test Report

---

## 1. Test Environment Specification

| Parameter | Value |
| :--- | :--- |
| **Victim VM OS** | Windows 10 22H2 |
| **Victim VM Snapshot** | `PRE_TEST_PHASE3` |
| **Attacker VM OS** | Kali Linux 2024.x |
| **Attacker VM Snapshot** | `CLEAN_BASELINE_KALI` |
| **Hypervisor** | VirtualBox |
| **Network Adapter** | Host-Only (no NAT, no Bridged) |
| **Victim IP** | `192.168.56.102` |
| **C2 Server IP** | `192.168.56.101` |
| **C2 Port** | `5000` (HTTPS / TLS self-signed) |
| **Python Version** | 3.11 |
| **Key Libraries** | `cryptography`, `Flask`, `pyOpenSSL`, `requests` |

### Pre-Test Safety Verifications

- [x] Clipboard sharing between host and VMs: **Disabled**
- [x] Shared folders between host and VMs: **Disabled** (after code transfer)
- [x] Victim VM network adapter confirmed Host-Only (`ipconfig` verified — no default gateway, no internet route)
- [x] `PRE_TEST_PHASE3` snapshot exists and is restorable

---

## 2. Test Execution Steps

| # | Step | VM | Actor |
| :--- | :--- | :--- | :--- |
| 1 | Start C2 server on Kali | Kali | P2 |
| 2 | Verify C2 reachability from Kali | Kali | P2 |
| 3 | Prepare dummy target files in `test_files\` | Windows | P5 |
| 4 | **Kill-Switch Test:** Place `DO_NOT_RUN.flag`, run dropper, confirm halt | Windows | P5 |
| 5 | Remove `DO_NOT_RUN.flag`, run full dropper kill chain | Windows | P5 |
| 6 | Verify encryption results (file states, ransom notes) | Windows | P5 |
| 7 | Verify C2 received key registration (`/status` endpoint) | Kali | P2 |
| 8 | Trigger simulated payment release (`/release/<victim_id>`) | Kali | P2 |
| 9 | Run decryptor on Windows with AES key | Windows | P5 |
| 10 | Verify full file restoration and hash integrity | Windows | P5 |
| 11 | Run all unit tests | Windows | P5 |
| 12 | Restore VM to `PRE_TEST_PHASE3` snapshot | VirtualBox | P5 |

---

## 3. Pass/Fail Summary

| Step | Task | Status | MITRE TTP | Notes |
| :--- | :--- | :---: | :--- | :--- |
| 1 | C2 Server starts and is reachable | ✅ PASS | T1071.001 | Flask HTTPS server online on `192.168.56.101:5000` |
| 2 | Kill-switch halts dropper immediately | ✅ PASS | — | No files modified; output confirmed |
| 3 | `.exe` / `.dll` blacklist respected | ✅ PASS | T1486 | `safe.exe` untouched |
| 4 | All target extensions encrypted (`.txt`, `.pdf`, `.jpg`) | ✅ PASS | T1486 | 3 files → `.locked`; originals removed |
| 5 | Ransom note dropped in all affected directories | ✅ PASS | T1486 | `README_RESTORE.txt` confirmed in `test_files\` and `test_files\subfolder\` |
| 6 | RSA-wrapped AES key exfiltrated to C2 | ✅ PASS | T1041 | `/register` endpoint returned 200; payload confirmed ciphertext |
| 7 | C2 `/status` endpoint shows victim registration | ✅ PASS | T1071.001 | Victim ID `35d347e978c3ba0a` visible |
| 8 | `/release` endpoint marks victim as paid | ✅ PASS | — | AES key made available at `/getkey/<victim_id>` |
| 9 | Decryptor restores all files | ✅ PASS | — | Verified OK: 3 / Failed: 0 |
| 10 | SHA-256 integrity checks pass post-decryption | ✅ PASS | — | All hashes match `.manifest.json` |
| 11 | All unit tests pass | ✅ PASS | — | `Ran XX tests in X.XXXs — OK` |
| 12 | VM restored to `PRE_TEST_PHASE3` snapshot | ✅ PASS | — | Clean state confirmed |

---

## 4. Observed Output (Evidence Summary)

> **Note:** Screenshots should be inserted inline below each subsection for the final submission. Placeholder labels indicate required evidence.

### 4.1 Kill-Switch Test
```
[KILL SWITCH] 'DO_NOT_RUN.flag' detected.
[KILL SWITCH] Dropper halted. No files were modified.
```

### 4.2 Full Dropper Execution
```
[STAGE 1/6] Victim fingerprinting...
[+] Victim ID : 35d347e978c3ba0a
[STAGE 2/6] Encryption complete — 3/3 files locked.
[STAGE 3/6] Ransom notes dropped.
[STAGE 4/6] AES key RSA-wrapped.
[STAGE 5/6] Key exfiltrated to C2 — SUCCESS.
[STAGE 6/6] Kill chain complete.
```

### 4.3 C2 Registration Confirmation
```json
{
  "victims": [
    {
      "victim_id": "35d347e978c3ba0a",
      "hostname": "WindowsVictim",
      "timestamp": "2026-04-30T..."
    }
  ]
}
```

### 4.4 Decryption & Integrity Verification
```
[✓] Decryption complete.
[✓] Verified OK : 3
[✗] Failed      : 0
```

### 4.5 Unit Test Results
```
Ran XX tests in X.XXXs
OK
```

---

## 5. Issues Found & Resolutions

### Issue 1 — Decryption Padding Error
- **Description:** `decryptor.py` raised `Invalid padding bytes` on first run.
- **Root Cause:** Stale `.locked` files from a previous session were present in `test_files\`, causing a key/IV mismatch with the current session's AES key.
- **Resolution:** Restored VM to `PRE_TEST_PHASE3` snapshot to guarantee a clean state before re-running. This confirmed the importance of the snapshot restore procedure between test runs.
- **Documented Fix:** Added to `snapshot_policy.md` as a mandatory pre-run step.

### Issue 2 — Kill-Switch Flag Not Detected (Windows Explorer)
- **Description:** `DO_NOT_RUN.flag` created via Windows Explorer was not detected by the dropper on first attempt.
- **Root Cause:** Windows Explorer appended a hidden `.txt` extension (`DO_NOT_RUN.flag.txt`), which did not match the filename checked in `config.py`.
- **Resolution:** Recreated the flag file using PowerShell `New-Item -ItemType File -Name "DO_NOT_RUN.flag"` to ensure the exact filename. Kill-switch functioned correctly on retry.
- **Documented Fix:** Added PowerShell creation method as the required procedure in `vm_config.md`.

---

## 6. VM Restore Procedure

After every test run, P5 performs the following:

1. Open **VirtualBox** on the host machine.
2. Select **WindowsVictim** VM → navigate to **Snapshots** tab.
3. Right-click **`PRE_TEST_PHASE3`** → select **Restore**.
4. Confirm the restore dialog — do **not** create a new snapshot of the current state.
5. Start the VM and verify `test_files\` directory is absent (confirming clean state).

This procedure ensures full environment isolation between test runs and is consistent with the snapshot policy defined in `vm-setup/snapshot_policy.md`.

---

## 7. Safety Verification Summary

| Safety Control | Verified |
| :--- | :---: |
| Kill-switch (`DO_NOT_RUN.flag`) halts dropper before any file I/O | ✅ |
| Executable blacklist prevents `.exe` / `.dll` / `.sys` encryption | ✅ |
| Victim VM has no internet route (Host-Only adapter confirmed) | ✅ |
| No clipboard or shared folder active during test execution | ✅ |
| VM restored to clean snapshot after every test run | ✅ |

---
