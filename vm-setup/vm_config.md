# VM Configuration (Updated Phase 2)

## 1. Attacker VM (KaliAttacker)
* **OS:** Kali Linux 2024.x
* **RAM:** 2048 MB
* **Storage:** 20 GB
* **Network:** Host-Only Adapter
* **IP Address:** 192.168.56.101

## 2. Victim VM (WindowsVictim)
* **OS:** Windows 10 22H2
* **RAM:** 2048 MB
* **Storage:** 40 GB
* **Network:** Host-Only Adapter
* **IP Address:** 192.168.56.102

## 3. Network Verification
* **External Connectivity:** `ping 8.8.8.8` from Windows VM failed as intended, confirming no internet route.
* **Inter-VM Connectivity:** `ping` between Kali and Windows VMs succeeded, confirming isolated communication.
* **C2 Port Check:** Verified connectivity to the C2 listener via port 5000.

## 4. Phase 2 Integration Proofs
* **Protocol Adjustment:** Transitioned the C2 communication from HTTPS to **HTTP** to facilitate stable execution within the air-gapped lab without SSL/TLS certificate conflicts.
* **Cross-VM Handshake:** Successfully registered the `victim_id` from the Windows VM to the Kali C2 server.
    * **Windows PowerShell:** Confirmed `Server response: {"status":"registered"}`.
    * **Kali Terminal:** Logged `192.168.56.102 - - "POST /register HTTP/1.1" 200 -`.

## 5. Snapshots Taken
* **CLEAN_BASELINE:** Taken immediately after OS install, before any code execution.
* **CLEAN_BASELINE_KALI:** Taken after Kali OS install, before C2 configuration.
* **PRE_TEST_PHASE3:** Taken on 2026-04-26. This is the integration baseline for the final kill-chain, containing verified networking and functional dropper-to-C2 registration.

### Evidence Gallery
* `Capture_d_écran_2026-04-15_210550.png` — VirtualBox snapshot panel showing CLEAN_BASELINE.
* `Capture_d_écran_2026-04-15_210724.png` — KaliAttacker running (CLEAN_BASELINE_KALI).
* `Capture_d_écran_2026-04-15_210738.png` — WindowsVictim running (CLEAN_BASELINE).
* **`Screenshot 2026-04-26 201206.jpg`** — Evidence of successful cross-VM `POST /register` with HTTP 200 status.
* **`Screenshot 2026-04-26 183829.png`** — Documentation of initial local integration and encryptor functionality.