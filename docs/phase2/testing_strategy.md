# Phase 2: Testing Strategy & QA Report

## 1. Integration Test Approach
To verify the cross-VM communication between the Windows Victim and Kali Attacker, we utilized the following methodology:

* **Connectivity Verification:** Used `Test-NetConnection -ComputerName 192.168.56.101 -Port 5000` to confirm the Host-Only network bridge allows TCP traffic.
* **Protocol Alignment:** Successfully transitioned the C2 communication from HTTPS to HTTP for the lab environment to ensure connectivity without local certificate errors.
* **Handshake Validation:** Verified that the `dropper.py` on Windows correctly reaches the `/register` endpoint on Kali, resulting in a `200 OK` status and a successful registration log.

## 2. VM Restore & Snapshot Procedure
As per project safety requirements, all testing is confined to an air-gapped environment [cite: 276].
* **Snapshot Baseline:** A snapshot named `PRE_TEST_PHASE3` has been established [cite: 474].
* **Restore Logic:**
    1. Power off the Victim VM after any test execution [cite: 514].
    2. Revert to `PRE_TEST_PHASE3` to clear all `.locked` files and the ransom note [cite: 514].
    3. Restart the Kali C2 server before triggering a new test run [cite: 514].


