# Threat Intelligence Report – Ransomware Simulator

## 1. Overview

This project simulates the behavior of a ransomware attack in a controlled academic environment.
The goal is to understand attacker techniques and develop defensive detection mechanisms.

The simulation mimics key ransomware behaviors such as:

* Rapid file modification
* File renaming (simulated encryption)
* Ransom note creation

---

## 2. Attack Flow (High-Level)

1. Initial execution of the payload
2. File system traversal
3. Mass file modification (renaming)
4. Creation of ransom note
5. System impact (user files inaccessible)

---

## 3. Technical Behavior Analysis

### File System Activity

* Recursively scans directories
* Targets multiple file types
* Renames files with a new extension (e.g., `.simulated`)

### Impact Simulation

* No real encryption is performed
* Behavior mimics real ransomware impact

### Ransom Note

* A text file is created in the target directory
* Simulates attacker communication

---

## 4. Indicators of Compromise (IOCs)

* Unusual file extensions: `.simulated`
* Presence of ransom note: `README_RESTORE_FILES.txt`
* Rapid file modification events
* High volume of file renaming in short time

---

## 5. Detection Strategy

A behavioral detection approach was implemented:

* Monitoring file system activity
* Detecting mass modifications within a short time window
* Identifying suspicious file extensions
* Triggering alerts based on thresholds

---

## 6. MITRE ATT&CK Mapping

The simulated behavior aligns with known adversary techniques such as:

* Execution via user interaction
* File and directory discovery
* Data encryption for impact

---

## 7. Mitigation Recommendations

* Regular offline backups
* Endpoint Detection & Response (EDR)
* File integrity monitoring
* User awareness and phishing prevention
* Least privilege access control

---

## 8. Conclusion

This project demonstrates how ransomware operates at a behavioral level and how such attacks can be detected using simple monitoring techniques.

The addition of detection scripts highlights the importance of defensive cybersecurity strategies.
