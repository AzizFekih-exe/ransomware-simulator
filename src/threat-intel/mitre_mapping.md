# MITRE ATT&CK Mapping

This project maps simulated ransomware behavior to the MITRE ATT&CK framework.

| Stage     | Technique ID | Technique Name               | Description                              |
| --------- | ------------ | ---------------------------- | ---------------------------------------- |
| Execution | T1204        | User Execution               | User runs the malicious file             |
| Discovery | T1083        | File and Directory Discovery | Scans system for files                   |
| Impact    | T1486        | Data Encrypted for Impact    | Files are renamed to simulate encryption |
| Impact    | T1490        | Inhibit System Recovery      | Ransom scenario implies loss of access   |

---

## Notes

Although this is a safe simulation, it reflects real-world ransomware behaviors and aligns with known adversary tactics.
