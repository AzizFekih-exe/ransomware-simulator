# Attack Flow – Ransomware Simulation

## Step-by-Step Flow

1. **Execution**

   * User runs the simulator script

2. **Directory Scanning**

   * The program traverses the target directory

3. **File Modification**

   * Files are renamed with `.simulated`
   * Simulates encryption behavior

4. **Ransom Note Creation**

   * A file named `README_RESTORE_FILES.txt` is created

5. **Impact**

   * Files appear “locked”
   * User perceives data loss

---

## Detection Points

* Sudden spike in file modifications
* Appearance of unusual extensions
* Creation of ransom note file

---

## Defensive Insight

These behaviors can be detected using:

* File monitoring systems
* Behavioral analysis tools
* Endpoint security solutions
