# VM Configuration

## Attacker VM (KaliAttacker)
- OS: Kali Linux 2024.x
- RAM: 2048 MB
- Storage: 20 GB
- Network: Host-Only Adapter
- IP Address: 192.168.56.101

## Victim VM (WindowsVictim)
- OS: Windows 10 22H2
- RAM: 2048 MB
- Storage: 40 GB
- Network: Host-Only Adapter
- IP Address: 192.168.56.102

## Network Verification
- ping 8.8.8.8 from Windows VM: FAILED (no internet - confirmed)
- ping between VMs: SUCCESS (isolated communication confirmed)

## Snapshots Taken
- CLEAN_BASELINE: taken after OS install, before any code
- CLEAN_BASELINE_KALI: taken after OS install, before any code
- `Capture_d_écran_2026-04-15_210550.png` — VirtualBox snapshot panel showing CLEAN_BASELINE
- `Capture_d_écran_2026-04-15_210724.png` — KaliAttacker running (CLEAN_BASELINE_KALI)
- `Capture_d_écran_2026-04-15_210738.png` — WindowsVictim running (CLEAN_BASELINE)