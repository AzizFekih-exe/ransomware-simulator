"""
config.py — Shared configuration constants for the Ransomware Simulator.
IT360 Project 14 | P3: Systems Architect manages this file.

All team members import from here. No hardcoded values in individual modules.
"""

# -------------------------------------------------------------------
# C2 SERVER SETTINGS (P2 owns these)
# -------------------------------------------------------------------
C2_HOST: str = "192.168.56.101"   # KaliAttacker VM IP (Host-Only network)
C2_PORT: int = 5000
C2_REGISTER_ENDPOINT: str = f"https://{C2_HOST}:{C2_PORT}/register"
C2_GETKEY_ENDPOINT: str   = f"https://{C2_HOST}:{C2_PORT}/getkey"

# Admin token — protects the /release and /status endpoints on the C2 server.
# Only the C2 operator (P2) uses this. Never sent to the victim.
ADMIN_TOKEN: str = "oussama_zmitri_123"  # nosec — no real credential value

# -------------------------------------------------------------------
# ENCRYPTION SETTINGS (P1 owns these)
# -------------------------------------------------------------------
TARGET_EXTENSIONS: tuple[str, ...] = (
    ".txt", ".docx", ".pdf",
    ".jpg", ".png", ".xlsx"
)

LOCKED_EXTENSION: str = ".locked"

# Extensions the encryptor must NEVER touch — avoids breaking the OS.
# Real ransomware families like LockBit implement this same whitelist
# to ensure the victim machine stays bootable (they still need to pay).
EXTENSION_BLACKLIST: tuple[str, ...] = (
    ".exe", ".dll", ".sys", ".ini",
    ".bat", ".ps1", ".lnk", ".locked"
)

# Target directory — scoped to test_files/ for safe academic testing.
TARGET_DIRECTORY: str = "test_files"

# -------------------------------------------------------------------
# KILL-SWITCH (P1 owns this)
# -------------------------------------------------------------------
KILL_SWITCH_FILENAME: str = "DO_NOT_RUN.flag"

# -------------------------------------------------------------------
# RSA PUBLIC KEY (P2 generated this keypair — private key lives on
# the C2 server only and is never committed to this repo)
# -------------------------------------------------------------------
RSA_PUBLIC_KEY_PEM: str = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnTsUetqTRYlMiH5+JfIS
q4dBmcj2sm9qfHRq7A0EEvfWCqPD8uHmHJIo2Fgw2pNt4hAoqogp1qiyK0TLD7oy
alAsE/nzGfpZL1iwS+xtvdT+OOhCQvpBTO+XdhaMYQVVhMPaMTWoItA2vKuqR7ud
8kHjTQBBTpACxEFtgzOFpcLYoAbQG1jz+8hopZVMkf3C+iaK4km/xqHwMFgIky0G
MlGfSvuH++n7z+0fypdEhPi9z5Qs1QVJi/0OrahU+td5EqfdE1KQgHzxyQ2CXkwo
VwQJO47MFH8gYdc1lzPhayyQPUetHrcdq713WVTmjlZ+QmVFF7ufHSEwPrCsgKlJ
XQIDAQAB
-----END PUBLIC KEY-----
"""