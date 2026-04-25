"""
decryptor.py — Decryptor Module
IT360 Project 14: Ransomware Simulator (Academic Use Only)

Accepts the AES key returned by the C2 server after simulated payment.
Decrypts all .locked files and verifies integrity against the manifest.

Author : P1 — Malware Developer
Phase  : 2
"""

import os
import sys
import json
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from src.common.config import LOCKED_EXTENSION, TARGET_DIRECTORY


MANIFEST_PATH: str = ".manifest.enc"


# ---------------------------------------------------------------------------
# MANIFEST RECOVERY
# ---------------------------------------------------------------------------

def load_manifest(key: bytes) -> dict[str, str]:
    """
    Decrypt and load the SHA-256 file manifest.

    Reads the first 16 bytes of .manifest.enc as the IV, decrypts
    the remainder with the provided AES key, and parses the JSON.

    Args:
        key: 32-byte AES-256 session key received from C2.

    Returns:
        dict[str, str]: {original_filepath: expected_sha256_hex}
    """
    if not os.path.exists(MANIFEST_PATH):
        print("[WARN] No manifest file found — integrity check will be skipped.")
        return {}

    with open(MANIFEST_PATH, "rb") as f:
        raw: bytes = f.read()

    iv: bytes         = raw[:16]          # First 16 bytes = IV
    ciphertext: bytes = raw[16:]          # Remainder = encrypted manifest

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded_plaintext: bytes = dec.update(ciphertext) + dec.finalize()

    # Remove PKCS7 padding
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    manifest_bytes: bytes = unpadder.update(padded_plaintext) + unpadder.finalize()

    return json.loads(manifest_bytes.decode("utf-8"))


# ---------------------------------------------------------------------------
# DECRYPTION
# ---------------------------------------------------------------------------

def decrypt_file(locked_path: str, key: bytes) -> str:
    """
    Decrypt a single .locked file and restore the original filename.

    Reads the first 16 bytes as the IV (prepended during encryption),
    decrypts the remainder, removes PKCS7 padding, and writes the
    restored plaintext back to the original filename.

    Args:
        locked_path: Path to the .locked encrypted file.
        key        : 32-byte AES-256 session key.

    Returns:
        str: Path to the restored plaintext file, or "" on failure.
    """
    # Derive original path by stripping .locked extension
    original_path: str = locked_path[: -len(LOCKED_EXTENSION)]

    try:
        with open(locked_path, "rb") as f:
            raw: bytes = f.read()

        iv: bytes         = raw[:16]      # IV prepended during encryption
        ciphertext: bytes = raw[16:]      # Actual ciphertext

        # AES-256-CBC decryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext: bytes = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext: bytes = unpadder.update(padded_plaintext) + unpadder.finalize()

        # Write restored plaintext
        with open(original_path, "wb") as f:
            f.write(plaintext)

        # Remove the .locked file
        os.remove(locked_path)
        print(f"[+] Decrypted : {locked_path} → {os.path.basename(original_path)}")
        return original_path

    except (FileNotFoundError, PermissionError, ValueError) as e:
        print(f"[ERROR] Failed to decrypt {locked_path}: {e}")
        return ""


# ---------------------------------------------------------------------------
# INTEGRITY VERIFICATION
# ---------------------------------------------------------------------------

def verify_integrity(restored_path: str, manifest: dict[str, str]) -> bool:
    """
    Verify a restored file matches its pre-encryption SHA-256 hash.

    Computes SHA-256 of the restored file and compares it against
    the hash stored in the manifest. A mismatch indicates corruption
    during encryption or decryption.

    Args:
        restored_path: Path to the decrypted file.
        manifest     : {filepath: expected_sha256_hex} from load_manifest().

    Returns:
        bool: True if hashes match, False otherwise.
    """
    if restored_path not in manifest:
        print(f"[WARN] {restored_path} not in manifest — cannot verify.")
        return False

    with open(restored_path, "rb") as f:
        actual_hash: str = hashlib.sha256(f.read()).hexdigest()

    expected_hash: str = manifest[restored_path]

    if actual_hash == expected_hash:
        print(f"[✓] Integrity verified : {os.path.basename(restored_path)}")
        return True
    else:
        print(f"[✗] INTEGRITY MISMATCH: {os.path.basename(restored_path)}")
        print(f"    Expected : {expected_hash}")
        print(f"    Actual   : {actual_hash}")
        return False


# ---------------------------------------------------------------------------
# MAIN DECRYPTION ROUTINE
# ---------------------------------------------------------------------------

def run_decryption(target_dir: str, aes_key_hex: str) -> None:
    """
    Execute the full decryption routine over a target directory.

    Orchestration order:
      1. Convert hex AES key back to bytes.
      2. Load and decrypt the manifest.
      3. Discover all .locked files.
      4. Decrypt each file and restore original filename.
      5. Verify SHA-256 integrity for each restored file.
      6. Print summary report.

    Args:
        target_dir  : Directory containing .locked files.
        aes_key_hex : Hex string of AES-256 key received from C2.
    """
    print("\n[*] Converting AES key from hex...")
    try:
        key: bytes = bytes.fromhex(aes_key_hex)
    except ValueError:
        print("[ERROR] Invalid AES key hex string. Aborting.")
        sys.exit(1)

    print("[*] Loading encrypted manifest...")
    manifest: dict[str, str] = load_manifest(key)

    print(f"\n[*] Scanning {target_dir} for .locked files...")
    locked_files: list[str] = []
    for dirpath, _, filenames in os.walk(target_dir):
        for filename in filenames:
            if filename.endswith(LOCKED_EXTENSION):
                locked_files.append(os.path.join(dirpath, filename))

    print(f"[*] Found {len(locked_files)} encrypted file(s).\n")

    if not locked_files:
        print("[!] No .locked files found. Nothing to decrypt.")
        return

    verified: int = 0
    failed  : int = 0

    for locked_path in locked_files:
        restored = decrypt_file(locked_path, key)
        if restored:
            ok = verify_integrity(restored, manifest)
            if ok:
                verified += 1
            else:
                failed += 1
        else:
            failed += 1

    print(f"\n{'=' * 60}")
    print(f"[✓] Decryption complete.")
    print(f"[✓] Verified OK : {verified}")
    print(f"[✗] Failed      : {failed}")
    print(f"{'=' * 60}")


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  IT360 — Ransomware Simulator | Decryptor (P1)")
    print("  FOR ACADEMIC USE IN AIR-GAPPED VM ONLY")
    print("=" * 60)

    # In the full build, the key arrives from C2 via dropper.py.
    # For standalone testing, we accept it as a command-line argument.
    if len(sys.argv) < 2:
        print("\n[USAGE] python decryptor.py <aes_key_hex>")
        print("[USAGE] The key hex is printed by encryptor.py on run.")
        sys.exit(1)

    aes_key_hex: str = sys.argv[1]
    run_decryption(TARGET_DIRECTORY, aes_key_hex)