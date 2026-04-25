"""
test_encryptor_v2.py — Unit Tests for Phase 2 Encryptor + Decryptor
IT360 Project 14 | P1 — Malware Developer
"""

import os
import shutil
import tempfile
import unittest

from src.encryptor.encryptor import (
    generate_key_iv,
    discover_target_files,
    encrypt_file,
    build_manifest,
)
from src.encryptor.decryptor import (
    decrypt_file,
    verify_integrity,
)


class TestKeyGeneration(unittest.TestCase):

    def test_key_is_32_bytes(self):
        key, _ = generate_key_iv()
        self.assertEqual(len(key), 32)

    def test_iv_is_16_bytes(self):
        _, iv = generate_key_iv()
        self.assertEqual(len(iv), 16)

    def test_keys_are_unique(self):
        keys = {generate_key_iv()[0] for _ in range(10)}
        self.assertEqual(len(keys), 10)


class TestFileDiscovery(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        # Create target files
        for name in ["a.txt", "b.pdf", "c.jpg"]:
            open(os.path.join(self.test_dir, name), "w").close()
        # Create non-target files
        for name in ["program.exe", "lib.dll", "already.locked"]:
            open(os.path.join(self.test_dir, name), "w").close()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_discovers_target_extensions(self):
        targets = discover_target_files(self.test_dir)
        names = [os.path.basename(t) for t in targets]
        self.assertIn("a.txt", names)
        self.assertIn("b.pdf", names)
        self.assertIn("c.jpg", names)

    def test_excludes_blacklisted_extensions(self):
        targets = discover_target_files(self.test_dir)
        names = [os.path.basename(t) for t in targets]
        self.assertNotIn("program.exe", names)
        self.assertNotIn("lib.dll",     names)

    def test_excludes_already_locked(self):
        targets = discover_target_files(self.test_dir)
        names = [os.path.basename(t) for t in targets]
        self.assertNotIn("already.locked", names)


class TestEncryptDecryptRoundtrip(unittest.TestCase):

    def setUp(self):
        self.test_dir  = tempfile.mkdtemp()
        self.plaintext = b"IT360 roundtrip test content - must survive encrypt/decrypt."
        self.test_file = os.path.join(self.test_dir, "roundtrip.txt")

        with open(self.test_file, "wb") as f:
            f.write(self.plaintext)

        self.key, self.iv = generate_key_iv()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_encrypt_creates_locked_file(self):
        locked = encrypt_file(self.test_file, self.key, self.iv)
        self.assertTrue(os.path.exists(locked))

    def test_encrypt_removes_original(self):
        encrypt_file(self.test_file, self.key, self.iv)
        self.assertFalse(os.path.exists(self.test_file))

    def test_ciphertext_differs_from_plaintext(self):
        locked = encrypt_file(self.test_file, self.key, self.iv)
        with open(locked, "rb") as f:
            ciphertext = f.read()
        self.assertNotEqual(ciphertext, self.plaintext)

    def test_full_roundtrip_restores_plaintext(self):
        locked   = encrypt_file(self.test_file, self.key, self.iv)
        restored = decrypt_file(locked, self.key)
        with open(restored, "rb") as f:
            recovered = f.read()
        self.assertEqual(recovered, self.plaintext)

    def test_integrity_verification_passes_after_roundtrip(self):
        manifest = build_manifest([self.test_file])
        locked   = encrypt_file(self.test_file, self.key, self.iv)
        restored = decrypt_file(locked, self.key)
        # Remap key to restored path since original was deleted
        manifest[restored] = list(manifest.values())[0]
        result = verify_integrity(restored, manifest)
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)