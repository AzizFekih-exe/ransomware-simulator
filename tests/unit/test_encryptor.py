"""
test_encryptor.py — Unit Tests for encryptor_poc.py
IT360 Project 14 | P1 — Malware Developer | Phase 1
"""

import os
import shutil
import tempfile
import unittest

from src.encryptor.encryptor_poc import (
    generate_key_iv,
    encrypt_file,
    secure_delete,
)

KNOWN_PLAINTEXT = b"This is test content for the IT360 encryptor unit tests."


class TestGenerateKeyIV(unittest.TestCase):
    """Tests for the generate_key_iv() function."""

    def test_key_is_32_bytes(self):
        """AES-256 key must be exactly 32 bytes."""
        key, _ = generate_key_iv()
        self.assertEqual(len(key), 32)

    def test_iv_is_16_bytes(self):
        """AES CBC IV must be exactly 16 bytes."""
        _, iv = generate_key_iv()
        self.assertEqual(len(iv), 16)

    def test_keys_are_unique_across_calls(self):
        """
        CSPRNG output must not repeat across calls.
        Running 10 iterations — probability of collision is negligible
        (1 / 2^256 per pair) but tests that random is actually called.
        """
        keys = {generate_key_iv()[0] for _ in range(10)}
        self.assertEqual(len(keys), 10, "Duplicate keys detected — RNG may be broken.")

    def test_return_type_is_tuple_of_bytes(self):
        """Return value must be a tuple of (bytes, bytes)."""
        result = generate_key_iv()
        self.assertIsInstance(result, tuple)
        self.assertIsInstance(result[0], bytes)
        self.assertIsInstance(result[1], bytes)


class TestEncryptFile(unittest.TestCase):
    """Tests for the encrypt_file() function."""

    def setUp(self):
        """Create a temporary directory with a dummy plaintext file."""
        self.test_dir = tempfile.mkdtemp()
        self.target_file = os.path.join(self.test_dir, "sample.txt")

        with open(self.target_file, "wb") as f:
            f.write(KNOWN_PLAINTEXT)

        self.key, self.iv = generate_key_iv()

    def tearDown(self):
        """Remove all test artifacts."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_locked_file_is_created(self):
        """A .locked file must exist after encryption."""
        locked = encrypt_file(self.target_file, self.key, self.iv)
        self.assertTrue(os.path.exists(locked))

    def test_locked_file_has_correct_extension(self):
        """Output filename must end with .locked."""
        locked = encrypt_file(self.target_file, self.key, self.iv)
        self.assertTrue(locked.endswith(".locked"))

    def test_locked_file_is_not_empty(self):
        """Encrypted output must be larger than zero bytes."""
        locked = encrypt_file(self.target_file, self.key, self.iv)
        self.assertGreater(os.path.getsize(locked), 0)

    def test_original_file_is_deleted(self):
        """Original plaintext file must not exist after encryption."""
        encrypt_file(self.target_file, self.key, self.iv)
        self.assertFalse(os.path.exists(self.target_file))

    def test_ciphertext_differs_from_plaintext(self):
        """Encrypted output must not equal the original plaintext."""
        locked = encrypt_file(self.target_file, self.key, self.iv)
        with open(locked, "rb") as f:
            ciphertext = f.read()
        self.assertNotEqual(ciphertext, KNOWN_PLAINTEXT)

    def test_iv_is_prepended_to_ciphertext(self):
        """First 16 bytes of .locked file must equal the IV used."""
        locked = encrypt_file(self.target_file, self.key, self.iv)
        with open(locked, "rb") as f:
            stored_iv = f.read(16)
        self.assertEqual(stored_iv, self.iv)


class TestSecureDelete(unittest.TestCase):
    """Tests for the secure_delete() function."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.dummy_file = os.path.join(self.test_dir, "to_delete.txt")
        with open(self.dummy_file, "wb") as f:
            f.write(b"sensitive content" * 100)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_file_is_removed(self):
        """File must not exist on disk after secure_delete()."""
        secure_delete(self.dummy_file)
        self.assertFalse(os.path.exists(self.dummy_file))


if __name__ == "__main__":
    unittest.main(verbosity=2)