"""
test_phase3.py — Unit Tests for Phase 3 Components

"""

import os
import shutil
import tempfile
import unittest
import platform

from src.dropper.dropper import generate_victim_id, wrap_aes_key_with_rsa
from src.encryptor.ransom_note import generate_ransom_note, drop_notes_in_all_affected_dirs
from src.encryptor.encryptor import generate_key_iv


class TestVictimFingerprinting(unittest.TestCase):

    def test_victim_id_is_16_chars(self):
        """Victim ID must be exactly 16 hex characters."""
        vid = generate_victim_id()
        self.assertEqual(len(vid), 16)

    def test_victim_id_is_deterministic(self):
        """Same machine must always produce the same victim ID."""
        vid1 = generate_victim_id()
        vid2 = generate_victim_id()
        self.assertEqual(vid1, vid2)

    def test_victim_id_is_hex(self):
        """Victim ID must be a valid hex string."""
        vid = generate_victim_id()
        int(vid, 16)   # Raises ValueError if not valid hex


class TestRSAKeyWrapping(unittest.TestCase):

    def test_wrapped_key_is_256_bytes(self):
        """RSA-2048 wrapped output must be exactly 256 bytes."""
        key, _ = generate_key_iv()
        wrapped = wrap_aes_key_with_rsa(key.hex())
        self.assertEqual(len(wrapped), 256)

    def test_wrapped_key_differs_from_plaintext(self):
        """Wrapped key must not equal the original AES key bytes."""
        key, _ = generate_key_iv()
        wrapped = wrap_aes_key_with_rsa(key.hex())
        self.assertNotEqual(wrapped, key)

    def test_two_wrappings_of_same_key_differ(self):
        """
        RSA-OAEP uses random padding — two encryptions of the same
        plaintext must produce different ciphertexts.
        """
        key, _ = generate_key_iv()
        wrapped1 = wrap_aes_key_with_rsa(key.hex())
        wrapped2 = wrap_aes_key_with_rsa(key.hex())
        self.assertNotEqual(wrapped1, wrapped2)


class TestRansomNote(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_note_is_created(self):
        """Ransom note file must exist after generation."""
        generate_ransom_note(self.test_dir, "abc123", platform.node(), 5)
        self.assertTrue(
            os.path.exists(os.path.join(self.test_dir, "README_RESTORE.txt"))
        )

    def test_note_contains_victim_id(self):
        """Ransom note must contain the victim ID."""
        generate_ransom_note(self.test_dir, "deadbeef1234", platform.node(), 3)
        with open(os.path.join(self.test_dir, "README_RESTORE.txt")) as f:
            content = f.read()
        self.assertIn("deadbeef1234", content)

    def test_note_contains_academic_disclaimer(self):
        """Note must contain the academic simulation disclaimer."""
        generate_ransom_note(self.test_dir, "abc", platform.node(), 1)
        with open(os.path.join(self.test_dir, "README_RESTORE.txt")) as f:
            content = f.read()
        self.assertIn("ACADEMIC SIMULATION", content)

    def test_drop_in_multiple_dirs(self):
        """A note must be dropped in every unique affected directory."""
        dir_a = os.path.join(self.test_dir, "folder_a")
        dir_b = os.path.join(self.test_dir, "folder_b")
        os.makedirs(dir_a)
        os.makedirs(dir_b)

        fake_locked = [
            os.path.join(dir_a, "file1.txt.locked"),
            os.path.join(dir_b, "file2.txt.locked"),
        ]

        drop_notes_in_all_affected_dirs(fake_locked, "abc", platform.node(), 2)

        self.assertTrue(os.path.exists(os.path.join(dir_a, "README_RESTORE.txt")))
        self.assertTrue(os.path.exists(os.path.join(dir_b, "README_RESTORE.txt")))


if __name__ == "__main__":
    unittest.main(verbosity=2)