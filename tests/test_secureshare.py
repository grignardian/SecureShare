"""Offline key management and encrypted bundle tests."""
import os
import stat
import sys
import tempfile
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src import crypto, keystore


class OfflineSecureShareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.keys = os.path.join(self.temp.name, "keys")
        self.plain = os.path.join(self.temp.name, "message.txt")
        self.bundle = os.path.join(self.temp.name, "message.secureshare")
        self.output = os.path.join(self.temp.name, "restored.txt")
        self.payload = b"offline secret\x00" * 128
        with open(self.plain, "wb") as stream:
            stream.write(self.payload)
        self.private, self.public = keystore.generate_rsa_keypair()

    def tearDown(self):
        self.temp.cleanup()

    def test_key_generation_storage_unlock_and_permissions(self):
        keystore.save_private_key(self.private, "correct horse battery", self.keys)
        keystore.save_public_key(self.public, self.keys)
        self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", open(keystore.get_private_key_path(self.keys), "r").read())
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(keystore.get_private_key_path(self.keys)).st_mode), 0o600)
        loaded = keystore.load_private_key("correct horse battery", self.keys)
        self.assertEqual(loaded.public_key().public_numbers(), self.private.public_key().public_numbers())
        with self.assertRaises(ValueError):
            keystore.load_private_key("wrong", self.keys)

    def test_local_contact_import_and_duplicate_rejection(self):
        pub_path = os.path.join(self.temp.name, "friend.pem")
        with open(pub_path, "w") as stream:
            stream.write(self.public)
        contact = keystore.import_contact_from_file("Friend", pub_path, self.keys)
        self.assertEqual(contact["fingerprint"], keystore.compute_fingerprint(self.public))
        with self.assertRaises(ValueError):
            keystore.import_contact_from_file("Other name", pub_path, self.keys)
        with self.assertRaises(ValueError):
            keystore.add_contact("Friend", self.public, self.keys)

    def test_encrypt_decrypt_round_trip(self):
        info = crypto.encrypt_file(self.plain, self.bundle, self.public)
        restored = crypto.decrypt_file(self.bundle, self.output, self.private)
        with open(self.output, "rb") as stream:
            self.assertEqual(stream.read(), self.payload)
        self.assertEqual(info["sha256"], restored["sha256"])

    def test_wrong_private_key_rejected_without_output(self):
        other_private, _ = keystore.generate_rsa_keypair()
        crypto.encrypt_file(self.plain, self.bundle, self.public)
        with self.assertRaises(ValueError):
            crypto.decrypt_file(self.bundle, self.output, other_private)
        self.assertFalse(os.path.exists(self.output))

    def test_ciphertext_tampering_detected_without_output(self):
        crypto.encrypt_file(self.plain, self.bundle, self.public)
        with open(self.bundle, "rb") as stream:
            data = bytearray(stream.read())
        data[-1] ^= 1
        with open(self.bundle, "wb") as stream:
            stream.write(data)
        with self.assertRaisesRegex(ValueError, "authentication"):
            crypto.decrypt_file(self.bundle, self.output, self.private)
        self.assertFalse(os.path.exists(self.output))

    def test_metadata_tampering_detected(self):
        crypto.encrypt_file(self.plain, self.bundle, self.public)
        with open(self.bundle, "rb") as stream:
            data = bytearray(stream.read())
        marker = b"message.txt"
        offset = data.index(marker)
        data[offset] ^= 1
        with open(self.bundle, "wb") as stream:
            stream.write(data)
        with self.assertRaises(ValueError):
            crypto.decrypt_file(self.bundle, self.output, self.private)
        self.assertFalse(os.path.exists(self.output))

    def test_malformed_bundle_rejected(self):
        with open(self.bundle, "wb") as stream:
            stream.write(b"not a SecureShare bundle")
        with self.assertRaises(ValueError):
            crypto.decrypt_file(self.bundle, self.output, self.private)
        self.assertFalse(os.path.exists(self.output))

    def test_output_overwrite_is_not_silent(self):
        crypto.encrypt_file(self.plain, self.bundle, self.public)
        with open(self.output, "wb") as stream:
            stream.write(b"keep this")
        with self.assertRaises(FileExistsError):
            crypto.decrypt_file(self.bundle, self.output, self.private)
        with open(self.output, "rb") as stream:
            self.assertEqual(stream.read(), b"keep this")

    def test_output_cannot_replace_input(self):
        with self.assertRaises(ValueError):
            crypto.encrypt_file(self.plain, self.plain, self.public)


if __name__ == "__main__":
    unittest.main()
