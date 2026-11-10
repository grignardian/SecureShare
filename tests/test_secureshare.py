"""
test_secureshare.py - Simple Unit Tests for SecureShare
-------------------------------------------------------
Tests the core security and functional requirements:
1. Successful file encryption and decryption roundtrip.
2. File integrity verification (detecting tampered ciphertext via SHA-256).
3. Incorrect private key handling (rejecting unauthorized decryption).
4. Missing input file error handling.
5. Key generation and loading from keystore.
"""

import os
import sys
import unittest
import tempfile

# Add project root to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src import crypto, keystore


class TestSecureShare(unittest.TestCase):

    def setUp(self):
        """Create a temporary directory and test files before each test."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.sample_file = os.path.join(self.test_dir.name, "sample.txt")
        self.encrypted_file = os.path.join(self.test_dir.name, "sample.txt.secureshare")
        self.decrypted_file = os.path.join(self.test_dir.name, "sample_restored.txt")

        # Write test data
        self.original_content = b"SecureShare College PBL Evaluation Test Data: Confidential Content 12345."
        with open(self.sample_file, "wb") as f:
            f.write(self.original_content)

        # Generate test keypairs for Bob and Alice
        keystore.KEYS_DIR = os.path.join(self.test_dir.name, "keys")
        self.bob_priv, self.bob_pub = keystore.generate_keypair("bob")
        self.alice_priv, self.alice_pub = keystore.generate_keypair("alice")

    def tearDown(self):
        """Clean up temporary directory after each test."""
        self.test_dir.cleanup()

    def test_successful_encryption_and_decryption(self):
        """Test complete encryption and decryption flow."""
        # 1. Encrypt file for Bob
        result_enc = crypto.encrypt_file(self.sample_file, self.encrypted_file, self.bob_pub)
        self.assertTrue(os.path.exists(self.encrypted_file))
        self.assertGreater(result_enc["encrypted_size"], 0)

        # Encrypted file content must differ from plaintext
        with open(self.encrypted_file, "rb") as f:
            enc_data = f.read()
        self.assertNotEqual(enc_data, self.original_content)

        # 2. Decrypt file using Bob's private key
        result_dec = crypto.decrypt_file(self.encrypted_file, self.decrypted_file, self.bob_priv)
        self.assertTrue(os.path.exists(self.decrypted_file))

        # 3. Verify content matches original exactly
        with open(self.decrypted_file, "rb") as f:
            restored_data = f.read()
        self.assertEqual(restored_data, self.original_content)
        self.assertEqual(result_dec["sha256"], result_enc["sha256"])

    def test_incorrect_private_key_fails(self):
        """Test that decrypting with the wrong private key raises DecryptionError."""
        # Encrypt for Bob
        crypto.encrypt_file(self.sample_file, self.encrypted_file, self.bob_pub)

        # Attempt to decrypt using Alice's private key
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt_file(self.encrypted_file, self.decrypted_file, self.alice_priv)

    def test_tampered_file_detected(self):
        """Test that modifying even a single byte in ciphertext triggers IntegrityError."""
        crypto.encrypt_file(self.sample_file, self.encrypted_file, self.bob_pub)

        # Read encrypted bundle and flip a byte near the end (in the ciphertext)
        with open(self.encrypted_file, "rb") as f:
            bundle_bytes = bytearray(f.read())

        bundle_bytes[-5] ^= 0xFF  # Corrupt a byte in ciphertext

        with open(self.encrypted_file, "wb") as f:
            f.write(bundle_bytes)

        # Decryption must detect tampering and raise IntegrityError
        with self.assertRaises(crypto.IntegrityError):
            crypto.decrypt_file(self.encrypted_file, self.decrypted_file, self.bob_priv)

    def test_missing_input_file(self):
        """Test that encrypting or decrypting a non-existent file raises FileNotFoundError."""
        non_existent = os.path.join(self.test_dir.name, "does_not_exist.txt")

        with self.assertRaises(FileNotFoundError):
            crypto.encrypt_file(non_existent, self.encrypted_file, self.bob_pub)

        with self.assertRaises(FileNotFoundError):
            crypto.decrypt_file(non_existent, self.decrypted_file, self.bob_priv)

    def test_key_generation_and_loading(self):
        """Test generating and loading RSA keys."""
        priv_pem, pub_pem = keystore.generate_keypair("student")
        self.assertIn("BEGIN PRIVATE KEY", priv_pem)
        self.assertIn("BEGIN PUBLIC KEY", pub_pem)

        loaded_pub = keystore.load_public_key("student")
        loaded_priv = keystore.load_private_key("student")

        self.assertEqual(pub_pem, loaded_pub)
        self.assertEqual(priv_pem, loaded_priv)

        keys = keystore.list_available_keys()
        self.assertIn("student", keys)
        self.assertIn("bob", keys)
        self.assertIn("alice", keys)


if __name__ == "__main__":
    unittest.main()
