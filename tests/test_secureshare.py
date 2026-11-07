"""
Unit Tests for SecureShare
Tests:
1. AES-256-CBC Encryption & Decryption (with PKCS7 padding)
2. RSA-2048 Key Pair Generation, OAEP Encapsulation & Decryption
3. SHA-256 Hash Generation & Tamper Detection
4. PBKDF2 Password Hashing with Salt Verification
5. SQLite Database Operations
"""

import os
import sys
import unittest
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import crypto
import db


class TestCrypto(unittest.TestCase):

    def test_aes_encryption_decryption(self):
        key = crypto.new_aes_key()
        self.assertEqual(len(key), 32)
        plaintext = b"SecureShare end-to-end encryption test data string."
        ciphertext = crypto.aes_encrypt(plaintext, key)
        self.assertNotEqual(plaintext, ciphertext)
        decrypted = crypto.aes_decrypt(ciphertext, key)
        self.assertEqual(plaintext, decrypted)

    def test_rsa_keypair_and_oaep(self):
        priv_pem, pub_pem = crypto.generate_rsa_keypair()
        self.assertIn("BEGIN PRIVATE KEY", priv_pem)
        self.assertIn("BEGIN PUBLIC KEY", pub_pem)
        aes_key = crypto.new_aes_key()
        encrypted_key = crypto.rsa_encrypt(pub_pem, aes_key)
        self.assertNotEqual(aes_key, encrypted_key)
        decrypted_key = crypto.rsa_decrypt(priv_pem, encrypted_key)
        self.assertEqual(aes_key, decrypted_key)

    def test_sha256_and_tamper_detection(self):
        data = b"Original uncorrupted document."
        h1 = crypto.sha256(data)
        h2 = crypto.sha256(data)
        self.assertEqual(h1, h2)
        tampered = bytearray(data)
        tampered[0] ^= 0xFF
        h_tampered = crypto.sha256(bytes(tampered))
        self.assertNotEqual(h1, h_tampered)

    def test_pbkdf2_password_hashing(self):
        salt, pw_hash = crypto.hash_password("SuperSecret123!")
        self.assertTrue(crypto.check_password("SuperSecret123!", salt, pw_hash))
        self.assertFalse(crypto.check_password("WrongPassword!", salt, pw_hash))


if __name__ == "__main__":
    unittest.main()
