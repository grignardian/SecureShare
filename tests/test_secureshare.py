"""
Unit Tests for SecureShare
Tests:
1. AES-256-CBC Encryption & Decryption (with PKCS7 padding)
2. RSA-2048 Key Pair Generation, OAEP Encapsulation & Decryption
3. SHA-256 Hash Generation & Tamper Detection
4. PBKDF2 Password Hashing with Salt Verification
5. Portable .secureshare Bundle (Encrypt, Inspect, Decrypt, WrongKeyError, TamperDetectedError)
6. Fixed Cross-Device Profiles & Local Keystore Management
"""

import os
import sys
import json
import struct
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import crypto
import keystore


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
        self.assertTrue(crypto.validate_public_key(pub_pem))
        self.assertTrue(crypto.validate_private_key(priv_pem))
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

    def test_portable_bundle_roundtrip_and_security(self):
        bob_priv, bob_pub     = crypto.generate_rsa_keypair()
        alice_priv, _         = crypto.generate_rsa_keypair()
        payload = b"Portable cross-device encrypted file payload!" * 5

        bundle, info = crypto.encrypt_file_bundle(
            plaintext=payload,
            filename="../../evil/path/report.pdf",
            recipient_pub_pem=bob_pub,
            recipient_name="bob",
            sender_name="alice",
        )
        # Path traversal sanitization check
        self.assertEqual(info["filename"], "report.pdf")

        header, ct = crypto.inspect_file_bundle(bundle)
        self.assertEqual(header["filename"], "report.pdf")
        self.assertEqual(header["recipient"], "bob")
        self.assertGreater(len(ct), len(payload))

        # Wrong key must fail with WrongKeyError
        with self.assertRaises(crypto.WrongKeyError):
            crypto.decrypt_file_bundle(bundle, alice_priv)

        # Valid key succeeds and verifies hash
        dec_hdr, decrypted, got_sha = crypto.decrypt_file_bundle(bundle, bob_priv)
        self.assertEqual(decrypted, payload)
        self.assertEqual(got_sha, info["sha256"])
        self.assertEqual(dec_hdr["filename"], "report.pdf")

        # 1-byte tamper inside ciphertext triggers TamperDetectedError
        tampered = bytearray(bundle)
        tampered[info["header_offset"] + 18] ^= 0xFF
        with self.assertRaises(crypto.TamperDetectedError):
            crypto.decrypt_file_bundle(bytes(tampered), bob_priv)

        # Invalid magic signature raises InvalidBundleError
        with self.assertRaises(crypto.InvalidBundleError):
            crypto.inspect_file_bundle(b"NOT_A_VALID_BUNDLE")


class TestKeystore(unittest.TestCase):

    def test_fixed_profiles_cross_device_bundle(self):
        keystore.ensure_fixed_profiles()
        ok_bob, _   = keystore.authenticate("bob", "Bob123!")
        ok_alice, _ = keystore.authenticate("alice", "Alice123!")
        self.assertTrue(ok_bob)
        self.assertTrue(ok_alice)

        ok_bad, _ = keystore.authenticate("bob", "WrongPass")
        self.assertFalse(ok_bad)

        bob_pub   = keystore.get_public_key("bob")
        bob_priv  = keystore.get_private_key("bob")
        alice_priv = keystore.get_private_key("alice")

        data = b"Cross-device file encrypted by Alice for Bob."
        bundle, _ = crypto.encrypt_file_bundle(data, "memo.txt", bob_pub, "bob", "alice")

        with self.assertRaises(crypto.WrongKeyError):
            crypto.decrypt_file_bundle(bundle, alice_priv)

        _, plain, _ = crypto.decrypt_file_bundle(bundle, bob_priv)
        self.assertEqual(plain, data)

    def test_local_user_and_contact_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            orig_local = keystore.LOCAL_DIR
            orig_contacts = keystore.CONTACTS_DIR
            orig_lfile = keystore.LOCAL_PROFILES_FILE
            try:
                keystore.LOCAL_DIR = tmp
                keystore.CONTACTS_DIR = os.path.join(tmp, "contacts")
                keystore.LOCAL_PROFILES_FILE = os.path.join(tmp, "profiles.json")
                os.makedirs(keystore.CONTACTS_DIR, exist_ok=True)

                ok, _ = keystore.register_user("charlie_test", "Charlie123!")
                self.assertTrue(ok)
                auth_ok, _ = keystore.authenticate("charlie_test", "Charlie123!")
                self.assertTrue(auth_ok)

                _, ext_pub = crypto.generate_rsa_keypair()
                imp_ok, _ = keystore.import_contact("david_ext", ext_pub)
                self.assertTrue(imp_ok)
                self.assertEqual(keystore.get_public_key("david_ext").strip(), ext_pub.strip())
                self.assertTrue(keystore.delete_contact("david_ext"))
            finally:
                keystore.LOCAL_DIR = orig_local
                keystore.CONTACTS_DIR = orig_contacts
                keystore.LOCAL_PROFILES_FILE = orig_lfile


if __name__ == "__main__":
    unittest.main()
