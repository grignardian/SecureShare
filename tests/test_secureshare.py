"""
test_secureshare.py - Unit and Integration Tests for SecureShare
-----------------------------------------------------------------
Tests all authentication, key management, cryptographic, database,
and TLS client-server file-sharing workflows using temporary directories.
"""

import os
import sys
import stat
import json
import struct
import threading
import tempfile
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src import auth, client, crypto, database, keystore, server


class TestSecureShareUnit(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test.db")
        self.keys_dir = os.path.join(self.temp_dir.name, "keys")
        database.init_db(self.db_path)

        # Create sample plaintext file
        self.sample_path = os.path.join(self.temp_dir.name, "secret_notes.txt")
        self.sample_data = b"Confidential SecureShare test file content for Python PBL."
        with open(self.sample_path, "wb") as f:
            f.write(self.sample_data)

        self.enc_path = os.path.join(self.temp_dir.name, "secret_notes.enc")
        self.dec_path = os.path.join(self.temp_dir.name, "secret_notes_restored.txt")

    def tearDown(self):
        self.temp_dir.cleanup()

    # --- 1 to 4: Authentication & SQLite Tests ---

    def test_user_registration_and_login(self):
        _, pub_pem = keystore.generate_rsa_keypair()
        ok, msg = auth.register_user("alice", "AlicePass123", pub_pem, db_path=self.db_path)
        self.assertTrue(ok, msg)

        login_ok, login_msg = auth.login_user("alice", "AlicePass123", db_path=self.db_path)
        self.assertTrue(login_ok, login_msg)

    def test_incorrect_password_rejected(self):
        _, pub_pem = keystore.generate_rsa_keypair()
        auth.register_user("bob", "CorrectPass!", pub_pem, db_path=self.db_path)

        ok, _ = auth.login_user("bob", "WrongPass!", db_path=self.db_path)
        self.assertFalse(ok)

    def test_duplicate_username_rejected(self):
        _, pub_pem = keystore.generate_rsa_keypair()
        ok1, _ = auth.register_user("alice", "Pass1234", pub_pem, db_path=self.db_path)
        ok2, _ = auth.register_user("alice", "OtherPass99", pub_pem, db_path=self.db_path)
        self.assertTrue(ok1)
        self.assertFalse(ok2)

    # --- 5 to 7: Keystore & Cryptographic Primitive Tests ---

    def test_rsa_key_generation_password_and_permissions(self):
        pub_pem = keystore.create_and_save_user_keys("alice", "KeyPass123", keys_dir=self.keys_dir)
        self.assertIn("BEGIN PUBLIC KEY", pub_pem)

        priv_path = keystore.get_private_key_path("alice", keys_dir=self.keys_dir)
        self.assertTrue(os.path.exists(priv_path))

        # Check private key file is encrypted on disk
        with open(priv_path, "rb") as f:
            raw_priv = f.read()
        self.assertIn(b"ENCRYPTED PRIVATE KEY", raw_priv)

        # Check owner-only permissions (0600) on POSIX systems
        if os.name == "posix":
            mode = stat.S_IMODE(os.stat(priv_path).st_mode)
            self.assertEqual(mode, 0o600)

        # Correct password unlocks key; wrong password raises ValueError
        unlocked = keystore.load_private_key("alice", "KeyPass123", keys_dir=self.keys_dir)
        self.assertIn("BEGIN PRIVATE KEY", unlocked)

        with self.assertRaises(ValueError):
            keystore.load_private_key("alice", "WrongPass", keys_dir=self.keys_dir)

        # Overwrite protection when overwrite=False
        with self.assertRaises(FileExistsError):
            keystore.create_and_save_user_keys("alice", "NewPass", keys_dir=self.keys_dir, overwrite=False)

    def test_aes_encryption_and_decryption(self):
        aes_key = crypto.generate_aes_key()
        iv_and_ct = crypto.encrypt_aes(self.sample_data, aes_key)
        self.assertNotEqual(iv_and_ct, self.sample_data)

        restored = crypto.decrypt_aes(iv_and_ct, aes_key)
        self.assertEqual(restored, self.sample_data)

    def test_rsa_key_wrapping_and_unwrapping(self):
        priv_obj, pub_pem = keystore.generate_rsa_keypair()
        priv_path = keystore.save_private_key("bob", priv_obj, "BobPass1", keys_dir=self.keys_dir)
        self.assertTrue(os.path.exists(priv_path))
        priv_pem = keystore.load_private_key("bob", "BobPass1", keys_dir=self.keys_dir)

        session_keys = crypto.generate_aes_key() + crypto.generate_hmac_key()
        wrapped = crypto.encrypt_rsa(pub_pem, session_keys)
        self.assertNotEqual(wrapped, session_keys)

        unwrapped = crypto.decrypt_rsa(priv_pem, wrapped)
        self.assertEqual(unwrapped, session_keys)

    # --- 11 to 15: File Encryption, Integrity, Tamper & Error Tests ---

    def test_file_encrypt_decrypt_and_sha256_verification(self):
        bob_pub = keystore.create_and_save_user_keys("bob", "BobPass1", keys_dir=self.keys_dir)
        bob_priv = keystore.load_private_key("bob", "BobPass1", keys_dir=self.keys_dir)

        enc_info = crypto.encrypt_file(
            self.sample_path, self.enc_path, bob_pub,
            sender_name="alice", recipient_name="bob"
        )
        self.assertTrue(os.path.exists(self.enc_path))
        self.assertEqual(enc_info["sha256"], crypto.compute_sha256(self.sample_data))

        dec_info = crypto.decrypt_file(self.enc_path, self.dec_path, bob_priv)
        with open(self.dec_path, "rb") as f:
            restored = f.read()
        self.assertEqual(restored, self.sample_data)
        self.assertEqual(dec_info["sha256"], enc_info["sha256"])

    def test_modified_ciphertext_detected_by_hmac(self):
        bob_pub = keystore.create_and_save_user_keys("bob", "BobPass1", keys_dir=self.keys_dir)
        bob_priv = keystore.load_private_key("bob", "BobPass1", keys_dir=self.keys_dir)

        crypto.encrypt_file(self.sample_path, self.enc_path, bob_pub)

        # Flip 1 byte in the ciphertext near the end of the file
        with open(self.enc_path, "rb") as f:
            data = bytearray(f.read())
        data[-3] ^= 0xFF
        with open(self.enc_path, "wb") as f:
            f.write(data)

        with self.assertRaisesRegex(ValueError, "HMAC verification failed"):
            crypto.decrypt_file(self.enc_path, self.dec_path, bob_priv)

    def test_modified_metadata_detected_by_hmac(self):
        bob_pub = keystore.create_and_save_user_keys("bob", "BobPass1", keys_dir=self.keys_dir)
        bob_priv = keystore.load_private_key("bob", "BobPass1", keys_dir=self.keys_dir)

        crypto.encrypt_file(
            self.sample_path, self.enc_path, bob_pub,
            sender_name="alice", recipient_name="bob"
        )

        # Parse and alter metadata header JSON (e.g. change filename & sha256)
        with open(self.enc_path, "rb") as f:
            data = f.read()

        magic_len = len(crypto.FILE_MAGIC)
        header_len = struct.unpack(">I", data[magic_len:magic_len + 4])[0]
        header_bytes = data[magic_len + 4:magic_len + 4 + header_len]
        rest_of_file = data[magic_len + 4 + header_len:]

        metadata = json.loads(header_bytes.decode("utf-8"))
        metadata["filename"] = "evil_modified_name.exe"
        tampered_header = json.dumps(metadata, separators=(",", ":")).encode("utf-8")

        tampered_bundle = (
            crypto.FILE_MAGIC +
            struct.pack(">I", len(tampered_header)) +
            tampered_header +
            rest_of_file
        )
        with open(self.enc_path, "wb") as f:
            f.write(tampered_bundle)

        with self.assertRaisesRegex(ValueError, "HMAC verification failed"):
            crypto.decrypt_file(self.enc_path, self.dec_path, bob_priv)

    def test_incorrect_private_key_rejected(self):
        bob_pub = keystore.create_and_save_user_keys("bob", "BobPass1", keys_dir=self.keys_dir)
        keystore.create_and_save_user_keys("alice", "AlicePass1", keys_dir=self.keys_dir)
        alice_priv = keystore.load_private_key("alice", "AlicePass1", keys_dir=self.keys_dir)

        crypto.encrypt_file(self.sample_path, self.enc_path, bob_pub)

        with self.assertRaisesRegex(ValueError, "Incorrect private key"):
            crypto.decrypt_file(self.enc_path, self.dec_path, alice_priv)

    def test_missing_file_and_corrupted_file_handling(self):
        bob_pub = keystore.create_and_save_user_keys("bob", "BobPass1", keys_dir=self.keys_dir)
        bob_priv = keystore.load_private_key("bob", "BobPass1", keys_dir=self.keys_dir)

        missing_path = os.path.join(self.temp_dir.name, "missing_file.txt")
        with self.assertRaises(FileNotFoundError):
            crypto.encrypt_file(missing_path, self.enc_path, bob_pub)
        with self.assertRaises(FileNotFoundError):
            crypto.decrypt_file(missing_path, self.dec_path, bob_priv)

        # Corrupted / invalid file format
        corrupt_path = os.path.join(self.temp_dir.name, "corrupt.enc")
        with open(corrupt_path, "wb") as f:
            f.write(b"NOT_A_VALID_SECURESHARE_FILE")

        with self.assertRaises(ValueError):
            crypto.decrypt_file(corrupt_path, self.dec_path, bob_priv)

    def test_file_overwrite_protection(self):
        bob_pub = keystore.create_and_save_user_keys("bob", "BobPass1", keys_dir=self.keys_dir)

        # Prevent overwriting input file itself
        with self.assertRaises(ValueError):
            crypto.encrypt_file(self.sample_path, self.sample_path, bob_pub)

        crypto.encrypt_file(self.sample_path, self.enc_path, bob_pub)
        # Prevent overwriting existing output file unless overwrite=True
        with self.assertRaises(FileExistsError):
            crypto.encrypt_file(self.sample_path, self.enc_path, bob_pub, overwrite=False)


class TestSecureShareIntegration(unittest.TestCase):
    """Full end-to-end client-server TLS test over localhost."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "server.db")
        self.files_dir = os.path.join(self.temp_dir.name, "server_files")
        self.cert_path = os.path.join(self.temp_dir.name, "server.crt")
        self.key_path = os.path.join(self.temp_dir.name, "server.key")

        self.alice_keys = os.path.join(self.temp_dir.name, "alice_keys")
        self.bob_keys = os.path.join(self.temp_dir.name, "bob_keys")
        self.charlie_keys = os.path.join(self.temp_dir.name, "charlie_keys")

        self.stop_flag = {"stop": False}
        self.port_holder = {"port": None}
        self.ready_event = threading.Event()

        def on_ready(assigned_port):
            self.port_holder["port"] = assigned_port
            self.ready_event.set()

        self.server_thread = threading.Thread(
            target=server.run_server,
            kwargs={
                "host": "127.0.0.1",
                "port": 0,
                "cert_path": self.cert_path,
                "key_path": self.key_path,
                "db_path": self.db_path,
                "files_dir": self.files_dir,
                "ready_callback": on_ready,
                "stop_flag": self.stop_flag
            },
            daemon=True
        )
        self.server_thread.start()
        self.assertTrue(self.ready_event.wait(timeout=5), "Test server failed to start.")
        self.port = self.port_holder["port"]

    def tearDown(self):
        self.stop_flag["stop"] = True
        self.server_thread.join(timeout=3)
        self.temp_dir.cleanup()

    def test_alice_to_bob_end_to_end_and_unauthorized_download(self):
        # 1. Ping server over TLS
        pong = client.ping_server("127.0.0.1", self.port, cert_path=self.cert_path)
        self.assertIn("SecureShare", pong)

        # 2. Register Alice, Bob, and Charlie
        alice_pub = keystore.create_and_save_user_keys("alice", "AlicePass", keys_dir=self.alice_keys)
        bob_pub = keystore.create_and_save_user_keys("bob", "BobPass", keys_dir=self.bob_keys)
        charlie_pub = keystore.create_and_save_user_keys("charlie", "CharliePass", keys_dir=self.charlie_keys)

        ok_a, _ = client.register("127.0.0.1", self.port, "alice", "AlicePass", alice_pub, cert_path=self.cert_path)
        ok_b, _ = client.register("127.0.0.1", self.port, "bob", "BobPass", bob_pub, cert_path=self.cert_path)
        ok_c, _ = client.register("127.0.0.1", self.port, "charlie", "CharliePass", charlie_pub, cert_path=self.cert_path)
        self.assertTrue(ok_a and ok_b and ok_c)

        # 3. Alice logs in and prepares a document
        ok_login_a, token_a, _ = client.login("127.0.0.1", self.port, "alice", "AlicePass", cert_path=self.cert_path)
        self.assertTrue(ok_login_a)

        orig_file = os.path.join(self.temp_dir.name, "project_report.txt")
        orig_content = b"End-to-end encrypted file sent from Alice to Bob over TLS!" * 50
        with open(orig_file, "wb") as f:
            f.write(orig_content)

        # 4. Alice fetches Bob's public key, encrypts locally, and uploads over TLS
        fetched_bob_pub = client.get_public_key("127.0.0.1", self.port, token_a, "bob", cert_path=self.cert_path)
        self.assertEqual(fetched_bob_pub, bob_pub)

        alice_enc_file = os.path.join(self.temp_dir.name, "alice_upload.secureshare")
        enc_info = crypto.encrypt_file(orig_file, alice_enc_file, fetched_bob_pub, sender_name="alice", recipient_name="bob")

        upload_resp = client.upload_encrypted_file(
            "127.0.0.1", self.port, token_a, "bob",
            enc_info["filename"], enc_info["file_size"], enc_info["sha256"],
            alice_enc_file, cert_path=self.cert_path
        )
        file_id = upload_resp["file_id"]

        # 5. Unauthorized user (Charlie) attempts to download Bob's file -> must fail
        ok_login_c, token_c, _ = client.login("127.0.0.1", self.port, "charlie", "CharliePass", cert_path=self.cert_path)
        self.assertTrue(ok_login_c)
        charlie_dl_path = os.path.join(self.temp_dir.name, "charlie_stolen.enc")
        with self.assertRaises(PermissionError):
            client.download_encrypted_file(
                "127.0.0.1", self.port, token_c, file_id, charlie_dl_path, cert_path=self.cert_path
            )

        # 6. Bob logs in, sees the received file, downloads and decrypts it locally
        ok_login_b, token_b, _ = client.login("127.0.0.1", self.port, "bob", "BobPass", cert_path=self.cert_path)
        self.assertTrue(ok_login_b)

        received_list = client.list_received_files("127.0.0.1", self.port, token_b, cert_path=self.cert_path)
        self.assertEqual(len(received_list), 1)
        self.assertEqual(received_list[0]["original_filename"], "project_report.txt")
        self.assertEqual(received_list[0]["sender"], "alice")

        bob_dl_enc = os.path.join(self.temp_dir.name, "bob_downloaded.secureshare")
        client.download_encrypted_file("127.0.0.1", self.port, token_b, file_id, bob_dl_enc, cert_path=self.cert_path)

        bob_priv_pem = keystore.load_private_key("bob", "BobPass", keys_dir=self.bob_keys)
        bob_restored_file = os.path.join(self.temp_dir.name, "bob_restored.txt")
        dec_info = crypto.decrypt_file(bob_dl_enc, bob_restored_file, bob_priv_pem)

        with open(bob_restored_file, "rb") as f:
            restored_bytes = f.read()
        self.assertEqual(restored_bytes, orig_content)
        self.assertEqual(dec_info["sha256"], enc_info["sha256"])

        # 7. Verify file history for both Alice and Bob
        alice_hist = client.list_file_history("127.0.0.1", self.port, token_a, cert_path=self.cert_path)
        bob_hist = client.list_file_history("127.0.0.1", self.port, token_b, cert_path=self.cert_path)
        self.assertEqual(len(alice_hist), 1)
        self.assertEqual(len(bob_hist), 1)
        self.assertEqual(alice_hist[0]["receiver"], "bob")
        self.assertEqual(bob_hist[0]["sender"], "alice")


if __name__ == "__main__":
    unittest.main()
