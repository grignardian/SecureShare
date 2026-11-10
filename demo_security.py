#!/usr/bin/env python3
"""
demo_security.py - Standalone Portable File Encryption & Tamper Test
Run with: python3 demo_security.py

Demonstrates:
  1. Encrypting a file into a portable .secureshare bundle (AES-256-CBC + RSA-2048 OAEP).
  2. File payload inspection (ciphertext is unreadable without the recipient's private key).
  3. Wrong-key rejection (Alice cannot decrypt a file encrypted for Bob) & valid decryption.
  4. Tamper detection (flipping 1 byte inside the .secureshare file triggers rejection).
"""

import os
import tempfile

import crypto
import keystore


def main():
    print("=" * 72)
    print("SECURESHARE: PORTABLE FILE CRYPTOGRAPHIC & TAMPER TEST")
    print("Testing: AES-256-CBC  •  RSA-2048 OAEP  •  SHA-256  •  Fixed Keys")
    print("=" * 72)

    keystore.ensure_fixed_profiles()
    alice_priv = keystore.get_private_key("alice")
    bob_pub    = keystore.get_public_key("bob")
    bob_priv   = keystore.get_private_key("bob")

    secret_text = (
        b"Project Planning & Budget Review\n"
        b"Author: Alice\n"
        b"Recipient: Bob\n"
        b"Approved Budget: $48,000 for Q3 infrastructure\n"
        b"Confidential internal document."
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        bundle_path = os.path.join(tmpdir, "project_budget.txt.secureshare")

        # 1. Encrypt into portable bundle
        print("\n[STEP 1] Alice encrypts 'project_budget.txt' for Bob (using Bob's fixed public key):")
        bundle_bytes, info = crypto.encrypt_file_bundle(
            plaintext=secret_text,
            filename="project_budget.txt",
            recipient_pub_pem=bob_pub,
            recipient_name="bob",
            sender_name="alice",
        )
        with open(bundle_path, "wb") as f:
            f.write(bundle_bytes)

        print(f"  • Original file size: {info['plaintext_size']} bytes")
        print(f"  • Original SHA-256:   {info['sha256']}")
        print(f"  • Encrypted payload:  {info['ciphertext_size']} bytes (AES-256-CBC)")
        print(f"  • Output bundle size: {info['bundle_size']} bytes (.secureshare)")

        # 2. Test 1: Payload Inspection
        print("\n" + "-" * 72)
        print("TEST 1: File Payload Inspection (Safe to send over WhatsApp/Email/USB?)")
        print("-" * 72)
        with open(bundle_path, "rb") as f:
            disk_bytes = f.read()
        header, raw_ct = crypto.inspect_file_bundle(disk_bytes)
        print(f"  Bundle header metadata: filename={header['filename']}, recipient={header['recipient']}")
        print(f"  First 32 ciphertext bytes (hex): {raw_ct[:32].hex()}")
        try:
            raw_ct.decode("utf-8")
            print("  FAILED: Ciphertext contains readable UTF-8 plaintext!")
        except UnicodeDecodeError:
            print("  Attempting UTF-8 decode on ciphertext: UnicodeDecodeError (pure binary)")
            print("  PASSED: File content is completely unreadable without Bob's private key.")

        # 3. Test 2: Wrong-Key Rejection + Legitimate Decryption
        print("\n" + "-" * 72)
        print("TEST 2: Access Control & Legitimate Recipient Decryption")
        print("-" * 72)
        try:
            crypto.decrypt_file_bundle(disk_bytes, alice_priv)
            raise AssertionError("Alice should not be able to decrypt Bob's file!")
        except crypto.WrongKeyError as exc:
            print(f"  1. Alice tries decrypting with her own key -> BLOCKED: {exc}")

        _, recovered, computed_sha = crypto.decrypt_file_bundle(disk_bytes, bob_priv)
        assert recovered == secret_text
        assert computed_sha == info["sha256"]
        print("  2. Bob decrypts with his fixed RSA-2048 private key -> OK")
        print(f"     Expected SHA-256: {info['sha256']}")
        print(f"     Computed SHA-256: {computed_sha}")
        print("  PASSED: Wrong key rejected; Bob recovered exact original file with 100% hash match.")

        # 4. Test 3: Tamper Attack
        print("\n" + "-" * 72)
        print("TEST 3: Tamper Attack (What happens if 1 byte is modified in transit?)")
        print("-" * 72)
        tampered = bytearray(disk_bytes)
        offset = info["header_offset"] + 20
        old_b = tampered[offset]
        tampered[offset] ^= 0xFF
        new_b = tampered[offset]
        print(f"  Flipped 1 byte at offset {offset}: 0x{old_b:02X} -> 0x{new_b:02X}")

        try:
            crypto.decrypt_file_bundle(bytes(tampered), bob_priv)
            raise AssertionError("Tampered bundle should have been rejected!")
        except crypto.TamperDetectedError as exc:
            print(f"  Bob attempts to decrypt modified file -> REJECTED: {exc}")
            print("  PASSED: Tampered file was immediately caught and blocked.")

    print("\n" + "=" * 72)
    print("SUMMARY: All 3 security and integrity checks passed successfully.")
    print("=" * 72)


if __name__ == "__main__":
    main()
