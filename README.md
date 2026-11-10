# SecureShare — Offline File Encryption

SecureShare is a local Tkinter desktop app for encrypting a file for another person and decrypting a bundle received separately. It has no accounts, server, network connections, upload/download feature, or shared key directory. The app never transfers files; use your preferred method to exchange public keys and encrypted bundles.

## What it does

- Creates one local RSA-2048 key pair. The private key is encrypted on disk with a passphrase; the public key can be exported.
- Imports other people’s public keys into a local contact book under `keys/contacts.json`.
- Encrypts each selected file with a fresh AES-256 key and AES-GCM. RSA-OAEP with SHA-256 wraps that AES key for the chosen recipient.
- Authenticates the bundle metadata and encrypted content with AES-GCM. Decryption writes no output unless authentication succeeds.
- Saves a versioned `.secureshare` bundle. Decryption suggests the original filename, strips path components, and requires the user to choose an output location.

## Setup

Requirements: Python 3.8+, Tkinter, and the `cryptography` package.

```bash
python3 -m pip install -r requirements.txt
python3 src/app.py
```

On some Linux distributions, Tkinter must be installed separately (for example, `python3-tk`).

## First-time setup and exchanging keys

1. Open **My Keys** and generate a key pair. Choose a strong passphrase for the private key.
2. Export **your public key** and give it to people who may send files to you. Never share your private key.
3. Ask a recipient for their public key file and import it in **Contacts / Public Keys**.
4. Verify the displayed SHA-256 fingerprint with the key owner through a trusted channel before relying on that key. A local contact list cannot establish identity on its own.

Your private key is saved under `keys/my_private_key.pem` and the public key under `keys/my_public_key.pem`. Private key file permissions are restricted to the owner where the operating system supports that. Back up the private key securely: losing it means files encrypted for that key cannot be decrypted.

## Encrypt and decrypt

To encrypt, select a file, choose a contact, and click **Encrypt file**. Choose where to save the `.secureshare` bundle, then transfer that bundle yourself. The recipient needs the matching private key on their device.

To decrypt, select a `.secureshare` bundle, enter the passphrase that protects your private key, and choose where to save the restored file. Existing files are not replaced without a confirmation in the GUI. Wrong keys, malformed bundles, or changes to authenticated content or metadata cause decryption to fail.

## Bundle format

Version 2 bundles contain a magic signature, a length-prefixed JSON metadata header, a 12-byte AES-GCM nonce, and AES-GCM ciphertext with its authentication tag. Metadata includes a suggested filename, plaintext size and SHA-256 digest, format version, and the RSA-wrapped AES key. The exact serialized metadata is supplied to AES-GCM as associated authenticated data, so tampering with it is detected. Filename metadata is treated only as a suggestion; path components are removed and the user chooses the actual output path.

The current implementation loads files into memory and limits plaintext files to 50 MiB. RSA-2048 and AES-256-GCM are provided by `cryptography`; cryptographic primitives are not implemented by this project. The app does not sign files, so encryption alone does not prove who created a bundle. Anyone with a recipient’s public key can encrypt to them. Verify public-key fingerprints independently to reduce key-substitution risk.

## Tests

```bash
python3 -m unittest -v tests/test_secureshare.py
```

Tests use temporary directories for keys, contacts, sample files, and bundles.
