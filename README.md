# SecureShare

**Keep files private. Share them your way.**

SecureShare is a small desktop app for encrypting files before you pass them to someone. It runs locally on your computer: there are no accounts, servers, or file uploads.

## How it works

When you encrypt a file, SecureShare creates a random AES key and encrypts the file with it. It then locks that AES key with the recipient’s public key. Only the matching private key can unlock the file.

The encrypted output is a `.secureshare` bundle. You can send that bundle using email, a USB drive, or another service. SecureShare itself does not transfer it.

## Get started

You’ll need Python 3.8 or later, Tkinter, and the `cryptography` package.

```bash
python3 -m pip install -r requirements.txt
python3 src/app.py
```

On some Linux systems, install Tkinter separately (often packaged as `python3-tk`).

## Set up your keys

1. Open **My Keys** and choose **Create key pair**.
2. Set a passphrase to protect your private key.
3. Choose **Export public key** and share that file with people who will send you encrypted files.
4. Ask your recipient for their public-key file. In **Contacts**, choose **Import public key** and give it a name you’ll recognize.

Your keys and contacts stay in the local `keys/` folder:

- `my_private_key.pem` — your passphrase-protected private key. Keep it private and make a secure backup.
- `my_public_key.pem` — your public key, which you can share.
- `contacts.json` — names and public keys you import.

The private key is saved with owner-only file permissions where supported. If you lose it, files encrypted for that key cannot be recovered. SecureShare won’t silently replace an existing key pair.

## Encrypt a file

1. Open **Encrypt** and browse to the file.
2. Choose a recipient from your contacts.
3. Choose where to save the `.secureshare` bundle.
4. Share the bundle with the recipient using a method outside SecureShare.

## Decrypt a file

1. Open **Decrypt** and choose the `.secureshare` bundle.
2. Enter the passphrase for your private key.
3. Choose where to save the restored file.

SecureShare checks the encrypted content before saving. If the bundle is damaged, changed, or made for a different key, decryption fails. Existing output files require confirmation before replacement.

## History

The **History** tab lists successful encryptions and decryptions, including the time, action, file name, contact (for encryption), file size, and saved-to path. The history is kept in a local SQLite database at `local_data/history.sqlite3`. Use **Clear history** in the tab to remove all entries.

History does not contain file contents, keys, or passphrases. File names and paths can still reveal private information, so the database stays on this computer and is excluded from Git.

## A few things to know

- Keep your private key and passphrase to yourself. Share only public keys.
- Anyone who has a recipient’s public key can encrypt a file for them. Encryption doesn’t prove who created the file; this version doesn’t add digital signatures.
- Imported contacts are stored on this computer and aren’t synced with other devices.
- Files up to 50 MiB are supported. The app currently loads the selected file into memory while encrypting or decrypting.
- Files are selected with the **Browse** buttons; drag and drop isn’t available yet.

## Tests

Run the tests with:

```bash
python3 -m unittest -v tests/test_secureshare.py
```

Tests use temporary folders so they don’t touch your real keys or contacts.
