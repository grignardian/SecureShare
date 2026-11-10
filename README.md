# SecureShare

Standalone cross-device end-to-end file encryption desktop app in Python.

Encrypts any file into a self-contained `.secureshare` bundle that can be sent over WhatsApp, Email, Cloud Drive, or USB and verified/decrypted by the intended recipient on another device.

## Cryptography

- **File Encryption:** AES-256-CBC with a fresh 256-bit random session key, 16-byte random IV, and PKCS7 padding.
- **Key Exchange:** RSA-2048 OAEP (SHA-256 MGF1).
- **Tamper Detection:** SHA-256 integrity verification prior to saving restored output.
- **Password Hashing:** PBKDF2-HMAC-SHA256 (16-byte salt, 200,000 iterations).

## Setup & Usage

```bash
git clone https://github.com/grignardian/SecureShare.git
cd SecureShare
pip install -r requirements.txt
python3 app.py
```

*(Linux users without `tkinter`: install `python3-tk` on Debian/Ubuntu or `python3-tkinter` on Fedora.)*

## Cross-Device Demo

Two built-in profiles (`alice` / `Alice123!` and `bob` / `Bob123!`) use fixed RSA-2048 keys in `keys/` so you can test across separate devices without a central server:

1. **Sender (Device A):** Sign in as `alice`, open **Encrypt File**, select `bob`, pick a file, and save `<file>.secureshare`. Transfer it via any medium.
2. **Recipient (Device B):** Sign in as `bob`, open **Decrypt File**, load the `.secureshare` file, and decrypt. Wrong keys or 1-byte tampering are rejected.

Custom profiles and external `.pem` public keys can also be created, exported, and imported from the **Keys & Contacts** tab.

## Project Structure

```
SecureShare/
├── app.py                   # Tkinter GUI application
├── crypto.py                # AES-256-CBC, RSA-2048 OAEP, SHA-256, PBKDF2 & .secureshare format
├── keystore.py              # Fixed cross-device keyring, local profiles & .pem contacts
├── keys/                    # Fixed cross-device key pairs for alice & bob
├── tests/
│   └── test_secureshare.py  # Unit tests
└── requirements.txt
```

## Tests

```bash
python3 -m unittest discover -v tests
```
