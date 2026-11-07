# SecureShare: End-to-End Encrypted File Sharing System

SecureShare is a modern, zero-knowledge desktop application for end-to-end encrypted file transfer. It combines military-grade symmetric encryption (AES-256-CBC) with asymmetric cryptography (RSA-2048 OAEP), SHA-256 cryptographic hashing for tamper verification, and PBKDF2 password derivation.

---

## 1. Quick Start

Run the application:
```bash
python3 app.py
```
*(The GUI opens with pre-configured demo credentials ready to log in).*

To run the automated Security & Tamper Attack test suite:
```bash
python3 demo_security.py
```

---

## 2. Default Login Accounts

| Username | Password | Purpose |
| :--- | :--- | :--- |
| `bob` | `Bob123!` | Pre-filled sender/receiver account |
| `alice` | `Alice123!` | Test peer account |

*(You can also click **"Create Account"** to register any new username and password instantly).*

---

## 3. Project Structure

```
PythonPBL/
├── app.py             # Modern Desktop GUI application (python3 app.py)
├── crypto.py          # Cryptographic module (AES-256-CBC, RSA-2048, SHA-256, PBKDF2)
├── db.py              # SQLite database layer & encrypted vault storage
├── demo_security.py   # Standalone demo for encryption & tamper detection
├── user_keys/         # RSA-2048 public & private keys
├── encrypted_vault/   # Zero-knowledge storage holding only unreadable ciphertext
├── downloads/         # Decrypted and verified output files
├── requirements.txt   # Dependencies (cryptography)
└── README.md          # Documentation
```

---

## 4. Cryptographic Pipeline

1. **Password Authentication**: PBKDF2 HMAC-SHA256 with random salt (200,000 iterations). Plaintext passwords are never stored.
2. **Hybrid File Encryption**:
   - Sender generates a fresh random 256-bit AES session key (`os.urandom(32)`).
   - The file is encrypted using **AES-256-CBC** with PKCS7 padding and a unique 16-byte IV.
   - The recipient's **RSA-2048 public key** encrypts the AES session key via OAEP (SHA-256 MGF1).
3. **Integrity & Tamper Detection**:
   - Sender computes SHA-256 hash of original file prior to encryption.
   - Recipient decrypts and independently computes the SHA-256 digest.
   - If even 1 bit was altered in transit or in the vault, the mismatch is flagged and download is aborted.
4. **Zero-Knowledge Vault**:
   - The storage layer stores only encrypted blobs and public metadata. Plaintext files and private keys never touch the vault.
