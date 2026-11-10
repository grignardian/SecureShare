# SecureShare: Portable End-to-End Encrypted File Sharing System

SecureShare is a standalone desktop application for **true cross-device end-to-end encrypted file sharing**. Instead of locking files inside a local database, SecureShare encrypts any file into a single portable `.secureshare` bundle that you can send over **WhatsApp, Email, Google Drive, Telegram, or USB**, and the recipient opens/drops it on their own device to verify and decrypt.

---

## 1. Quick Start

Run the application:
```bash
python3 app.py
# or
./run.sh
```

Run the standalone cryptographic & tamper test suite:
```bash
python3 demo_security.py
```

Run unit tests:
```bash
python3 -m unittest discover -v tests
```

---

## 2. How Cross-Device Encryption Works

1. **Built-in Fixed Cross-Device Accounts** (`alice` & `bob` in `keys/`):
   - Both accounts come with fixed RSA-2048 key pairs committed in `keys/` so two separate devices running SecureShare share the exact same key pairs without needing an online key server or connected database.
   - | Username | Password | Role |
     | :--- | :--- | :--- |
     | `alice` | `Alice123!` | Sender / Receiver |
     | `bob` | `Bob123!` | Sender / Receiver |
2. **Custom Accounts & Key Exchange (`Keys & Contacts` tab)**:
   - Click **Create Local Account** to generate a brand-new RSA-2048 key pair in `local_keys/`.
   - Export your **Public Key (`.pem`)** and send it to a peer, or import a peer's `.pem` key to encrypt files specifically for them.

---

## 3. Step-by-Step Usage Across Two Devices

1. **On Device 1 (Sender — e.g. Alice)**:
   - Sign in as `alice`.
   - Open the **Encrypt File** tab, select recipient **`bob`**, pick any file, and click **Encrypt & Save Portable `.secureshare` File**.
   - Send the generated `<filename>.secureshare` file via WhatsApp, Email, Drive, or USB.
2. **On Device 2 (Recipient — e.g. Bob)**:
   - Sign in as `bob`.
   - Open the **Decrypt File** tab and open/drop the received `.secureshare` file.
   - Click **Decrypt, Verify SHA-256 & Save Restored File**.
   - SecureShare unwraps the AES session key with Bob's RSA private key, decrypts the payload, verifies the SHA-256 checksum, and saves the restored file to `downloads/`.

*(If an attacker tampers with even 1 byte, or if the wrong user like Alice tries to decrypt Bob's file, decryption is immediately rejected.)*

---

## 4. Project Structure

```
SecureShare/
├── app.py              # Light-themed Tkinter Desktop GUI (4 tabs)
├── crypto.py           # AES-256-CBC, RSA-2048 OAEP, SHA-256, PBKDF2 & .secureshare bundle engine
├── keystore.py         # Fixed cross-device keyring + local profiles & .pem contact management
├── demo_security.py    # Standalone CLI verification & tamper-attack test script
├── keys/               # Fixed cross-device RSA-2048 keys & PBKDF2 hashes for alice & bob
├── local_keys/         # Locally registered users & imported contacts (gitignored)
├── downloads/          # Restored decrypted output files
├── tests/              # Automated unit tests
├── run.sh              # Launcher script
├── requirements.txt    # Dependencies (cryptography)
└── README.md           # Documentation
```

---

## 5. `.secureshare` Portable Bundle Format & Security

1. **Password Security**: User passwords are verified via **PBKDF2-HMAC-SHA256** with a 16-byte random salt and 200,000 iterations.
2. **File Encryption**: Every encrypted file generates a fresh 256-bit random AES session key (`os.urandom(32)`) and 16-byte random IV using **AES-256-CBC** with PKCS7 padding.
3. **Key Encapsulation**: The 32-byte AES session key is encrypted using the recipient's **RSA-2048 public key** with OAEP (SHA-256 MGF1).
4. **Bundle Structure**:
   `[SECSHARE1 (9B)] + [Header Length (4B)] + [JSON Header (filename, size, sender, recipient, sha256, enc_key)] + [Raw AES-256-CBC Ciphertext]`
5. **Tamper Detection**: Before saving the decrypted file, the recipient computes `SHA-256(decrypted)` and verifies it matches the expected digest; any single-bit modification or block corruption aborts saving.
