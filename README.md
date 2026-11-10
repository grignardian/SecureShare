# SecureShare 🔒

A simple and secure desktop application for file encryption and decryption built with Python and Tkinter.

---

## 1. What is SecureShare?

**SecureShare** is an easy-to-use desktop tool that allows users to encrypt sensitive files on their computer before sharing them over the internet (via Email, WhatsApp, Google Drive, or USB). The encrypted files can only be unlocked by the designated recipient using their private key.

---

## 2. What Problem Does It Solve?

When sending files through public channels (like email, messaging apps, or cloud storage):
- **Third-Party Surveillance:** Cloud servers and middleman services can read your unencrypted files.
- **Data Tampering:** It is difficult to know if a file was altered or corrupted during transit.
- **Complex PGP/GPG Tools:** Traditional command-line encryption software is confusing for non-technical users.

**SecureShare solves this** by giving students and everyday users a simple, graphical interface to encrypt files locally with military-grade encryption (AES-256 + RSA-2048) and verify file integrity (SHA-256) with one click.

---

## 3. Main Features

- **Hybrid Encryption:**
  - **AES-256-CBC:** High-speed symmetric encryption to lock the actual file data.
  - **RSA-2048 OAEP:** Asymmetric encryption to safely protect and share the AES secret key.
- **Tamper Detection (SHA-256):** Computes a cryptographic checksum of the original file. If anyone modifies even a single byte of the encrypted file, SecureShare immediately detects it and stops decryption.
- **Unauthorized Access Prevention:** Only the recipient possessing the matching RSA private key can decrypt the file.
- **Cross-Device Ready:** Default demo keys (`alice` and `bob`) are included out-of-the-box so you can demonstrate encrypting a file on one device and decrypting it on another device.
- **Simple Graphical Interface:** Built using Python's standard `tkinter` library—no complex web servers or heavy frameworks required.

---

## 4. Project Folder Structure

```text
SecureShare/
│
├── src/
│   ├── app.py                  # Graphical User Interface (Tkinter)
│   ├── crypto.py               # Encryption, decryption & SHA-256 hashing
│   └── keystore.py             # RSA key generation, loading & saving
│
├── keys/                       # Directory containing RSA public and private keys (.pem)
│
├── tests/
│   └── test_secureshare.py     # Automated unit tests
│
├── documentation/              # Project synopsis and presentation slides
│   ├── PythonPBLSynopsis.docx
│   ├── PythonPBLSynopsis.pdf
│   ├── SecureShare_PBL_Synopsis.pdf
│   └── SecureShare_PBL_Synopsis.pptx
│
├── requirements.txt            # Python dependencies (cryptography)
├── README.md                   # Project guide and documentation
└── .gitignore                  # Git ignore rules (keys, temporary files)
```

---

## 5. Technologies and Libraries Used

- **Python 3.10+**: Core programming language.
- **Tkinter**: Standard Python graphical user interface (GUI) library.
- **Cryptography (`cryptography>=3.4.0`)**: Standard library for AES-256-CBC, PKCS7 padding, and RSA-2048 OAEP encryption.
- **Hashlib**: Standard library module used to compute SHA-256 integrity digests.

---

## 6. Installation Instructions

1. **Clone or Download the Repository:**
   ```bash
   git clone https://github.com/grignardian/SecureShare.git
   cd SecureShare
   ```

2. **(Optional) Create a Virtual Environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate    # On Windows use: .venv\Scripts\activate
   ```

3. **Install Required Dependency:**
   ```bash
   pip install -r requirements.txt
   ```

   *(Note for Linux users: If Tkinter is not installed on your system, install it via `sudo apt install python3-tk` on Ubuntu/Debian or `sudo dnf install python3-tkinter` on Fedora).*

---

## 7. How to Run the Application

From the root directory of the project, run:

```bash
python3 src/app.py
```

*(On Windows, you can also run `python src/app.py`).*

---

## 8. How to Encrypt a File

1. Open the application and stay on the **🔒 Encrypt File** tab.
2. Click **Browse...** next to "Select File to Encrypt" and choose any file (e.g., a `.txt`, `.pdf`, `.docx`, or `.png`).
3. Under **Recipient Public Key**, choose the recipient from the dropdown (e.g., `bob`) or select a custom `.pem` public key file.
4. (Optional) Adjust the output path if desired (defaults to `filename.secureshare`).
5. Click **🔒 Encrypt and Lock File**.
6. The application generates a self-contained `.secureshare` file. You can now safely send this file via Email, WhatsApp, Google Drive, or a USB drive!

---

## 9. How to Decrypt a File

1. Open the application and switch to the **🔓 Decrypt File** tab.
2. Click **Browse...** and select the `.secureshare` file you received.
3. Under **Your Private Key**, select your key name from the dropdown (e.g., `bob`) or select your private `.pem` file.
4. Specify where you want the restored file to be saved.
5. Click **🔓 Decrypt and Verify File**.
6. SecureShare verifies the SHA-256 checksum and restores the original file. If someone tampered with the file or if the wrong key is used, an error alert will be displayed.

---

## 10. How Encryption Keys Are Managed

- Keys are stored in the `keys/` directory in standard PEM format:
  - `{name}_public.pem`: Can be shared freely with anyone who wants to send you encrypted files.
  - `{name}_private.pem`: Must be kept strictly secret on your own machine.
- Default key pairs for `alice` and `bob` are automatically generated if not present.
- To generate a new key pair for a new user, switch to the **🔑 Key Management** tab, type a username (e.g., `charlie`), and click **Generate Keys**.

---

## 11. Running the Automated Tests

To run the unit tests and verify encryption, decryption, incorrect key rejection, and tamper detection:

```bash
python3 -m unittest -v tests/test_secureshare.py
```
