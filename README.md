# SecureShare

SecureShare is a lightweight desktop program written in Python for encrypting and decrypting files. It gives you a clean graphical interface to lock files before sending them over email, messaging apps, or cloud storage, ensuring only the intended recipient can open them.

---

## What Problem Does This Solve?

When you email a document or upload it to Google Drive or WhatsApp, the file sits on third-party servers where it could be inspected, leaked, or modified.

Most existing encryption tools (like command-line PGP or GPG) are complicated and difficult for non-technical users to set up. SecureShare was created to solve this problem:

1. **Protect Privacy**: Files are encrypted on your local computer before they ever leave your machine.
2. **Detect Tampering**: It checks the digital fingerprint (SHA-256) of your file to verify that nobody changed anything in transit.
3. **Keep It Simple**: You do not have to memorize terminal commands—everything works through a straightforward graphical window.

---

## How It Works

SecureShare uses a standard approach called **hybrid encryption**:

1. **Locking the File (AES-256)**: When you pick a file, the app creates a one-time random secret key and uses AES-256-CBC to quickly scramble the file contents.
2. **Locking the Key (RSA-2048)**: Because you need to get that AES key to the recipient, the app encrypts the secret key using the recipient's RSA public key.
3. **Checking Integrity (SHA-256)**: The app calculates a SHA-256 hash of the original file and stores it in the header of the encrypted file.
4. **Unlocking on the Other End**: When the recipient receives the `.secureshare` file, their private key unlocks the AES key, which unlocks the file. If even a single byte was altered, the SHA-256 check fails and the app warns you.

---

## Project Structure

```text
SecureShare/
|
|-- src/
|   |-- app.py                  # Graphical user interface (Tkinter)
|   |-- crypto.py               # Encryption, decryption, and hashing logic
|   `-- keystore.py             # Key generation and file storage
|
|-- keys/                       # Folder where public and private keys are saved
|
|-- tests/
|   `-- test_secureshare.py     # Unit tests
|
|-- documentation/              # Project synopsis and presentation slides
|   |-- PythonPBLSynopsis.docx
|   |-- PythonPBLSynopsis.pdf
|   |-- SecureShare_PBL_Synopsis.pdf
|   `-- SecureShare_PBL_Synopsis.pptx
|
|-- requirements.txt            # Project dependencies
|-- README.md                   # This guide
`-- .gitignore                  # Files and folders ignored by Git
```

---

## Technologies Used

- **Python 3**: Core language.
- **Tkinter**: Standard GUI library included with Python.
- **cryptography**: The standard Python library used for AES-256 and RSA-2048 operations.
- **hashlib**: Standard Python module used to generate SHA-256 hashes.

---

## Setup and Installation

### 1. Download the Project

Clone the repository or download the ZIP file:

```bash
git clone https://github.com/grignardian/SecureShare.git
cd SecureShare
```

### 2. Install the Required Library

Install the `cryptography` package using pip:

```bash
pip install -r requirements.txt
```

*(Note for Linux users: If Tkinter is not already installed on your system, install it with `sudo apt install python3-tk` on Ubuntu/Debian or `sudo dnf install python3-tkinter` on Fedora).*

---

## How to Run the Application

Start the program from the project folder:

```bash
python3 src/app.py
```

On Windows:

```bash
python src/app.py
```

---

## Step-by-Step Usage Guide

### Encrypting a File

1. Open the app and go to the **Encrypt File** tab.
2. Click **Browse...** to pick the file you want to protect (any document, image, or text file).
3. Select the recipient's public key from the dropdown (for example, `bob`), or select a `.pem` file directly.
4. Click **Encrypt and Lock File**.
5. The app creates a new file ending with `.secureshare`. You can now safely email this file or send it over WhatsApp.

### Decrypting a File

1. Go to the **Decrypt File** tab.
2. Click **Browse...** and select the `.secureshare` file you received.
3. Choose your matching private key from the dropdown (or select your `.pem` file).
4. Choose where to save the restored file.
5. Click **Decrypt and Verify File**.
6. The app checks that the file was not altered and restores your original file.

### Generating New Keys

Default keys for `alice` and `bob` are generated automatically so you can test the program right away.

To create keys for someone else:
1. Go to the **Key Management** tab.
2. Type a name (for example, `charlie`).
3. Click **Generate Keys**.
4. The app saves two files in the `keys/` directory:
   - `charlie_public.pem` (share this with anyone who wants to send files to Charlie)
   - `charlie_private.pem` (keep this secret on Charlie's computer)

---

## Running the Tests

To verify that encryption, decryption, wrong-key rejection, and tamper detection are all working properly, run:

```bash
python3 -m unittest -v tests/test_secureshare.py
```
