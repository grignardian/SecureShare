# SecureShare - End-to-End Encrypted Client-Server File Sharing System

SecureShare is a Python-based client-server desktop application for sharing files securely over a local network or the internet. Built as a college Python Lab (PBL) project at JIIT (Course Code: 26B15CS217), it encrypts every file on the sender's computer before uploading it to a central server, ensuring that only the intended recipient can unlock and read it.

---

## 1. Problem Statement

When sharing files over regular email, messaging apps, or cloud services:
- Files are often readable on third-party servers. If a server is breached, private files are exposed.
- Receivers cannot easily verify whether a file was modified or corrupted during transfer.
- Traditional encryption tools like command-line PGP are difficult for everyday users to configure and use.

## 2. Project Objectives

- Encrypt files locally on the sender's machine before network transmission so the server never sees plaintext content.
- Use hybrid cryptography (AES-256-CBC + RSA-2048 OAEP) along with HMAC-SHA256 and SHA-256 to protect both confidentiality and integrity.
- Implement direct client-server networking with Python TCP sockets protected by TLS (`ssl`).
- Manage user registration, login, and transfer history using SQLite and PBKDF2 password hashing.
- Provide a clean, straightforward graphical user interface in Tkinter.

## 3. Main Features

- **End-to-End Encryption**: Files are scrambled locally on the sender's laptop. The central server only stores encrypted files and cannot read them.
- **Two-Laptop Wi-Fi Support**: Built on TCP sockets listening on `0.0.0.0`, allowing Alice and Bob to run the client on two separate computers on the same Wi-Fi network.
- **TLS Encrypted Transport**: All login requests, keys, and file uploads travel inside a verified TLS tunnel.
- **Tamper Detection**: Uses HMAC-SHA256 (verified before decryption) and SHA-256 (verified after decryption) to catch even a single altered byte in either the encrypted file or its metadata.
- **Protected Private Keys**: User RSA private keys stay exclusively on each user's computer, encrypted with their login password and protected with owner-only file permissions (`0600`).
- **Sent and Received History**: Both sender and receiver can inspect past file transfers in the app.

---

## 4. Technologies Used

- **Python 3.8+**
- **socket** & **ssl**: Standard libraries for TCP client-server communication over TLS.
- **cryptography**: Standard library for AES-256-CBC encryption, RSA-2048 OAEP key wrapping, password-protected PKCS#8 private keys, and X.509 TLS certificate generation.
- **hashlib** & **hmac**: Standard libraries for PBKDF2 password hashing, SHA-256 file checksums, and HMAC authentication.
- **sqlite3**: Lightweight SQL database for user records and file transfer logs.
- **tkinter**: Built-in desktop GUI toolkit.
- **json** & **struct**: Used for simple length-prefixed protocol messages.

---

## 5. Project Structure

```text
SecureShare/
|
|-- src/
|   |-- app.py          # Tkinter desktop graphical user interface
|   |-- client.py       # TLS TCP client and chunked upload/download logic
|   |-- server.py       # Sequential TLS server handling client requests
|   |-- auth.py         # User registration and PBKDF2 login verification
|   |-- database.py     # SQLite database creation and queries
|   |-- crypto.py       # AES-256-CBC, RSA-2048 OAEP, HMAC-SHA256, and SHA-256
|   `-- keystore.py     # RSA key pair generation and encrypted local storage
|
|-- keys/               # Local user keys (never committed to Git)
|-- server_data/        # SQLite database and encrypted server files (gitignored)
|-- certs/              # TLS certificate (server.crt) and private key (server.key)
|
|-- tests/
|   `-- test_secureshare.py   # Automated unit and localhost integration tests
|
|-- documentation/      # Submitted project synopsis and presentation slides
|-- requirements.txt    # Required external library (cryptography)
|-- README.md           # Project guide and instructions
`-- .gitignore          # Rules excluding private keys, databases, and server data
```

---

## 6. Architecture and How It Works

### Client-Server Communication
- **Protocol**: The server listens for TCP connections on port `5555` (configurable) wrapped with TLS.
- **Sequential Model**: To keep the codebase simple and reliable, each request opens one TLS connection, sends a 4-byte length prefix followed by a JSON header, streams binary file data in 4 KB chunks (for uploads/downloads), receives the response, and closes the connection.
- **Zero-Knowledge Server**: The server stores encrypted blobs under random UUID filenames in `server_data/files/`. It never receives plaintext files, plaintext passwords, or user private keys.

### Hybrid Encryption Process
1. **AES-256-CBC Encryption**: When Alice sends a file, a fresh random 32-byte AES key and 16-byte random IV are generated. The file is padded using PKCS7 and encrypted with AES-256-CBC.
2. **RSA-2048 Key Exchange**: A separate 32-byte random HMAC key is also generated. Both keys (`AES key + HMAC key`) are encrypted together using Bob's RSA-2048 public key (with OAEP padding and SHA-256) retrieved from the server.
3. **HMAC-SHA256 Protection**: Before uploading, the app computes an HMAC-SHA256 tag over the file signature, metadata header (filename, size, SHA-256, encrypted keys), IV, and ciphertext. This prevents an attacker from modifying either the ciphertext or the metadata/SHA-256 hash.
4. **Verification and Decryption**: When Bob downloads the file, his local private key decrypts the AES and HMAC keys. The app checks the HMAC tag first using `hmac.compare_digest()`. Only if HMAC passes does it decrypt the file with AES-256-CBC and verify that the restored file's SHA-256 hash matches the original checksum.

### Authentication and Database
- **Registration & Login**: Passwords are salted with 16 random bytes and hashed with 200,000 iterations of PBKDF2-HMAC-SHA256. Upon login, the server generates a random session token stored strictly in server memory (no JWT; sessions reset when the server restarts).
- **SQLite Tables**:
  - `users`: Stores `user_id`, `username`, `password_hash`, `salt`, `public_key`, and `created_at`.
  - `files`: Stores `file_id`, `sender`, `receiver`, `original_filename`, `stored_filename`, `file_size`, `sha256`, and `uploaded_at`.

---

## 7. Setup and Installation

### 1. System Prerequisites (Linux)

On **Fedora / RHEL**:
```bash
sudo dnf install python3-tkinter openssl
```

On **Ubuntu / Debian**:
```bash
sudo apt update
sudo apt install python3-tk openssl
```

### 2. Install Python Dependencies

```bash
git clone https://github.com/grignardian/SecureShare.git
cd SecureShare
pip install -r requirements.txt
```

---

## 8. TLS Certificate Setup and Firewall Rules

SecureShare uses TLS for every network connection and verifies the server certificate on the client (`server.crt`).

### Automatic Certificate Setup
When you run `python src/server.py` for the first time, it automatically detects your laptop's LAN IP address and generates:
- `certs/server.key` (Private TLS key — keep ONLY on the server laptop!)
- `certs/server.crt` (Public TLS certificate — copy this file to client laptops)

If your laptop changes Wi-Fi networks and gets a new IP address, run:
```bash
python src/server.py --gen-cert
```
Or specify an explicit IP if needed:
```bash
python src/server.py --ip 192.168.1.25 --gen-cert
```

*(Optional Manual OpenSSL Method: If you prefer creating certificates manually with `openssl`, include `subjectAltName = IP:127.0.0.1,IP:<SERVER_LAN_IP>,DNS:localhost` in an OpenSSL config file when generating a self-signed certificate).*

### Allowing Port 5555 Through the Firewall (For Two-Laptop Demo)

On **Fedora**:
```bash
sudo firewall-cmd --add-port=5555/tcp
```
*(Add `--permanent` if you want the rule to persist across reboots).*

On **Ubuntu (UFW)**:
```bash
sudo ufw allow 5555/tcp
```

---

## 9. How to Run and Demonstrate

### Option A: Quick Local Test (One Laptop)

1. Open Terminal 1 and start the server:
   ```bash
   python3 src/server.py
   ```
2. Open Terminal 2 for Alice:
   ```bash
   python3 src/app.py
   ```
3. Open Terminal 3 for Bob:
   ```bash
   python3 src/app.py
   ```
4. Both clients connect to Server IP `127.0.0.1` and Port `5555`.

### Option B: Two Physical Laptops on the Same Wi-Fi (Main Demo)

#### On Laptop 1 (Server + Alice):
1. Check Laptop 1's Wi-Fi IP address:
   ```bash
   hostname -I
   ```
   (For example: `192.168.1.15`).
2. Allow TCP port `5555` in your firewall (see instructions above).
3. Start the server:
   ```bash
   python3 src/server.py
   ```
   Note the LAN IP printed in the terminal and the path to `certs/server.crt`.
4. Copy **ONLY** `certs/server.crt` to Laptop 2 inside its `certs/` folder (using a USB drive, local transfer, etc.). **Do NOT copy `server.key`.**
5. Open a second terminal on Laptop 1 to run Alice's client:
   ```bash
   python3 src/app.py
   ```
6. Click **Register New Account** to register `alice` (connect to `127.0.0.1` or `192.168.1.15`). Then log in as `alice`.

#### On Laptop 2 (Bob):
1. Ensure Laptop 2 is connected to the same Wi-Fi network and has `certs/server.crt` placed in its `SecureShare/certs/` folder.
2. Start Bob's client:
   ```bash
   python3 src/app.py
   ```
3. Under Server Connection Settings:
   - Enter Laptop 1's LAN IP (e.g., `192.168.1.15`).
   - Port: `5555`.
   - Click **Test Connection** to confirm TLS verification works over Wi-Fi.
4. Register `bob` and log in as `bob`.

#### Sending and Receiving a File:
1. **On Laptop 1 (Alice)**: Go to the **Send File** tab, click **Refresh Users**, choose any file, select `bob`, and click **Encrypt and Send File**.
2. **On Laptop 2 (Bob)**: Go to the **Received Files** tab, click **Refresh Inbox**, select the file from Alice, and click **Download, Decrypt and Verify Selected File**.
3. Save the restored file and open it to confirm it matches Alice's original file byte-for-byte.
4. Both Alice and Bob can switch to the **File History** tab to inspect sent and received transfer timestamps.

*Note on Key Security*: Private keys in `keys/` are encrypted with your password and must never be shared or committed to Git. If you log in from a brand-new computer, use the **Import Private Key (.pem)** button to load your backed-up key rather than overwriting it.

---

## 10. Running Automated Tests

All unit tests and the end-to-end localhost TLS integration test run inside isolated temporary directories (without modifying your real `keys/` or `server_data/`):

```bash
python3 -m unittest -v tests/test_secureshare.py
```

---

## 11. Note on Exposed Keys in Old Git History

Earlier commits in this repository's Git history contained sample Alice and Bob `.pem` key files. Those keys have been untracked from the repository, excluded via `.gitignore`, and replaced by per-user password-protected key generation at registration time. Because deleting files from the latest commit does not purge them from past Git commits, you can clean the public commit history before final submission using `git-filter-repo`:

```bash
pip install git-filter-repo
git filter-repo --invert-paths --path keys/ --path src/keys/
```
*(After scrubbing history, force-push to GitHub only when ready and agreed upon by your team).*
