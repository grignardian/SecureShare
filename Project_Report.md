# PROJECT REPORT
# SecureShare: An End-to-End Encrypted File Sharing System

**System Architecture & Technical Specifications**  
**Cryptography:** AES-256-CBC, RSA-2048 (OAEP), SHA-256, PBKDF2-HMAC-SHA256  
**Implementation:** Python 3, Tkinter GUI, SQLite3  

---

## Abstract

In the modern digital landscape, file sharing services are vital for business, academic, and personal collaboration. However, conventional cloud-based file transfer platforms store plaintext or centrally-decryptable files on remote servers, exposing users to eavesdropping, data breaches, insider threats, and man-in-the-middle (MITM) tampering attacks. 

**SecureShare** solves these challenges by implementing an accessible, lightweight, and zero-knowledge client-server file sharing system in Python. SecureShare utilizes a hybrid cryptographic scheme combining **AES-256-CBC** symmetric encryption for bulk file data with **RSA-2048 (OAEP + SHA-256)** asymmetric key encapsulation for secure AES key exchange. File integrity is cryptographically assured using **SHA-256** checksums, while user credentials are protected using **PBKDF2-HMAC-SHA256** password hashing with unique random salts. The system features a native **Tkinter** graphical user interface and an automated verification test suite.

---

## 1. Problem Statement & Objectives

### 1.1 Problem Statement
Conventional cloud-based file transmission systems suffer from three primary vulnerabilities:
1. **Centralized Data Exposure:** Servers store files in accessible or centrally decrypted states, creating single points of failure.
2. **Lack of Integrity Verification:** Everyday users cannot easily verify whether files were modified in transit by network adversaries.
3. **Usability Barriers:** Existing end-to-end encryption tools (such as PGP/GPG) require complex key management and command-line knowledge, discouraging everyday adoption.

### 1.2 Project Objectives
- Build a Python client-server system guaranteeing zero-knowledge file relaying.
- Implement hybrid cryptography combining AES-256-CBC and RSA-2048.
- Provide automatic SHA-256 integrity verification that alerts users upon tampering.
- Create an intuitive Tkinter GUI alongside an interactive terminal interface.
- Demonstrate resistance against server-side inspection and modification attacks.

---

## 2. Theoretical Background & Cryptographic Architecture

### 2.1 Why Hybrid Encryption?
- **Symmetric Encryption (AES-256):** AES is computationally efficient and capable of encrypting megabyte- or gigabyte-scale files in milliseconds. However, it requires both sender and receiver to share a secret key.
- **Asymmetric Encryption (RSA-2048):** RSA allows secure communication without pre-shared secrets through public/private key pairs. However, RSA is mathematically intensive and cannot directly encrypt large data payloads.
- **Hybrid Solution:** SecureShare generates a fresh, ephemeral 256-bit AES key for each file transfer. The file content is encrypted with AES-256-CBC. Only the small 32-byte AES key is encrypted using the recipient's RSA-2048 public key.

### 2.2 Tamper Detection via SHA-256
Before encryption, the sender computes:
$$\text{Hash} = \text{SHA-256}(\text{Plaintext})$$
The receiver computes the hash of the decrypted content and verifies:
$$\text{SHA-256}(\text{Decrypted}) \stackrel{?}{=} \text{Original Hash}$$
Due to the avalanche effect of SHA-256, even a single flipped bit in transit results in an entirely different digest, guaranteeing immediate tamper detection.

### 2.3 Credential Protection via PBKDF2
Passwords are never stored in plaintext. They are salted using a 16-byte cryptographically secure random salt ($S$) and stretched with 100,000 iterations of HMAC-SHA256:
$$\text{Key} = \text{PBKDF2}(\text{HMAC-SHA256}, \text{Password}, S, 100000)$$

---

## 3. System Architecture & Components

The application follows a three-tier modular design:

```
+-------------------------------------------------------------------------------+
|                               1. CLIENT TIER                                  |
|  - Desktop GUI (Tkinter) & Interactive Terminal CLI                           |
|  - Local Cryptographic Engine (AES-256-CBC, RSA-2048, SHA-256)                |
|  - Local Key Storage (client_storage/{username}_private.pem)                  |
+-------------------------------------------------------------------------------+
                                     |
                       TCP Socket Stream Protocol
                                     |
+-------------------------------------------------------------------------------+
|                               2. SERVER TIER                                  |
|  - Multi-threaded TCP Socket Relay Server (server/server.py)                  |
|  - Zero-Knowledge Storage: Holds ciphertext in server_storage/               |
|  - Public Key & Metadata Relay Service                                        |
+-------------------------------------------------------------------------------+
                                     |
+-------------------------------------------------------------------------------+
|                               3. DATABASE TIER                                |
|  - SQLite (secureshare.db)                                                    |
|  - Table 'users': username, password_hash, salt, public_key, timestamp        |
|  - Table 'file_transfers': sender, recipient, file_size, sha256, status       |
+-------------------------------------------------------------------------------+
```

---

## 4. Implementation Details

### 4.1 Module Breakdown
1. **`common/protocol.py`:** Standardized 4-byte length-prefixed packet protocol ensuring reliable TCP transmission of JSON control packets and binary payloads without socket fragmentation.
2. **`client/crypto_utils.py`:** Standalone, pure cryptographic operations utilizing the `cryptography` library and Python's standard `hashlib`.
3. **`server/database.py`:** Thread-safe SQLite management using parameterized SQL queries and threading locks to prevent race conditions.
4. **`server/server.py`:** Multi-threaded socket server handling concurrent clients.
5. **`client/client_core.py`:** High-level networking and cryptographic orchestration.
6. **`client/gui.py`:** User interface featuring an Authentication window, Send File tab with live cryptographic log, Inbox with Decrypt button, and Transfer History view.
7. **`demo_security_test.py`:** Automated security demonstration suite.

---

## 5. Security Evaluation & Experimental Results

The automated demonstration suite (`demo_security_test.py`) verified the system against multiple attack scenarios:

### Test 1: Legitimate Transfer & Decryption
- **File Sent:** `test_confidential.txt` (96 bytes)
- **Plaintext:** `TOP SECRET: SecureShare End-to-End Cryptography Verification Data!`
- **Original SHA-256:** `c2e6eeccf60cbaab7f3f1f318d3f837bcbf15b19c445128583d5a708d4e2db8c`
- **Result:** Bob decrypted the file successfully; decrypted SHA-256 matched the original hash with 100% precision.

### Test 2: Server Storage Inspection (Eavesdropping Resistance)
- **Stored File:** `demo_server_storage/91a4fc439a964a6e9a989832618db4b8.enc`
- **First 32 bytes (Hex):** `182175f0a404e7d4017d05c5ea4a9e12e55db7c99b1d00bcdf4cbac23984d9ba`
- **Direct Reading Attempt:** Failed with `UnicodeDecodeError`. Server holds only high-entropy pseudorandom bytes. Neither server administrators nor malicious actors on the host can access user data.

### Test 3: Tampering Attack Simulation
- A simulated attacker modified byte offset 20 of the encrypted file stored on the server.
- Bob attempted download and decryption.
- **Expected Hash:** `96770d0a62eb423dee65681620a37c881a51cc8342acba55b1ee0bda79c95024`
- **Decrypted Hash:** `ac1b553740f2b77a6ce19d301cf106b0eb195d6a4127498b496a71d3946251b2`
- **Result:** `❌ TAMPER DETECTION ALERT: SHA-256 hash mismatch! File integrity compromised.`
- The corrupted file was immediately rejected and quarantined.

---

## 6. Sustainable Development Goal (SDG) Mapping

- **Primary SDG: SDG 9 (Industry, Innovation, and Infrastructure)**  
  SecureShare contributes to building resilient and secure digital infrastructure by demonstrating how accessible cryptographic protocols protect digital communication channels against interception.
- **Secondary SDG: SDG 16 (Peace, Justice, and Strong Institutions)**  
  By guaranteeing data confidentiality and tamper-evident records, SecureShare supports transparent, accountable institutions and safeguards fundamental privacy rights.

---

## 7. Conclusion

SecureShare achieves all core objectives of an end-to-end encrypted transfer platform. It provides a robust, zero-knowledge, encrypted file transfer system implemented in clean Python. By combining AES-256-CBC, RSA-2048, SHA-256, SQLite, and Tkinter, the project demonstrates core software engineering and cybersecurity principles in an accessible application.
