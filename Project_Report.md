# PROJECT REPORT
# SecureShare: Portable End-to-End Encrypted File Sharing System

**System Architecture & Technical Specifications**  
**Cryptography:** AES-256-CBC, RSA-2048 (OAEP), SHA-256, PBKDF2-HMAC-SHA256  
**Implementation:** Python 3, Tkinter GUI, Portable `.secureshare` Binary Bundles  

---

## Abstract

In modern digital communication, users routinely share sensitive files across messaging platforms (WhatsApp, Telegram), email, cloud links, and USB drives. Standard platforms either transmit files without true end-to-end encryption or store centrally readable copies on remote servers, exposing files to breaches, eavesdropping, and tampering.

**SecureShare** solves this by decoupling **cryptographic protection** from the **transport channel**. Rather than trapping encrypted files inside a single-device local database, SecureShare encrypts any file into a self-contained, portable `.secureshare` binary bundle using **AES-256-CBC** symmetric encryption, encapsulates the session key using **RSA-2048 (OAEP + SHA-256)** asymmetric encryption, and embeds a **SHA-256** integrity checksum. The encrypted `.secureshare` file can be transferred via any ordinary medium to a second device, where the intended recipient drops it into SecureShare to verify integrity and restore the original file.

---

## 1. Problem Statement & Objectives

### 1.1 Problem Statement
1. **Unencrypted Transport Exposure:** Sending plain PDFs, documents, or images over email or chat exposes file contents to intermediary servers.
2. **Single-Device Database Limitations:** Simulating file sharing through a local database prevents demonstrating genuine file transmission between two physical devices without deploying an online server.
3. **Lack of Integrity Guarantees:** Recipients cannot easily detect whether a file was corrupted or silently tampered with in transit.

### 1.2 Project Objectives
- Encrypt any file locally into a portable `.secureshare` bundle transferable over any external channel (WhatsApp, Email, Drive, USB).
- Support **fixed cross-device RSA-2048 key pairs** (`alice` and `bob`) for instant multi-device encryption/decryption demonstrations without requiring an online database, alongside **`.pem` key export/import** for custom users.
- Implement hybrid encryption (**AES-256-CBC** + **RSA-2048 OAEP**).
- Enforce automatic **SHA-256** tamper detection and wrong-key access rejection.
- Protect user accounts using **PBKDF2-HMAC-SHA256** salted password hashing.

---

## 2. Cryptographic Architecture

### 2.1 Hybrid Encryption & `.secureshare` Bundle Format
- **Symmetric Encryption (AES-256-CBC):** Each file uses a fresh random 256-bit key and 16-byte IV with PKCS7 padding, handling files of any size rapidly.
- **Asymmetric Key Encapsulation (RSA-2048 OAEP):** The 32-byte AES key is encrypted using the recipient's RSA-2048 public key via OAEP with SHA-256.
- **Portable Bundle Layout:**
  ```
  [9 bytes Magic: "SECSHARE1"]
  [4 bytes Header Length (uint32 big-endian)]
  [JSON Header: filename, size, sender, recipient, sha256, enc_key_hex]
  [Raw Binary Payload: 16-byte IV + AES-256-CBC Ciphertext]
  ```

### 2.2 Integrity Verification & Path Sanitization
Before encryption, the sender computes $\text{SHA-256}(\text{Plaintext})$. Upon decryption on the receiving device, the recipient recomputes $\text{SHA-256}(\text{Decrypted})$ and verifies an exact match before writing output. Filenames extracted from the bundle header are sanitized via `os.path.basename` to block directory-traversal attacks.

### 2.3 Credential Protection via PBKDF2
Passwords are never stored in plaintext. User passwords are salted with 16 cryptographically random bytes ($S$) and stretched with 200,000 iterations of HMAC-SHA256:
$$\text{Hash} = \text{PBKDF2}(\text{HMAC-SHA256}, \text{Password}, S, 200000)$$

---

## 3. Module Architecture

1. **`crypto.py`:** Pure cryptographic primitives (`aes_encrypt`, `aes_decrypt`, `generate_rsa_keypair`, `rsa_encrypt`, `rsa_decrypt`, `sha256`, `hash_password`, `check_password`) plus portable bundle APIs (`encrypt_file_bundle`, `inspect_file_bundle`, `decrypt_file_bundle`) with typed security exceptions (`WrongKeyError`, `TamperDetectedError`, `InvalidBundleError`).
2. **`keystore.py`:** Manages built-in fixed cross-device profiles (`keys/`) as well as locally created accounts and imported external `.pem` contacts (`local_keys/`).
3. **`app.py`:** Light-themed Tkinter GUI featuring:
   - Sign In / Profile Creation with PBKDF2 verification and Show/Hide password toggle.
   - **Encrypt File** tab (recipient fingerprint check, file picker, portable `.secureshare` export).
   - **Decrypt File** tab (header inspector, custom or profile private key selection, SHA-256 verification, and file restore).
   - **Keys & Contacts** tab (copy/export public `.pem`, import recipient `.pem`, keypair regeneration).
   - **Tamper & Security Test** tab (live automated 3-step cryptographic check).
4. **`demo_security.py` & `tests/test_secureshare.py`:** Standalone CLI demonstration and automated unit tests.

---

## 4. Security Verification Results

The automated verification (`demo_security.py` and `unittest`) confirms:
1. **Unreadable Ciphertext Payload:** Inspecting the `.secureshare` payload bytes yields pure high-entropy binary (`UnicodeDecodeError` on UTF-8 decode), keeping files private across any transport medium.
2. **Wrong-Key Access Control:** Attempting to decrypt Bob's `.secureshare` file with Alice's private key immediately raises `WrongKeyError`.
3. **Legitimate Recovery & Integrity Match:** Bob decrypts using his fixed RSA-2048 private key and achieves a 100% SHA-256 match.
4. **Tamper Rejection:** Flipping a single byte inside the `.secureshare` ciphertext raises `TamperDetectedError` and prevents saving the modified file.

---

## 5. Conclusion

By adopting a serverless, portable `.secureshare` bundle architecture paired with fixed cross-device test keys and `.pem` key exchange, SecureShare enables genuine end-to-end encrypted file sharing across separate physical devices using AES-256-CBC, RSA-2048 OAEP, SHA-256, and PBKDF2.
