# SecureShare: Technical Viva & Evaluation Guide

This guide covers the core questions and technical explanations commonly asked during project evaluations and viva voce examinations.

---

## 1. System Architecture & Cryptography

### Q1: Why use Hybrid Encryption instead of purely RSA or purely AES?
* **Pure RSA limitation**: Asymmetric cryptography (RSA-2048) is computationally expensive, requires significant CPU overhead, and mathematically cannot encrypt data larger than its key modulus size minus padding (a 2048-bit RSA key can only encrypt up to 214 bytes under OAEP SHA-256). It is impractical for bulk files (PDFs, images, documents).
* **Pure AES limitation**: Symmetric cryptography (AES-256) is fast and supports arbitrary file sizes, but requires sender and receiver to share the secret key beforehand. If the key is transmitted over an insecure channel, the entire system is compromised.
* **Hybrid Solution**: We combine both:
  1. Generate a random, temporary 256-bit AES session key for the file.
  2. Encrypt the file data using **AES-256-CBC**.
  3. Encrypt the 32-byte AES session key using the recipient's **RSA-2048 public key** via OAEP.
  4. The recipient uses their private RSA key to unwrap the AES key, then decrypts the file payload.

---

### Q2: Why AES-256-CBC and why is an Initialization Vector (IV) necessary?
* **AES-256**: Uses a 256-bit key size, currently impenetrable against brute-force attacks by any known computing hardware.
* **CBC (Cipher Block Chaining) Mode**: Each plaintext block is XORed with the previous ciphertext block before encryption.
* **Role of the IV**: The IV (16 random bytes) ensures that encrypting the same file twice produces completely distinct ciphertexts. Without an IV (such as in ECB mode), identical plaintext blocks produce identical ciphertext blocks, leaking structural information.

---

### Q3: Why PKCS7 padding?
* AES is a block cipher operating strictly on 128-bit (16-byte) blocks.
* If a file size is not an exact multiple of 16 bytes, PKCS7 appends $N$ bytes (each with value $N$) to round up to the nearest 16-byte boundary.
* During decryption, if the padding is corrupted or tampered with, the unpadder immediately raises an exception and aborts.

---

### Q4: Why RSA-2048 with OAEP instead of PKCS#1 v1.5?
* **OAEP (Optimal Asymmetric Encryption Padding)**: Incorporates two cryptographic hash functions to introduce randomness into the plaintext before RSA encryption.
* Prevents **Chosen-Ciphertext Attacks (CCA)** and **Bleichenbacher padding oracle attacks**, which exploit older PKCS#1 v1.5 padding schemes.

---

### Q5: How are passwords stored and authenticated?
* Passwords are **never stored in plaintext**.
* The system uses **PBKDF2-HMAC-SHA256**:
  * **16-byte cryptographically secure random salt** per user (`os.urandom(16)`), defeating precomputed Rainbow Table attacks.
  * **200,000 iterations** of HMAC-SHA256, significantly slowing down offline brute-force and dictionary attacks (e.g., using Hashcat or GPUs).
  * Only `(salt_hex, hash_hex)` is persisted in SQLite.

---

## 2. Integrity & Tamper Detection

### Q6: How does SecureShare detect file tampering?
1. Before encryption, the sender computes the **SHA-256 hash** of the original unencrypted file bytes.
2. The hash digest (64 hex characters) is recorded in the transfer metadata.
3. Upon download, the recipient decrypts the payload and independently recalculates the SHA-256 digest on the recovered plaintext.
4. If a single bit in the ciphertext or file is flipped by an attacker or corrupted on disk:
   - **Case A**: Decryption fails due to corrupted PKCS7 block padding $\to$ Aborted.
   - **Case B**: The decrypted plaintext is altered $\to$ The computed SHA-256 differs $\to$ Flagged as **Tamper Detected** and rejected without saving.

---

### Q7: What does "Zero-Knowledge Storage" mean in this system?
* The server/database holds:
  1. Encrypted `.enc` blobs in `encrypted_vault/` (pure high-entropy ciphertext).
  2. Encrypted AES session keys (only decryptable by the recipient's private key).
  3. RSA public keys and PBKDF2 password hashes.
* Neither the host operating system, database administrator, nor a network eavesdropper has access to:
  * Plaintext files
  * AES session keys
  * User private RSA keys (stored strictly in `user_keys/` on the user's client machine)

---

## 3. Security Demonstration Walkthrough

When presenting the **"Security & Tamper Demo"** tab:

| Step | Action Performed | What it Proves |
| :--- | :--- | :--- |
| **Test 1: Storage Inspection** | Inspects raw bytes in `encrypted_vault/*.enc` and tries to decode UTF-8. | Proves the server cannot read files; storage contains only high-entropy ciphertext. |
| **Test 2: Normal Decryption** | Recipient uses private RSA key to unwrap the AES key, decrypts the file, and checks SHA-256. | Proves clean end-to-end recovery with a 100% cryptographic hash match. |
| **Test 3: Bit-Flip Attack** | Flips byte 24 in the vault file (`0x4A` $\to$ `0xB5`), then recipient tries to download. | Proves that tampering is caught immediately via SHA-256 or padding failure, rejecting the corrupt file. |
