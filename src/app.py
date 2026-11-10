#!/usr/bin/env python3
"""
app.py - Graphical User Interface for SecureShare
-------------------------------------------------
A simple, beginner-friendly desktop application built with Tkinter.
Allows users to:
1. Encrypt files using AES-256 and the recipient's RSA public key.
2. Decrypt .secureshare files using their RSA private key.
3. Generate new RSA key pairs for new users.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Ensure the parent directory is in Python path for imports
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src import crypto, keystore


def main():
    # Make sure default demo keys (alice and bob) exist in keys/
    keystore.ensure_default_keys()

    # Create the main application window
    root = tk.Tk()
    root.title("SecureShare - File Encryption & Decryption")
    root.geometry("720x620")
    root.minsize(650, 550)

    # -----------------------------------------------------------------------
    # Helper Functions
    # -----------------------------------------------------------------------
    def refresh_key_dropdowns():
        """Reload available keys from keys/ folder into dropdowns."""
        keys = keystore.list_available_keys()
        enc_key_combo["values"] = keys
        dec_key_combo["values"] = keys

        if keys:
            # Set default recipient to 'bob' if available, otherwise first key
            if "bob" in keys:
                enc_key_combo.set("bob")
            else:
                enc_key_combo.set(keys[0])

            # Set default decryptor to 'alice' or 'bob'
            if "alice" in keys:
                dec_key_combo.set("alice")
            else:
                dec_key_combo.set(keys[0])

        # Also refresh key listbox in Key Management tab
        keys_listbox.delete(0, tk.END)
        for k in keys:
            keys_listbox.insert(tk.END, f"  •  {k}")

    # --- Tab 1: Encrypt Actions ---
    def browse_file_to_encrypt():
        filename = filedialog.askopenfilename(title="Select File to Encrypt")
        if filename:
            enc_file_entry.delete(0, tk.END)
            enc_file_entry.insert(0, filename)
            # Suggest default output path: same name with .secureshare extension
            default_out = filename + ".secureshare"
            enc_out_entry.delete(0, tk.END)
            enc_out_entry.insert(0, default_out)

    def browse_custom_public_key():
        filename = filedialog.askopenfilename(
            title="Select Recipient Public Key (.pem)",
            filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")]
        )
        if filename:
            enc_custom_key_entry.delete(0, tk.END)
            enc_custom_key_entry.insert(0, filename)

    def on_encrypt_click():
        input_file = enc_file_entry.get().strip()
        output_file = enc_out_entry.get().strip()
        custom_key_file = enc_custom_key_entry.get().strip()
        selected_key_name = enc_key_combo.get().strip()

        # Validation
        if not input_file:
            messagebox.showwarning("Missing Input", "Please select a file to encrypt.")
            return

        if not os.path.exists(input_file):
            messagebox.showerror("Error", f"Input file not found:\n{input_file}")
            return

        if not output_file:
            output_file = input_file + ".secureshare"
            enc_out_entry.insert(0, output_file)

        # Load recipient's public key
        try:
            if custom_key_file:
                public_key_pem = keystore.load_public_key(custom_key_file)
            elif selected_key_name:
                public_key_pem = keystore.load_public_key(selected_key_name)
            else:
                messagebox.showwarning("Missing Key", "Please select a recipient public key.")
                return
        except Exception as e:
            messagebox.showerror("Key Error", f"Failed to load public key:\n{e}")
            return

        # Perform Encryption
        try:
            result = crypto.encrypt_file(input_file, output_file, public_key_pem)
            enc_status_box.config(state=tk.NORMAL)
            enc_status_box.delete("1.0", tk.END)
            enc_status_box.insert(tk.END, "✔ File successfully encrypted!\n\n")
            enc_status_box.insert(tk.END, f"Original File:   {result['filename']}\n")
            enc_status_box.insert(tk.END, f"Original Size:   {result['original_size']} bytes\n")
            enc_status_box.insert(tk.END, f"Encrypted Size:  {result['encrypted_size']} bytes\n")
            enc_status_box.insert(tk.END, f"SHA-256 Digest:  {result['sha256']}\n")
            enc_status_box.insert(tk.END, f"Saved As:        {result['output_path']}\n")
            enc_status_box.config(state=tk.DISABLED)

            messagebox.showinfo("Success", f"File successfully encrypted and saved to:\n{output_file}")
        except Exception as e:
            messagebox.showerror("Encryption Failed", f"An error occurred during encryption:\n{e}")

    # --- Tab 2: Decrypt Actions ---
    def browse_file_to_decrypt():
        filename = filedialog.askopenfilename(
            title="Select Encrypted File (.secureshare)",
            filetypes=[("SecureShare Files", "*.secureshare"), ("All Files", "*.*")]
        )
        if filename:
            dec_file_entry.delete(0, tk.END)
            dec_file_entry.insert(0, filename)
            # Default output: remove .secureshare or append _decrypted
            if filename.endswith(".secureshare"):
                suggested_out = filename[:-12]
            else:
                suggested_out = filename + ".decrypted"
            dec_out_entry.delete(0, tk.END)
            dec_out_entry.insert(0, suggested_out)

    def browse_custom_private_key():
        filename = filedialog.askopenfilename(
            title="Select Private Key (.pem)",
            filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")]
        )
        if filename:
            dec_custom_key_entry.delete(0, tk.END)
            dec_custom_key_entry.insert(0, filename)

    def on_decrypt_click():
        input_file = dec_file_entry.get().strip()
        output_file = dec_out_entry.get().strip()
        custom_key_file = dec_custom_key_entry.get().strip()
        selected_key_name = dec_key_combo.get().strip()

        # Validation
        if not input_file:
            messagebox.showwarning("Missing Input", "Please select an encrypted file.")
            return

        if not os.path.exists(input_file):
            messagebox.showerror("Error", f"Encrypted file not found:\n{input_file}")
            return

        if not output_file:
            messagebox.showwarning("Missing Output", "Please specify where to save the decrypted file.")
            return

        # Load private key
        try:
            if custom_key_file:
                private_key_pem = keystore.load_private_key(custom_key_file)
            elif selected_key_name:
                private_key_pem = keystore.load_private_key(selected_key_name)
            else:
                messagebox.showwarning("Missing Key", "Please select your private key.")
                return
        except Exception as e:
            messagebox.showerror("Key Error", f"Failed to load private key:\n{e}")
            return

        # Perform Decryption
        try:
            result = crypto.decrypt_file(input_file, output_file, private_key_pem)
            dec_status_box.config(state=tk.NORMAL)
            dec_status_box.delete("1.0", tk.END)
            dec_status_box.insert(tk.END, "✔ File successfully decrypted & integrity verified!\n\n")
            dec_status_box.insert(tk.END, f"Restored Name:   {result['filename']}\n")
            dec_status_box.insert(tk.END, f"Restored Size:   {result['restored_size']} bytes\n")
            dec_status_box.insert(tk.END, f"Verified SHA256: {result['sha256']}\n")
            dec_status_box.insert(tk.END, f"Saved As:        {result['output_path']}\n")
            dec_status_box.config(state=tk.DISABLED)

            messagebox.showinfo("Success", f"File successfully decrypted!\nIntegrity SHA-256 confirmed.\nSaved to: {output_file}")
        except crypto.DecryptionError as e:
            messagebox.showerror("Decryption Failed", f"Wrong Key:\n{e}")
        except crypto.IntegrityError as e:
            messagebox.showerror("Integrity Check Failed", f"Security Alert:\n{e}")
        except Exception as e:
            messagebox.showerror("Decryption Failed", f"An error occurred:\n{e}")

    # --- Tab 3: Key Generation Actions ---
    def on_generate_keys_click():
        name = key_name_entry.get().strip().lower()
        if not name:
            messagebox.showwarning("Input Required", "Please enter a name for the key pair (e.g. 'alice', 'bob').")
            return

        # Clean name to safe alphanumeric
        clean_name = "".join(c for c in name if c.isalnum() or c in ("_", "-"))
        if not clean_name:
            messagebox.showerror("Invalid Name", "Please use letters, numbers, or underscores.")
            return

        try:
            keystore.generate_keypair(clean_name)
            refresh_key_dropdowns()
            key_name_entry.delete(0, tk.END)
            messagebox.showinfo(
                "Keys Generated",
                f"Generated 2048-bit RSA key pair for '{clean_name}':\n"
                f"• keys/{clean_name}_private.pem\n"
                f"• keys/{clean_name}_public.pem"
            )
        except Exception as e:
            messagebox.showerror("Generation Error", f"Failed to generate key pair:\n{e}")

    # -----------------------------------------------------------------------
    # Header Banner
    # -----------------------------------------------------------------------
    header_frame = tk.Frame(root, bg="#1e293b", pady=12)
    header_frame.pack(fill=tk.X)

    title_label = tk.Label(
        header_frame,
        text="SecureShare",
        font=("Arial", 18, "bold"),
        fg="#ffffff",
        bg="#1e293b"
    )
    title_label.pack()

    subtitle_label = tk.Label(
        header_frame,
        text="End-to-End File Encryption & Decryption (AES-256 + RSA-2048 + SHA-256)",
        font=("Arial", 10),
        fg="#94a3b8",
        bg="#1e293b"
    )
    subtitle_label.pack()

    # -----------------------------------------------------------------------
    # Notebook (Tabs)
    # -----------------------------------------------------------------------
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=12)

    tab_encrypt = ttk.Frame(notebook, padding=14)
    tab_decrypt = ttk.Frame(notebook, padding=14)
    tab_keys = ttk.Frame(notebook, padding=14)

    notebook.add(tab_encrypt, text="  🔒 Encrypt File  ")
    notebook.add(tab_decrypt, text="  🔓 Decrypt File  ")
    notebook.add(tab_keys, text="  🔑 Key Management  ")

    # =======================================================================
    # TAB 1: ENCRYPT
    # =======================================================================
    # 1. File to encrypt
    ttk.Label(tab_encrypt, text="1. Select File to Encrypt:", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(4, 2))
    f_enc_row = ttk.Frame(tab_encrypt)
    f_enc_row.pack(fill=tk.X, pady=(0, 10))
    enc_file_entry = ttk.Entry(f_enc_row)
    enc_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
    ttk.Button(f_enc_row, text="Browse...", command=browse_file_to_encrypt).pack(side=tk.RIGHT)

    # 2. Recipient Public Key
    ttk.Label(tab_encrypt, text="2. Recipient Public Key (Who will open this file?):", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(4, 2))
    f_enc_key_row = ttk.Frame(tab_encrypt)
    f_enc_key_row.pack(fill=tk.X, pady=(0, 4))
    enc_key_combo = ttk.Combobox(f_enc_key_row, state="readonly", width=20)
    enc_key_combo.pack(side=tk.LEFT, padx=(0, 8))
    ttk.Label(f_enc_key_row, text="or custom .pem:").pack(side=tk.LEFT, padx=(4, 4))
    enc_custom_key_entry = ttk.Entry(f_enc_key_row)
    enc_custom_key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
    ttk.Button(f_enc_key_row, text="Browse...", command=browse_custom_public_key).pack(side=tk.RIGHT)

    # 3. Output Path
    ttk.Label(tab_encrypt, text="3. Save Encrypted File As:", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(6, 2))
    f_enc_out_row = ttk.Frame(tab_encrypt)
    f_enc_out_row.pack(fill=tk.X, pady=(0, 12))
    enc_out_entry = ttk.Entry(f_enc_out_row)
    enc_out_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

    # Encrypt Action Button
    enc_btn = tk.Button(
        tab_encrypt,
        text="🔒 Encrypt and Lock File",
        command=on_encrypt_click,
        bg="#2563eb",
        fg="#ffffff",
        font=("Arial", 11, "bold"),
        relief=tk.FLAT,
        pady=6
    )
    enc_btn.pack(fill=tk.X, pady=(4, 10))

    # Encryption Status Box
    enc_status_box = tk.Text(tab_encrypt, height=7, bg="#f8fafc", fg="#0f172a", font=("Monospace", 9))
    enc_status_box.pack(fill=tk.BOTH, expand=True)
    enc_status_box.insert(tk.END, "Ready. Select a file and recipient key to encrypt.")
    enc_status_box.config(state=tk.DISABLED)

    # =======================================================================
    # TAB 2: DECRYPT
    # =======================================================================
    # 1. File to decrypt
    ttk.Label(tab_decrypt, text="1. Select Encrypted File (.secureshare):", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(4, 2))
    f_dec_row = ttk.Frame(tab_decrypt)
    f_dec_row.pack(fill=tk.X, pady=(0, 10))
    dec_file_entry = ttk.Entry(f_dec_row)
    dec_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
    ttk.Button(f_dec_row, text="Browse...", command=browse_file_to_decrypt).pack(side=tk.RIGHT)

    # 2. Your Private Key
    ttk.Label(tab_decrypt, text="2. Your Private Key (To unlock this file):", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(4, 2))
    f_dec_key_row = ttk.Frame(tab_decrypt)
    f_dec_key_row.pack(fill=tk.X, pady=(0, 4))
    dec_key_combo = ttk.Combobox(f_dec_key_row, state="readonly", width=20)
    dec_key_combo.pack(side=tk.LEFT, padx=(0, 8))
    ttk.Label(f_dec_key_row, text="or custom .pem:").pack(side=tk.LEFT, padx=(4, 4))
    dec_custom_key_entry = ttk.Entry(f_dec_key_row)
    dec_custom_key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
    ttk.Button(f_dec_key_row, text="Browse...", command=browse_custom_private_key).pack(side=tk.RIGHT)

    # 3. Output Path
    ttk.Label(tab_decrypt, text="3. Save Restored File As:", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(6, 2))
    f_dec_out_row = ttk.Frame(tab_decrypt)
    f_dec_out_row.pack(fill=tk.X, pady=(0, 12))
    dec_out_entry = ttk.Entry(f_dec_out_row)
    dec_out_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

    # Decrypt Action Button
    dec_btn = tk.Button(
        tab_decrypt,
        text="🔓 Decrypt and Verify File",
        command=on_decrypt_click,
        bg="#059669",
        fg="#ffffff",
        font=("Arial", 11, "bold"),
        relief=tk.FLAT,
        pady=6
    )
    dec_btn.pack(fill=tk.X, pady=(4, 10))

    # Decryption Status Box
    dec_status_box = tk.Text(tab_decrypt, height=7, bg="#f8fafc", fg="#0f172a", font=("Monospace", 9))
    dec_status_box.pack(fill=tk.BOTH, expand=True)
    dec_status_box.insert(tk.END, "Ready. Select an encrypted file and your private key to decrypt.")
    dec_status_box.config(state=tk.DISABLED)

    # =======================================================================
    # TAB 3: KEY MANAGEMENT
    # =======================================================================
    gen_frame = ttk.LabelFrame(tab_keys, text=" Generate New 2048-bit RSA Key Pair ", padding=12)
    gen_frame.pack(fill=tk.X, pady=(4, 14))

    ttk.Label(gen_frame, text="User or Key Name (e.g. 'charlie'):").pack(anchor=tk.W, pady=(2, 4))
    f_gen_row = ttk.Frame(gen_frame)
    f_gen_row.pack(fill=tk.X)
    key_name_entry = ttk.Entry(f_gen_row)
    key_name_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
    ttk.Button(f_gen_row, text="Generate Keys", command=on_generate_keys_click).pack(side=tk.RIGHT)

    list_frame = ttk.LabelFrame(tab_keys, text=" Available Keys in keys/ directory ", padding=12)
    list_frame.pack(fill=tk.BOTH, expand=True)

    keys_listbox = tk.Listbox(list_frame, font=("Monospace", 10), bg="#f8fafc", relief=tk.FLAT)
    keys_listbox.pack(fill=tk.BOTH, expand=True, pady=(4, 8))

    ttk.Button(list_frame, text="Refresh Key List", command=refresh_key_dropdowns).pack(anchor=tk.E)

    # Initial load of keys
    refresh_key_dropdowns()

    # Start main Tkinter loop
    root.mainloop()


if __name__ == "__main__":
    main()
