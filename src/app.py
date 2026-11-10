#!/usr/bin/env python3
"""Offline Tkinter interface for local file encryption and decryption."""
import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src import crypto, keystore


def main():
    root = tk.Tk()
    root.title("SecureShare — Offline File Encryption")
    root.geometry("760x560")
    root.minsize(640, 460)

    frame = ttk.Frame(root, padding=16)
    frame.pack(fill=tk.BOTH, expand=True)
    ttk.Label(frame, text="SecureShare", font=("TkDefaultFont", 18, "bold")).pack(anchor=tk.W)
    ttk.Label(frame, text="Encrypt files locally. Share encrypted bundles separately.").pack(anchor=tk.W, pady=(0, 12))
    tabs = ttk.Notebook(frame)
    tabs.pack(fill=tk.BOTH, expand=True)
    keys_tab = ttk.Frame(tabs, padding=14)
    contacts_tab = ttk.Frame(tabs, padding=14)
    encrypt_tab = ttk.Frame(tabs, padding=14)
    decrypt_tab = ttk.Frame(tabs, padding=14)
    tabs.add(keys_tab, text="My Keys")
    tabs.add(contacts_tab, text="Contacts / Public Keys")
    tabs.add(encrypt_tab, text="Encrypt File")
    tabs.add(decrypt_tab, text="Decrypt File")

    key_status = tk.StringVar()
    ttk.Label(keys_tab, textvariable=key_status, wraplength=660).pack(anchor=tk.W, pady=(0, 12))

    def refresh_key_status():
        if (os.path.exists(keystore.get_private_key_path())
                or os.path.exists(keystore.get_public_key_path())):
            try:
                pub = keystore.load_public_key()
                fp = keystore.compute_fingerprint(pub)
                key_status.set("Local RSA private key is present and passphrase-protected.\nFingerprint: " + fp)
            except Exception as exc:
                key_status.set("Key files need attention: " + str(exc))
        else:
            key_status.set("No key pair yet. Generate one before decrypting files for yourself.")

    def generate_keys():
        if keystore.has_private_key():
            messagebox.showerror("Key already exists", "A local key pair exists. This app will not replace it silently.")
            return
        password = simpledialog.askstring("Protect private key", "Choose a passphrase for your private key:", show="*", parent=root)
        if password is None:
            return
        confirm = simpledialog.askstring("Confirm passphrase", "Enter the passphrase again:", show="*", parent=root)
        if password != confirm:
            messagebox.showerror("Passphrases differ", "The passphrases did not match.")
            return
        if len(password) < 8:
            messagebox.showerror("Passphrase too short", "Use at least 8 characters.")
            return
        try:
            private_key, public_pem = keystore.generate_rsa_keypair()
            keystore.save_private_key(private_key, password)
            keystore.save_public_key(public_pem)
            refresh_key_status()
            refresh_contacts()
            messagebox.showinfo("Keys created", "Your private key is protected locally. Share only your exported public key.")
        except Exception as exc:
            messagebox.showerror("Key generation failed", str(exc))

    def export_public():
        if not os.path.isfile(keystore.get_public_key_path()):
            messagebox.showerror("No public key", "Generate your key pair first.")
            return
        path = filedialog.asksaveasfilename(title="Export public key", defaultextension=".pem", filetypes=[("PEM public key", "*.pem")])
        if path:
            try:
                keystore.export_public_key(path)
                messagebox.showinfo("Public key exported", "Fingerprint:\n" + keystore.compute_fingerprint(keystore.load_public_key()))
            except Exception as exc:
                messagebox.showerror("Export failed", str(exc))

    ttk.Button(keys_tab, text="Generate RSA key pair", command=generate_keys).pack(anchor=tk.W, pady=4)
    ttk.Button(keys_tab, text="Export my public key…", command=export_public).pack(anchor=tk.W, pady=4)
    ttk.Label(keys_tab, text="Keep your private key and passphrase safe. If the private key is lost, files encrypted for it cannot be recovered.", wraplength=660).pack(anchor=tk.W, pady=(14, 0))

    contact_list = tk.Listbox(contacts_tab, height=12)
    contact_list.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

    def refresh_contacts():
        contact_list.delete(0, tk.END)
        try:
            for item in keystore.load_contacts():
                contact_list.insert(tk.END, f"{item['name']} — {item['fingerprint']}")
        except Exception as exc:
            messagebox.showerror("Contact book error", str(exc))

    def import_contact():
        path = filedialog.askopenfilename(title="Import a public key", filetypes=[("PEM public key", "*.pem *.pub"), ("All files", "*.*")])
        if not path:
            return
        name = simpledialog.askstring("Contact name", "Name this contact:", parent=root)
        if not name:
            return
        try:
            contact = keystore.import_contact_from_file(name.strip(), path)
            refresh_contacts()
            refresh_contacts_combo()
            messagebox.showinfo("Contact imported", "Verify this fingerprint with the contact:\n\n" + contact["fingerprint"])
        except Exception as exc:
            messagebox.showerror("Import failed", str(exc))

    def remove_contact():
        sel = contact_list.curselection()
        if not sel:
            messagebox.showwarning("Select contact", "Choose a contact first.")
            return
        name = keystore.load_contacts()[sel[0]]["name"]
        if messagebox.askyesno("Remove contact", f"Remove {name} from this device?"):
            keystore.remove_contact(name)
            refresh_contacts()
            refresh_contacts_combo()

    contact_buttons = ttk.Frame(contacts_tab)
    contact_buttons.pack(fill=tk.X)
    ttk.Button(contact_buttons, text="Import public key…", command=import_contact).pack(side=tk.LEFT)
    ttk.Button(contact_buttons, text="Remove selected", command=remove_contact).pack(side=tk.LEFT, padx=8)
    ttk.Label(contacts_tab, text="Compare fingerprints through a trusted channel before encrypting to a newly imported key.", wraplength=660).pack(anchor=tk.W, pady=(10, 0))

    encrypt_path = tk.StringVar()
    ttk.Label(encrypt_tab, text="Choose a file and recipient public key. The encrypted .secureshare bundle is saved locally.", wraplength=650).pack(anchor=tk.W, pady=(0, 10))
    erow = ttk.Frame(encrypt_tab)
    erow.pack(fill=tk.X)
    ttk.Entry(erow, textvariable=encrypt_path).pack(side=tk.LEFT, fill=tk.X, expand=True)
    def browse_encrypt():
        p = filedialog.askopenfilename(title="Choose file to encrypt")
        if p: encrypt_path.set(p)
    ttk.Button(erow, text="Browse…", command=browse_encrypt).pack(side=tk.LEFT, padx=(8, 0))
    ttk.Label(encrypt_tab, text="Recipient:").pack(anchor=tk.W, pady=(14, 4))
    recipient = ttk.Combobox(encrypt_tab, state="readonly")
    recipient.pack(fill=tk.X)
    enc_status = tk.StringVar(value="")
    ttk.Label(encrypt_tab, textvariable=enc_status, wraplength=650).pack(anchor=tk.W, pady=12)

    def refresh_contacts_combo():
        names = [c["name"] for c in keystore.load_contacts()]
        recipient["values"] = names
        if names and recipient.get() not in names:
            recipient.set(names[0])

    def encrypt_selected():
        source = encrypt_path.get()
        name = recipient.get()
        if not os.path.isfile(source) or not name:
            messagebox.showwarning("Missing selection", "Choose a file and a recipient.")
            return
        contact = keystore.get_contact(name)
        if not contact:
            messagebox.showerror("Contact unavailable", "Import the recipient's public key first.")
            return
        suggested = os.path.basename(source) + ".secureshare"
        target = filedialog.asksaveasfilename(title="Save encrypted bundle", initialfile=suggested, defaultextension=".secureshare", filetypes=[("SecureShare bundle", "*.secureshare")])
        if not target:
            return
        if os.path.exists(target) and not messagebox.askyesno("Replace file?", "The selected output exists. Replace it?"):
            return
        try:
            result = crypto.encrypt_file(source, target, contact["public_key"], overwrite=True)
            enc_status.set(f"Encrypted {result['filename']} ({result['file_size']} bytes) for {name}.\nSaved: {target}")
            messagebox.showinfo("Encryption complete", "Share the encrypted bundle separately. SecureShare does not send files.")
        except Exception as exc:
            messagebox.showerror("Encryption failed", str(exc))
    ttk.Button(encrypt_tab, text="Encrypt file", command=encrypt_selected).pack(fill=tk.X, pady=4)

    decrypt_path = tk.StringVar()
    ttk.Label(decrypt_tab, text="Choose a .secureshare bundle. You need the private key that matches the recipient public key.", wraplength=650).pack(anchor=tk.W, pady=(0, 10))
    drow = ttk.Frame(decrypt_tab)
    drow.pack(fill=tk.X)
    ttk.Entry(drow, textvariable=decrypt_path).pack(side=tk.LEFT, fill=tk.X, expand=True)
    def browse_decrypt():
        p = filedialog.askopenfilename(title="Choose encrypted bundle", filetypes=[("SecureShare bundle", "*.secureshare"), ("All files", "*.*")])
        if p: decrypt_path.set(p)
    ttk.Button(drow, text="Browse…", command=browse_decrypt).pack(side=tk.LEFT, padx=(8, 0))
    dec_status = tk.StringVar(value="")
    ttk.Label(decrypt_tab, textvariable=dec_status, wraplength=650).pack(anchor=tk.W, pady=12)

    def decrypt_selected():
        source = decrypt_path.get()
        if not os.path.isfile(source):
            messagebox.showwarning("Choose bundle", "Select an encrypted bundle first.")
            return
        password = simpledialog.askstring("Unlock private key", "Enter your private-key passphrase:", show="*", parent=root)
        if password is None:
            return
        try:
            private_key = keystore.load_private_key(password)
        except Exception as exc:
            messagebox.showerror("Could not unlock key", str(exc))
            return
        try:
            suggested = crypto.get_bundle_suggested_filename(source)
        except Exception as exc:
            messagebox.showerror("Invalid bundle", str(exc))
            return
        target = filedialog.asksaveasfilename(title="Save decrypted file", initialfile=suggested)
        if not target:
            return
        if os.path.exists(target) and not messagebox.askyesno("Replace file?", "The selected output exists. Replace it?"):
            return
        try:
            result = crypto.decrypt_file(source, target, private_key, overwrite=True)
            dec_status.set(f"Decrypted and authenticated {result['filename']} ({result['file_size']} bytes).\nSaved: {target}")
            messagebox.showinfo("Decryption complete", "The file authentication check passed.")
        except Exception as exc:
            messagebox.showerror("Decryption failed", str(exc))

    ttk.Button(decrypt_tab, text="Decrypt file", command=decrypt_selected).pack(fill=tk.X, pady=4)
    refresh_key_status()
    refresh_contacts()
    refresh_contacts_combo()
    tabs.bind("<<NotebookTabChanged>>", lambda _event: refresh_contacts_combo())
    root.mainloop()


if __name__ == "__main__":
    main()
