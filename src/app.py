#!/usr/bin/env python3
"""Offline Tkinter interface for local file encryption and decryption."""
import os
import sys
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src import crypto, history, keystore


def main():
    root = tk.Tk()
    root.title("SecureShare | Private by design")
    root.geometry("900x680")
    root.minsize(720, 560)
    root.configure(bg="#F3F5F9")

    # Use the cross-platform clam theme as a clean base, then define a small,
    # consistent palette rather than relying on OS-specific widget defaults.
    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")
    style.configure("TFrame", background="#F3F5F9")
    style.configure("Card.TFrame", background="#FFFFFF")
    style.configure("TLabel", background="#FFFFFF", foreground="#243047", font=("Segoe UI", 10))
    style.configure("Card.TLabel", background="#FFFFFF", foreground="#243047", font=("Segoe UI", 10))
    style.configure("Panel.TLabel", background="#F6F8FC", foreground="#243047", font=("Segoe UI", 10))
    style.configure("Title.TLabel", background="#F3F5F9", foreground="#17233B", font=("Segoe UI", 24, "bold"))
    style.configure("Subtitle.TLabel", background="#F3F5F9", foreground="#69758A", font=("Segoe UI", 10))
    style.configure("Section.TLabel", background="#FFFFFF", foreground="#17233B", font=("Segoe UI", 15, "bold"))
    style.configure("Hint.TLabel", background="#FFFFFF", foreground="#718096", font=("Segoe UI", 9))
    style.configure("TNotebook", background="#F3F5F9", borderwidth=0, tabmargins=(0, 0, 0, 0))
    style.configure("TNotebook.Tab", background="#E8ECF3", foreground="#667085", padding=(18, 11), font=("Segoe UI", 10, "bold"), borderwidth=0)
    style.map("TNotebook.Tab", background=[("selected", "#FFFFFF"), ("active", "#DDE5F1")], foreground=[("selected", "#315CFF")])
    style.configure("TEntry", fieldbackground="#FFFFFF", foreground="#243047", padding=9, bordercolor="#DDE3EC")
    style.configure("TCombobox", fieldbackground="#FFFFFF", foreground="#243047", padding=8, arrowcolor="#52627A")
    style.configure("TButton", background="#E8ECF3", foreground="#34415A", padding=(13, 9), borderwidth=0, font=("Segoe UI", 9, "bold"))
    style.map("TButton", background=[("active", "#D9E0EB"), ("pressed", "#CBD5E3")])
    style.configure("Primary.TButton", background="#315CFF", foreground="#FFFFFF", padding=(15, 11), font=("Segoe UI", 10, "bold"))
    style.map("Primary.TButton", background=[("active", "#244BE0"), ("pressed", "#1D3FC2")], foreground=[("active", "#FFFFFF")])
    style.configure("Treeview", background="#FFFFFF", fieldbackground="#FFFFFF", foreground="#34415A", rowheight=32, borderwidth=0, font=("Segoe UI", 9))
    style.configure("Treeview.Heading", background="#F3F5F9", foreground="#718096", font=("Segoe UI", 9, "bold"), relief="flat")

    frame = ttk.Frame(root, padding=(30, 24, 30, 26))
    frame.pack(fill=tk.BOTH, expand=True)
    header = ttk.Frame(frame)
    header.pack(fill=tk.X, pady=(0, 22))
    brand = ttk.Frame(header)
    brand.pack(side=tk.LEFT)
    ttk.Label(brand, text="SecureShare", style="Title.TLabel").pack(anchor=tk.W)
    ttk.Label(brand, text="Private file encryption, kept on your device", style="Subtitle.TLabel").pack(anchor=tk.W, pady=(2, 0))
    ttk.Label(header, text="●  LOCAL ONLY", background="#E5F5EF", foreground="#14805E", padding=(12, 8), font=("Segoe UI", 8, "bold")).pack(side=tk.RIGHT, anchor=tk.CENTER)
    tabs = ttk.Notebook(frame)
    tabs.pack(fill=tk.BOTH, expand=True)
    keys_tab = ttk.Frame(tabs, padding=24, style="Card.TFrame")
    contacts_tab = ttk.Frame(tabs, padding=24, style="Card.TFrame")
    encrypt_tab = ttk.Frame(tabs, padding=24, style="Card.TFrame")
    decrypt_tab = ttk.Frame(tabs, padding=24, style="Card.TFrame")
    history_tab = ttk.Frame(tabs, padding=24, style="Card.TFrame")
    tabs.add(keys_tab, text="MY KEYS")
    tabs.add(contacts_tab, text="CONTACTS")
    tabs.add(encrypt_tab, text="ENCRYPT")
    tabs.add(decrypt_tab, text="DECRYPT")
    tabs.add(history_tab, text="HISTORY")

    key_status = tk.StringVar()
    ttk.Label(keys_tab, text="Your identity", style="Section.TLabel").pack(anchor=tk.W)
    ttk.Label(keys_tab, text="Your private key stays on this device and is protected by your passphrase.", style="Hint.TLabel").pack(anchor=tk.W, pady=(4, 18))
    key_card = tk.Frame(keys_tab, bg="#F6F8FC", padx=16, pady=15, highlightthickness=1, highlightbackground="#E8ECF3")
    key_card.pack(fill=tk.X, pady=(0, 18))
    ttk.Label(key_card, textvariable=key_status, wraplength=700, style="Panel.TLabel").pack(anchor=tk.W)

    def refresh_key_status():
        if (os.path.exists(keystore.get_private_key_path())
                or os.path.exists(keystore.get_public_key_path())):
            try:
                pub = keystore.load_public_key()
                key_status.set("RSA key pair ready  ·  private key protected with your passphrase")
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
                messagebox.showinfo("Public key exported", "Your public key is ready to share. Keep your private key to yourself.")
            except Exception as exc:
                messagebox.showerror("Export failed", str(exc))

    key_actions = ttk.Frame(keys_tab, style="Card.TFrame")
    key_actions.pack(fill=tk.X)
    ttk.Button(key_actions, text="Create key pair", command=generate_keys, style="Primary.TButton").pack(side=tk.LEFT, padx=(0, 9))
    ttk.Button(key_actions, text="Export public key", command=export_public).pack(side=tk.LEFT)
    ttk.Label(keys_tab, text="Keep a secure backup of your private key. If it is lost, files encrypted for it cannot be recovered.", style="Hint.TLabel", wraplength=700).pack(anchor=tk.W, pady=(22, 0))

    ttk.Label(contacts_tab, text="Your people", style="Section.TLabel").pack(anchor=tk.W)
    ttk.Label(contacts_tab, text="Import a public key to add someone to your local recipient list.", style="Hint.TLabel").pack(anchor=tk.W, pady=(4, 16))
    contact_list = tk.Listbox(contacts_tab, height=12, bg="#F8FAFD", fg="#34415A", selectbackground="#DCE6FF", selectforeground="#203FBB", highlightthickness=1, highlightbackground="#E8ECF3", relief="flat", font=("Segoe UI", 10), activestyle="none")
    contact_list.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

    def refresh_contacts():
        contact_list.delete(0, tk.END)
        try:
            for item in keystore.load_contacts():
                contact_list.insert(tk.END, f"  {item['name']}")
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
            messagebox.showinfo("Contact imported", f"{contact['name']} is ready to select as a recipient.")
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
    ttk.Button(contact_buttons, text="Import public key", command=import_contact, style="Primary.TButton").pack(side=tk.LEFT)
    ttk.Button(contact_buttons, text="Remove selected", command=remove_contact).pack(side=tk.LEFT, padx=8)
    ttk.Label(contacts_tab, text="Contacts are stored only on this device. Remove an old entry before importing a replacement key.", style="Hint.TLabel", wraplength=700).pack(anchor=tk.W, pady=(16, 0))

    encrypt_path = tk.StringVar()
    ttk.Label(encrypt_tab, text="Encrypt for someone", style="Section.TLabel").pack(anchor=tk.W)
    ttk.Label(encrypt_tab, text="Choose a file and recipient. The encrypted bundle is saved on this device.", style="Hint.TLabel", wraplength=700).pack(anchor=tk.W, pady=(4, 18))
    erow = ttk.Frame(encrypt_tab)
    erow.pack(fill=tk.X)
    ttk.Entry(erow, textvariable=encrypt_path).pack(side=tk.LEFT, fill=tk.X, expand=True)
    def browse_encrypt():
        p = filedialog.askopenfilename(title="Choose file to encrypt")
        if p: encrypt_path.set(p)
    ttk.Button(erow, text="Browse…", command=browse_encrypt).pack(side=tk.LEFT, padx=(8, 0))
    ttk.Label(encrypt_tab, text="RECIPIENT", style="Hint.TLabel").pack(anchor=tk.W, pady=(18, 7))
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
            record_history("Encrypt", result["filename"], source, target, result["file_size"], name)
            messagebox.showinfo("Encryption complete", "Share the encrypted bundle separately. SecureShare does not send files.")
        except Exception as exc:
            messagebox.showerror("Encryption failed", str(exc))
    ttk.Button(encrypt_tab, text="Encrypt file", command=encrypt_selected, style="Primary.TButton").pack(fill=tk.X, pady=(12, 4))

    decrypt_path = tk.StringVar()
    ttk.Label(decrypt_tab, text="Unlock a received bundle", style="Section.TLabel").pack(anchor=tk.W)
    ttk.Label(decrypt_tab, text="Choose a .secureshare bundle and save the restored file where you want it.", style="Hint.TLabel", wraplength=700).pack(anchor=tk.W, pady=(4, 18))
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
            record_history("Decrypt", result["filename"], source, target, result["file_size"])
            messagebox.showinfo("Decryption complete", "The file authentication check passed.")
        except Exception as exc:
            messagebox.showerror("Decryption failed", str(exc))

    ttk.Button(decrypt_tab, text="Decrypt file", command=decrypt_selected, style="Primary.TButton").pack(fill=tk.X, pady=(12, 4))
    ttk.Label(history_tab, text="Your activity", style="Section.TLabel").pack(anchor=tk.W)
    ttk.Label(history_tab, text="A private, on-device record of completed encryptions and decryptions.", style="Hint.TLabel").pack(anchor=tk.W, pady=(4, 16))
    history_toolbar = ttk.Frame(history_tab, style="Card.TFrame")
    history_toolbar.pack(fill=tk.X, pady=(0, 10))
    history_count = tk.StringVar(value="")
    ttk.Label(history_toolbar, textvariable=history_count, style="Hint.TLabel").pack(side=tk.LEFT)

    def refresh_history():
        try:
            rows = history.list_events()
            for child in history_tree.get_children():
                history_tree.delete(child)
            for row in rows:
                stamp = datetime.fromisoformat(row["occurred_at"]).astimezone().strftime("%d %b %Y  %H:%M")
                recipient_name = row["recipient"] or "—"
                history_tree.insert("", tk.END, values=(
                    stamp, row["action"], row["filename"], recipient_name,
                    format_file_size(row["file_size"]), row["output_path"]
                ))
            history_count.set(f"{len(rows)} {('entry' if len(rows) == 1 else 'entries')}")
        except Exception as exc:
            messagebox.showerror("History unavailable", str(exc))

    def clear_history_view():
        try:
            if not history.list_events():
                return
            if messagebox.askyesno("Clear history", "Remove all saved encryption and decryption history from this device?"):
                history.clear_history()
                refresh_history()
        except Exception as exc:
            messagebox.showerror("Could not clear history", str(exc))

    ttk.Button(history_toolbar, text="Refresh", command=refresh_history).pack(side=tk.RIGHT, padx=(8, 0))
    ttk.Button(history_toolbar, text="Clear history", command=clear_history_view).pack(side=tk.RIGHT)
    history_columns = ("time", "action", "filename", "recipient", "size", "saved")
    history_tree = ttk.Treeview(history_tab, columns=history_columns, show="headings", height=11)
    for column, label, width in (
        ("time", "WHEN", 142), ("action", "ACTION", 85), ("filename", "FILE", 150),
        ("recipient", "CONTACT", 110), ("size", "SIZE", 80), ("saved", "SAVED TO", 220)
    ):
        history_tree.heading(column, text=label)
        history_tree.column(column, width=width, minwidth=70, anchor=tk.W, stretch=(column == "saved"))
    history_tree.pack(fill=tk.BOTH, expand=True)
    ttk.Label(history_tab, text="History includes file names and paths. Clear it any time from this tab.", style="Hint.TLabel").pack(anchor=tk.W, pady=(12, 0))

    def record_history(action, filename, source, output, file_size, recipient_name=""):
        try:
            history.record_event(action, filename, source, output, file_size, recipient_name)
            refresh_history()
        except Exception as exc:
            messagebox.showwarning("History not saved", "The file operation succeeded, but its history entry could not be saved:\n\n" + str(exc))

    def format_file_size(size):
        size = float(size)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024 or unit == "GB":
                return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
            size /= 1024

    refresh_key_status()
    refresh_contacts()
    refresh_contacts_combo()
    refresh_history()
    tabs.bind("<<NotebookTabChanged>>", lambda _event: refresh_contacts_combo())
    root.mainloop()


if __name__ == "__main__":
    main()
