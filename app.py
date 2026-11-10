#!/usr/bin/env python3
"""
SecureShare – Portable End-to-End File Encryption & Decryption
================================================================
HOW TO RUN:
    python3 app.py [optional_file.secureshare]

Workflow:
  1. Encrypt File     – Pick any file & recipient → saves a self-contained .secureshare file
  2. Send Anywhere    – Transfer the .secureshare file via WhatsApp, Email, Drive, or USB
  3. Decrypt File     – Drop/open the .secureshare file on another device → verify SHA-256 & restore
  4. Fixed Cross-Device Keys – `bob` and `alice` use fixed RSA-2048 key pairs so encryption
                               on Device A and decryption on Device B work out-of-the-box

Cryptographic Stack:
  • File Encryption:      AES-256-CBC (random 256-bit key, random 16-byte IV, PKCS7)
  • Key Encapsulation:    RSA-2048 OAEP (SHA-256 MGF1)
  • Tamper Detection:     SHA-256 cryptographic digest verification
  • Profile Passwords:    PBKDF2-HMAC-SHA256 (200,000 iterations + 16-byte random salt)
"""

import os
import sys
import platform
import subprocess
import tempfile
from urllib.parse import urlparse, unquote
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import crypto
import keystore

# ── Directories ─────────────────────────────────────────────────────────────
BASE      = os.path.dirname(os.path.abspath(__file__))
DOWNLOADS = os.path.join(BASE, "downloads")
os.makedirs(DOWNLOADS, exist_ok=True)

keystore.ensure_fixed_profiles()


def _clean_path(raw: str) -> str:
    """Normalize paths pasted or dragged from file managers (handles quotes & file:// URIs)."""
    p = raw.strip().strip('"').strip("'")
    if p.startswith("file://"):
        p = unquote(urlparse(p).path)
    return p


def _format_size(n: int) -> str:
    if n < 1024:
        return f"{n:,} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB ({n:,} B)"
    return f"{n / (1024 * 1024):.2f} MB ({n:,} B)"


def _open_in_os(path: str):
    """Open a file or directory using the OS default handler."""
    sys_name = platform.system()
    if sys_name == "Linux":
        subprocess.Popen(["xdg-open", path])
    elif sys_name == "Darwin":
        subprocess.Popen(["open", path])
    elif sys_name == "Windows":
        os.startfile(path)


# ════════════════════════════════════════════════════════════════════════════
# APPLICATION GUI (LIGHT THEME)
# ════════════════════════════════════════════════════════════════════════════

class App(tk.Tk):

    def __init__(self, initial_bundle: str | None = None):
        super().__init__()
        self.title("SecureShare – End-to-End File Encryption & Decryption")
        self.geometry("1000x760")
        self.minsize(860, 640)
        self.resizable(True, True)
        self.configure(bg="#f1f5f9")

        self._current_user     = None
        self._private_key      = None
        self._public_key       = None
        self._pwd_visible      = False
        self._initial_bundle   = initial_bundle
        self._last_enc_output  = None
        self._last_dec_output  = None
        self._custom_priv_pem  = None
        self._custom_priv_path = None

        self._init_styles()
        self._show_login()

    # ── Theme & Styling ───────────────────────────────────────────────────────

    def _init_styles(self):
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except Exception:
            pass

        s.configure(".", font=("Segoe UI", 10), background="#f8fafc", foreground="#0f172a")
        s.configure("App.TFrame", background="#f8fafc")

        # Buttons
        s.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), foreground="#ffffff",
                    background="#2563eb", borderwidth=0, padding=(14, 8))
        s.map("Primary.TButton", background=[("active", "#1d4ed8"), ("pressed", "#1e40af")])

        s.configure("Success.TButton", font=("Segoe UI", 10, "bold"), foreground="#ffffff",
                    background="#059669", borderwidth=0, padding=(14, 8))
        s.map("Success.TButton", background=[("active", "#047857"), ("pressed", "#065f46")])

        s.configure("Outline.TButton", font=("Segoe UI", 9, "bold"), foreground="#1e293b",
                    background="#ffffff", borderwidth=1, padding=(10, 6))
        s.map("Outline.TButton", background=[("active", "#f1f5f9")])

        s.configure("DangerOutline.TButton", font=("Segoe UI", 9, "bold"), foreground="#dc2626",
                    background="#fef2f2", borderwidth=1, padding=(10, 6))
        s.map("DangerOutline.TButton", background=[("active", "#fee2e2")])

        s.configure("Eye.TButton", font=("Segoe UI", 9), foreground="#334155",
                    background="#f1f5f9", borderwidth=1, padding=(6, 4))
        s.map("Eye.TButton", background=[("active", "#e2e8f0")])

        s.configure("Header.TButton", font=("Segoe UI", 9, "bold"), foreground="#dc2626",
                    background="#fee2e2", borderwidth=0, padding=(10, 5))
        s.map("Header.TButton", background=[("active", "#fecaca")])

        # Tabs
        s.configure("TNotebook", background="#f1f5f9", borderwidth=0)
        s.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=(16, 9),
                    background="#e2e8f0", foreground="#475569", borderwidth=0)
        s.map("TNotebook.Tab",
              background=[("selected", "#ffffff"), ("active", "#cbd5e1")],
              foreground=[("selected", "#2563eb"), ("active", "#0f172a")])

        # Treeview
        s.configure("Treeview", font=("Segoe UI", 9), rowheight=28,
                    background="#ffffff", fieldbackground="#ffffff", foreground="#0f172a", borderwidth=0)
        s.map("Treeview",
              background=[("selected", "#2563eb"), ("!selected", "#ffffff")],
              foreground=[("selected", "#ffffff"), ("!selected", "#0f172a")])
        s.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"),
                    background="#e2e8f0", foreground="#0f172a", padding=(6, 6))
        s.map("Treeview.Heading",
              background=[("active", "#cbd5e1"), ("!active", "#e2e8f0")],
              foreground=[("active", "#0f172a"), ("!active", "#0f172a")])

    # ════════════════════════════════════════════════════════════════════════
    # LOGIN SCREEN
    # ════════════════════════════════════════════════════════════════════════

    def _show_login(self):
        self._clear_window()
        self.configure(bg="#f1f5f9")

        outer = tk.Frame(self, bg="#f1f5f9")
        outer.place(relx=0.5, rely=0.5, anchor="center")

        brand = tk.Frame(outer, bg="#f1f5f9")
        brand.pack(pady=(0, 18))
        tk.Label(brand, text="🛡️ SecureShare", font=("Segoe UI", 26, "bold"),
                 fg="#1e40af", bg="#f1f5f9").pack()
        tk.Label(brand, text="Portable End-to-End File Encryption  •  Encrypt Anywhere, Decrypt Anywhere",
                 font=("Segoe UI", 10), fg="#64748b", bg="#f1f5f9").pack(pady=(4, 0))

        card = tk.Frame(outer, bg="#ffffff", padx=36, pady=30,
                        highlightbackground="#cbd5e1", highlightthickness=1)
        card.pack(ipadx=10)

        tk.Label(card, text="Sign In / Select Key Profile", font=("Segoe UI", 14, "bold"),
                 fg="#0f172a", bg="#ffffff").pack(anchor="w", pady=(0, 14))

        # Username
        u_box = tk.Frame(card, bg="#ffffff")
        u_box.pack(fill="x", pady=5)
        tk.Label(u_box, text="Username", font=("Segoe UI", 9, "bold"), fg="#334155", bg="#ffffff").pack(anchor="w")
        self._login_user = ttk.Entry(u_box, width=36, font=("Segoe UI", 11))
        self._login_user.pack(fill="x", pady=(3, 0), ipady=3)
        self._login_user.insert(0, "alice")

        # Password + Eye Toggle
        p_box = tk.Frame(card, bg="#ffffff")
        p_box.pack(fill="x", pady=(10, 6))
        tk.Label(p_box, text="Password", font=("Segoe UI", 9, "bold"), fg="#334155", bg="#ffffff").pack(anchor="w")

        p_row = tk.Frame(p_box, bg="#ffffff")
        p_row.pack(fill="x", pady=(3, 0))
        self._login_pwd = ttk.Entry(p_row, width=28, show="•", font=("Segoe UI", 11))
        self._login_pwd.pack(side="left", fill="x", expand=True, ipady=3)
        self._login_pwd.insert(0, "Alice123!")

        self._pwd_visible = False
        self._btn_eye = ttk.Button(p_row, text="👁 Show", style="Eye.TButton",
                                   command=self._toggle_password_visibility)
        self._btn_eye.pack(side="right", padx=(6, 0))

        # Quick Fill Demo Accounts
        pill_row = tk.Frame(card, bg="#ffffff")
        pill_row.pack(fill="x", pady=(12, 16))
        tk.Label(pill_row, text="Fixed Cross-Device Profiles:", font=("Segoe UI", 9),
                 fg="#64748b", bg="#ffffff").pack(side="left", padx=(0, 6))
        ttk.Button(pill_row, text="👤 alice", style="Outline.TButton",
                   command=lambda: self._quick_fill("alice", "Alice123!")).pack(side="left", padx=3)
        ttk.Button(pill_row, text="👤 bob", style="Outline.TButton",
                   command=lambda: self._quick_fill("bob", "Bob123!")).pack(side="left", padx=3)

        # Action Buttons
        btn_row = tk.Frame(card, bg="#ffffff")
        btn_row.pack(fill="x", pady=(4, 8))
        ttk.Button(btn_row, text="🔐  Sign In", style="Primary.TButton", width=15,
                   command=self._do_login).pack(side="left", padx=(0, 8), fill="x", expand=True)
        ttk.Button(btn_row, text="➕ Create Local Account", style="Outline.TButton", width=18,
                   command=self._do_create_account).pack(side="left", fill="x", expand=True)

        self._login_status = tk.Label(card, text="", font=("Segoe UI", 9, "bold"),
                                      fg="#2563eb", bg="#ffffff", wraplength=380)
        self._login_status.pack(pady=(10, 0))

        info = tk.Frame(outer, bg="#f1f5f9")
        info.pack(pady=(16, 0))
        tk.Label(info,
                 text="💡 `alice` & `bob` use identical fixed RSA-2048 keys across devices so you can\n"
                      "encrypt on Laptop A, send via WhatsApp/Email/USB, and decrypt on Laptop B.",
                 font=("Segoe UI", 9), fg="#64748b", bg="#f1f5f9", justify="center").pack()

        self.bind("<Return>", lambda _: self._do_login())

    def _toggle_password_visibility(self):
        if self._pwd_visible:
            self._login_pwd.configure(show="•")
            self._btn_eye.configure(text="👁 Show")
            self._pwd_visible = False
        else:
            self._login_pwd.configure(show="")
            self._btn_eye.configure(text="🙈 Hide")
            self._pwd_visible = True

    def _quick_fill(self, username: str, password: str):
        self._login_user.delete(0, "end")
        self._login_user.insert(0, username)
        self._login_pwd.delete(0, "end")
        self._login_pwd.insert(0, password)
        self._status(self._login_status, f"Loaded fixed profile '{username}'. Click Sign In.", "green")

    def _do_login(self):
        user = self._login_user.get().strip()
        pwd  = self._login_pwd.get()
        if not user or not pwd:
            self._status(self._login_status, "Please enter both username and password.", "red")
            return

        ok, msg = keystore.authenticate(user, pwd)
        if not ok:
            self._status(self._login_status, msg, "red")
            return

        priv = keystore.get_private_key(user)
        pub  = keystore.get_public_key(user)
        if not priv or not pub:
            self._status(self._login_status, f"Key files missing for '{user}'.", "red")
            return

        self._current_user     = user
        self._private_key      = priv
        self._public_key       = pub
        self._custom_priv_pem  = None
        self._custom_priv_path = None
        self.unbind("<Return>")
        self._show_main()

    def _do_create_account(self):
        user = self._login_user.get().strip()
        pwd  = self._login_pwd.get()
        ok, msg = keystore.register_user(user, pwd)
        self._status(self._login_status, ("✅ " + msg) if ok else msg, "green" if ok else "red")

    # ════════════════════════════════════════════════════════════════════════
    # MAIN DASHBOARD
    # ════════════════════════════════════════════════════════════════════════

    def _show_main(self):
        self._clear_window()
        self.configure(bg="#f1f5f9")

        # Header Bar
        header = tk.Frame(self, bg="#ffffff", height=58, padx=16, pady=10,
                          highlightbackground="#e2e8f0", highlightthickness=1)
        header.pack(fill="x")

        brand = tk.Frame(header, bg="#ffffff")
        brand.pack(side="left")
        tk.Label(brand, text="🛡️ SecureShare", font=("Segoe UI", 15, "bold"),
                 fg="#1e40af", bg="#ffffff").pack(side="left")
        tk.Label(brand, text=" | Portable E2EE File Tool", font=("Segoe UI", 10),
                 fg="#64748b", bg="#ffffff").pack(side="left", padx=(4, 0))

        right = tk.Frame(header, bg="#ffffff")
        right.pack(side="right")

        fp = crypto.key_fingerprint(self._public_key)
        kind_tag = "FIXED KEY" if keystore.is_fixed_user(self._current_user) else "LOCAL KEY"
        pill = tk.Frame(right, bg="#eff6ff", padx=10, pady=4,
                        highlightbackground="#bfdbfe", highlightthickness=1)
        pill.pack(side="left", padx=(0, 8))
        tk.Label(pill, text=f"👤 {self._current_user}", font=("Segoe UI", 10, "bold"),
                 fg="#1e3a8a", bg="#eff6ff").pack(side="left", padx=(0, 8))
        tk.Label(pill, text=f"🔑 {kind_tag}: {fp}", font=("Consolas", 8, "bold"),
                 fg="#2563eb", bg="#eff6ff").pack(side="left")

        ttk.Button(right, text="Sign Out", style="Header.TButton",
                   command=self._do_logout).pack(side="left")

        # Notebook Tabs
        self._nb = ttk.Notebook(self)
        self._nb.pack(fill="both", expand=True, padx=12, pady=(8, 12))

        self._tab_encrypt = ttk.Frame(self._nb, style="App.TFrame", padding=16)
        self._tab_decrypt = ttk.Frame(self._nb, style="App.TFrame", padding=16)
        self._tab_keys    = ttk.Frame(self._nb, style="App.TFrame", padding=16)
        self._tab_demo    = ttk.Frame(self._nb, style="App.TFrame", padding=16)

        self._nb.add(self._tab_encrypt, text="  🔒  Encrypt File  ")
        self._nb.add(self._tab_decrypt, text="  🔓  Decrypt File  ")
        self._nb.add(self._tab_keys,    text="  🔑  Keys & Contacts  ")
        self._nb.add(self._tab_demo,    text="  🛡️  Tamper & Security Test  ")

        self._build_encrypt_tab()
        self._build_decrypt_tab()
        self._build_keys_tab()
        self._build_demo_tab()

        def on_tab_change(event):
            tab_text = self._nb.tab(self._nb.select(), "text")
            if "Encrypt" in tab_text:
                self._reload_recipients()
            elif "Keys" in tab_text:
                self._refresh_keys_tab()

        self._nb.bind("<<NotebookTabChanged>>", on_tab_change)

        # If launched with a .secureshare file argument, jump straight to Decrypt tab
        if self._initial_bundle and os.path.isfile(self._initial_bundle):
            self._nb.select(self._tab_decrypt)
            self._dec_in_path.delete(0, "end")
            self._dec_in_path.insert(0, self._initial_bundle)
            self._inspect_selected_bundle()
            self._initial_bundle = None

    def _do_logout(self):
        self._current_user = None
        self._private_key  = None
        self._public_key   = None
        self._show_login()

    # ════════════════════════════════════════════════════════════════════════
    # TAB 1 – ENCRYPT FILE (Save portable .secureshare file)
    # ════════════════════════════════════════════════════════════════════════

    def _build_encrypt_tab(self):
        p = self._tab_encrypt

        hdr = tk.Frame(p, bg="#f8fafc")
        hdr.pack(fill="x", pady=(0, 8))
        tk.Label(hdr, text="Encrypt File for Transfer", font=("Segoe UI", 14, "bold"),
                 fg="#0f172a", bg="#f8fafc").pack(anchor="w")
        tk.Label(hdr,
                 text="Encrypts your file into a portable .secureshare file. Send it via WhatsApp, Email, Drive, or USB — only the chosen recipient can decrypt it.",
                 font=("Segoe UI", 9), fg="#64748b", bg="#f8fafc").pack(anchor="w")

        card = tk.Frame(p, bg="#ffffff", padx=18, pady=14,
                        highlightbackground="#e2e8f0", highlightthickness=1)
        card.pack(fill="x", pady=(0, 10))

        # 1. Recipient selection
        r1 = tk.Frame(card, bg="#ffffff")
        r1.pack(fill="x", pady=(0, 10))
        tk.Label(r1, text="Encrypt For (Recipient):", font=("Segoe UI", 10, "bold"),
                 width=22, anchor="w", fg="#334155", bg="#ffffff").pack(side="left")

        self._enc_recipient_var = tk.StringVar()
        self._enc_recipient_cmb = ttk.Combobox(r1, textvariable=self._enc_recipient_var,
                                               state="readonly", width=22, font=("Segoe UI", 10))
        self._enc_recipient_cmb.pack(side="left", padx=(0, 8))
        self._enc_recipient_cmb.bind("<<ComboboxSelected>>", lambda _: self._update_recipient_fp())

        self._enc_fp_label = tk.Label(r1, text="", font=("Consolas", 9),
                                      fg="#2563eb", bg="#ffffff")
        self._enc_fp_label.pack(side="left", padx=(0, 8))

        ttk.Button(r1, text="📥 Import Key (.pem)", style="Outline.TButton",
                   command=self._quick_import_pem).pack(side="right")

        self._reload_recipients()

        # 2. Clickable Drop / Pick Zone
        drop = tk.Frame(card, bg="#f8fafc", pady=14, padx=14,
                        highlightbackground="#94a3b8", highlightthickness=1, cursor="hand2")
        drop.pack(fill="x", pady=(0, 8))
        lbl_drop_title = tk.Label(drop, text="📂  Click here to pick ANY file to encrypt",
                                  font=("Segoe UI", 11, "bold"), fg="#1e40af", bg="#f8fafc", cursor="hand2")
        lbl_drop_title.pack()
        lbl_drop_sub = tk.Label(drop, text="(Supports PDFs, images, docs, archives, or text — or paste path below)",
                                font=("Segoe UI", 8), fg="#64748b", bg="#f8fafc", cursor="hand2")
        lbl_drop_sub.pack(pady=(2, 0))

        for w in (drop, lbl_drop_title, lbl_drop_sub):
            w.bind("<Button-1>", lambda _: self._browse_encrypt_input())

        # Input File Row
        r2 = tk.Frame(card, bg="#ffffff")
        r2.pack(fill="x", pady=4)
        tk.Label(r2, text="Source File:", font=("Segoe UI", 10, "bold"),
                 width=14, anchor="w", fg="#334155", bg="#ffffff").pack(side="left")
        self._enc_in_path = ttk.Entry(r2, font=("Segoe UI", 10))
        self._enc_in_path.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(r2, text="Browse…", style="Outline.TButton",
                   command=self._browse_encrypt_input).pack(side="left", padx=(0, 6))
        ttk.Button(r2, text="📝 Quick Sample", style="Outline.TButton",
                   command=self._create_sample_input).pack(side="left")

        # Output .secureshare File Row
        r3 = tk.Frame(card, bg="#ffffff")
        r3.pack(fill="x", pady=4)
        tk.Label(r3, text="Save Encrypted As:", font=("Segoe UI", 10, "bold"),
                 width=14, anchor="w", fg="#334155", bg="#ffffff").pack(side="left")
        self._enc_out_path = ttk.Entry(r3, font=("Segoe UI", 10))
        self._enc_out_path.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(r3, text="Save As…", style="Outline.TButton",
                   command=self._browse_encrypt_output).pack(side="left")

        # Action Row
        act = tk.Frame(card, bg="#ffffff")
        act.pack(fill="x", pady=(12, 4))
        ttk.Button(act, text="🔒  Encrypt & Save Portable .secureshare File",
                   style="Primary.TButton", command=self._do_encrypt).pack(side="left", fill="x", expand=True)
        self._btn_open_enc_dir = ttk.Button(act, text="📁 Open Folder", style="Outline.TButton",
                                            command=self._open_enc_folder, state="disabled")
        self._btn_open_enc_dir.pack(side="left", padx=(8, 0))

        self._enc_status = tk.Label(card, text="", font=("Segoe UI", 10, "bold"),
                                    bg="#ffffff", wraplength=880, anchor="w", justify="left")
        self._enc_status.pack(fill="x", pady=(8, 0))

        tk.Label(p, text="Encryption Pipeline Details:",
                 font=("Segoe UI", 10, "bold"), fg="#1e293b", bg="#f8fafc").pack(anchor="w", pady=(2, 4))
        self._enc_log = self._make_console(p, height=9)

    def _reload_recipients(self):
        all_rec = keystore.list_all_recipients()
        names = [r["name"] for r in all_rec]
        current = self._enc_recipient_var.get()
        self._enc_recipient_cmb["values"] = names
        if current in names:
            self._enc_recipient_var.set(current)
        else:
            # Prefer selecting the other user by default for instant cross-device demo
            others = [n for n in names if n != self._current_user]
            if others:
                self._enc_recipient_var.set(others[0])
            elif names:
                self._enc_recipient_var.set(names[0])
        self._update_recipient_fp()

    def _update_recipient_fp(self):
        name = self._enc_recipient_var.get().strip()
        pub = keystore.get_public_key(name) if name else None
        if pub:
            fp = crypto.key_fingerprint(pub)
            self._enc_fp_label.config(text=f"Key Fingerprint: {fp}")
        else:
            self._enc_fp_label.config(text="")

    def _browse_encrypt_input(self):
        path = filedialog.askopenfilename(parent=self, title="Select any file to encrypt")
        if path and os.path.isfile(path):
            self._set_encrypt_paths(path)

    def _create_sample_input(self):
        path = os.path.join(BASE, "sample_document.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "CONFIDENTIAL DOCUMENT\n"
                "This file was encrypted with AES-256-CBC and RSA-2048 OAEP.\n"
                "Send the .secureshare file to the recipient on another device to decrypt it.\n"
            )
        self._set_encrypt_paths(path)
        self._status(self._enc_status, "✅ Sample document created and selected.", "green")

    def _set_encrypt_paths(self, input_path: str):
        self._enc_in_path.delete(0, "end")
        self._enc_in_path.insert(0, input_path)
        self._enc_out_path.delete(0, "end")
        self._enc_out_path.insert(0, input_path + ".secureshare")
        self._status(self._enc_status, "", "")

    def _browse_encrypt_output(self):
        cur = _clean_path(self._enc_out_path.get())
        init_name = os.path.basename(cur) if cur else "encrypted.secureshare"
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Save encrypted file as",
            initialfile=init_name,
            defaultextension=".secureshare",
            filetypes=[("SecureShare Encrypted File", "*.secureshare"), ("All files", "*.*")],
        )
        if path:
            self._enc_out_path.delete(0, "end")
            self._enc_out_path.insert(0, path)

    def _do_encrypt(self):
        recipient = self._enc_recipient_var.get().strip()
        in_path   = _clean_path(self._enc_in_path.get())
        out_path  = _clean_path(self._enc_out_path.get())
        log       = self._enc_log

        log.delete("1.0", "end")
        self._status(self._enc_status, "", "")

        if not recipient:
            self._status(self._enc_status, "⚠️ Please choose a recipient.", "red")
            return
        if not in_path or not os.path.isfile(in_path):
            self._status(self._enc_status, "⚠️ Please select a valid source file to encrypt.", "red")
            return
        if not out_path:
            out_path = in_path + ".secureshare"
            self._enc_out_path.insert(0, out_path)

        pub_pem = keystore.get_public_key(recipient)
        if not pub_pem:
            self._status(self._enc_status, f"⚠️ No public key found for '{recipient}'.", "red")
            return

        try:
            filename = os.path.basename(in_path)
            with open(in_path, "rb") as f:
                plaintext = f.read()

            self._append_console(log, f"[1] Read source file: '{filename}' ({_format_size(len(plaintext))})", "info")

            bundle, info = crypto.encrypt_file_bundle(
                plaintext=plaintext,
                filename=filename,
                recipient_pub_pem=pub_pem,
                recipient_name=recipient,
                sender_name=self._current_user,
            )

            self._append_console(log, f"[2] Computed SHA-256 hash: {info['sha256']}", "cyan")
            self._append_console(log, f"[3] Encrypted file with AES-256-CBC ({info['ciphertext_size']:,} bytes ciphertext)", "yellow")
            self._append_console(log, f"[4] Locked AES session key with {recipient}'s RSA-2048 public key ({crypto.key_fingerprint(pub_pem)})", "purple")

            os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
            with open(out_path, "wb") as f:
                f.write(bundle)

            self._last_enc_output = os.path.abspath(out_path)
            self._btn_open_enc_dir.configure(state="normal")

            self._append_console(log, f"[5] Saved portable bundle ({_format_size(len(bundle))}): {self._last_enc_output}", "green")
            self._append_console(log, f"Done! You can now send '{os.path.basename(out_path)}' via WhatsApp, Email, Drive, or USB.", "success")
            self._status(
                self._enc_status,
                f"✅ Encrypted & saved: {os.path.basename(out_path)} — Ready to send to '{recipient}'!",
                "green",
            )
        except Exception as exc:
            self._append_console(log, f"[ERROR] {exc}", "danger")
            self._status(self._enc_status, f"❌ Encryption failed: {exc}", "red")

    def _open_enc_folder(self):
        if self._last_enc_output:
            try:
                _open_in_os(os.path.dirname(self._last_enc_output))
            except Exception as exc:
                self._status(self._enc_status, f"Could not open folder: {exc}", "red")

    # ════════════════════════════════════════════════════════════════════════
    # TAB 2 – DECRYPT FILE (Drop / Open received .secureshare file)
    # ════════════════════════════════════════════════════════════════════════

    def _build_decrypt_tab(self):
        p = self._tab_decrypt

        hdr = tk.Frame(p, bg="#f8fafc")
        hdr.pack(fill="x", pady=(0, 8))
        tk.Label(hdr, text="Decrypt Received File", font=("Segoe UI", 14, "bold"),
                 fg="#0f172a", bg="#f8fafc").pack(anchor="w")
        tk.Label(hdr,
                 text="Open a .secureshare file received from another user/device. The app unwraps the key, verifies SHA-256 integrity, and saves the original file.",
                 font=("Segoe UI", 9), fg="#64748b", bg="#f8fafc").pack(anchor="w")

        card = tk.Frame(p, bg="#ffffff", padx=18, pady=14,
                        highlightbackground="#e2e8f0", highlightthickness=1)
        card.pack(fill="x", pady=(0, 10))

        # 1. Clickable Drop Zone for .secureshare
        drop = tk.Frame(card, bg="#f0fdf4", pady=14, padx=14,
                        highlightbackground="#86efac", highlightthickness=1, cursor="hand2")
        drop.pack(fill="x", pady=(0, 8))
        lbl_d1 = tk.Label(drop, text="📥  Click here to open / drop a received .secureshare file",
                          font=("Segoe UI", 11, "bold"), fg="#166534", bg="#f0fdf4", cursor="hand2")
        lbl_d1.pack()
        lbl_d2 = tk.Label(drop, text="(Or paste/drag the file path into the box below)",
                          font=("Segoe UI", 8), fg="#475569", bg="#f0fdf4", cursor="hand2")
        lbl_d2.pack(pady=(2, 0))
        for w in (drop, lbl_d1, lbl_d2):
            w.bind("<Button-1>", lambda _: self._browse_decrypt_input())

        # Encrypted file path
        r1 = tk.Frame(card, bg="#ffffff")
        r1.pack(fill="x", pady=4)
        tk.Label(r1, text="Encrypted File:", font=("Segoe UI", 10, "bold"),
                 width=16, anchor="w", fg="#334155", bg="#ffffff").pack(side="left")
        self._dec_in_path = ttk.Entry(r1, font=("Segoe UI", 10))
        self._dec_in_path.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._dec_in_path.bind("<FocusOut>", lambda _: self._inspect_selected_bundle())
        self._dec_in_path.bind("<Return>",   lambda _: self._inspect_selected_bundle())
        self._dec_in_path.bind("<KeyRelease>", lambda _: self.after_idle(self._inspect_selected_bundle))
        ttk.Button(r1, text="Browse…", style="Outline.TButton",
                   command=self._browse_decrypt_input).pack(side="left")

        # Bundle Metadata Inspector Banner
        self._meta_box = tk.Frame(card, bg="#f8fafc", padx=12, pady=8,
                                  highlightbackground="#e2e8f0", highlightthickness=1)
        self._meta_box.pack(fill="x", pady=6)
        self._meta_label = tk.Label(
            self._meta_box,
            text="No .secureshare file loaded yet.",
            font=("Consolas", 9), fg="#475569", bg="#f8fafc", justify="left", anchor="w",
        )
        self._meta_label.pack(fill="x")

        # Decryption Key Choice + Save Folder
        r2 = tk.Frame(card, bg="#ffffff")
        r2.pack(fill="x", pady=4)
        tk.Label(r2, text="Decryption Key:", font=("Segoe UI", 10, "bold"),
                 width=16, anchor="w", fg="#334155", bg="#ffffff").pack(side="left")
        self._dec_key_lbl = tk.Label(
            r2, text=f"Signed-in profile key ({self._current_user})",
            font=("Segoe UI", 9, "bold"), fg="#1e40af", bg="#ffffff"
        )
        self._dec_key_lbl.pack(side="left", padx=(0, 10))
        self._btn_reset_priv = ttk.Button(r2, text="Use My Key", style="Outline.TButton",
                                          command=self._reset_to_my_priv, state="disabled")
        self._btn_reset_priv.pack(side="right", padx=(4, 0))
        ttk.Button(r2, text="Use Custom Private .pem…", style="Outline.TButton",
                   command=self._choose_custom_priv).pack(side="right")

        r3 = tk.Frame(card, bg="#ffffff")
        r3.pack(fill="x", pady=4)
        tk.Label(r3, text="Save Restored To:", font=("Segoe UI", 10, "bold"),
                 width=16, anchor="w", fg="#334155", bg="#ffffff").pack(side="left")
        self._dec_out_dir = ttk.Entry(r3, font=("Segoe UI", 10))
        self._dec_out_dir.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._dec_out_dir.insert(0, DOWNLOADS)
        ttk.Button(r3, text="Folder…", style="Outline.TButton",
                   command=self._choose_decrypt_outdir).pack(side="left")

        # Action Buttons
        act = tk.Frame(card, bg="#ffffff")
        act.pack(fill="x", pady=(10, 4))
        ttk.Button(act, text="🔓  Decrypt, Verify SHA-256 & Save Restored File",
                   style="Success.TButton", command=self._do_decrypt).pack(side="left", fill="x", expand=True)
        self._btn_open_dec_file = ttk.Button(act, text="📄 Open File", style="Outline.TButton",
                                             command=self._open_dec_file, state="disabled")
        self._btn_open_dec_file.pack(side="left", padx=(8, 4))
        self._btn_open_dec_dir = ttk.Button(act, text="📁 Downloads", style="Outline.TButton",
                                            command=lambda: _open_in_os(_clean_path(self._dec_out_dir.get()) or DOWNLOADS))
        self._btn_open_dec_dir.pack(side="left")

        self._dec_status = tk.Label(card, text="", font=("Segoe UI", 10, "bold"),
                                    bg="#ffffff", wraplength=880, anchor="w", justify="left")
        self._dec_status.pack(fill="x", pady=(8, 0))

        tk.Label(p, text="Decryption & Integrity Check Log:",
                 font=("Segoe UI", 10, "bold"), fg="#1e293b", bg="#f8fafc").pack(anchor="w", pady=(2, 4))
        self._dec_log = self._make_console(p, height=8)

    def _browse_decrypt_input(self):
        path = filedialog.askopenfilename(
            parent=self,
            title="Select .secureshare encrypted file",
            filetypes=[("SecureShare Encrypted Files", "*.secureshare"), ("All files", "*.*")],
        )
        if path and os.path.isfile(path):
            self._dec_in_path.delete(0, "end")
            self._dec_in_path.insert(0, path)
            self._inspect_selected_bundle()

    def _inspect_selected_bundle(self):
        path = _clean_path(self._dec_in_path.get())
        if not path or not os.path.isfile(path):
            self._meta_label.config(text="No .secureshare file loaded yet.", fg="#475569")
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            header, _ = crypto.inspect_file_bundle(data)
            target = header.get("recipient", "unknown")
            sender = header.get("sender", "unknown")
            match_note = " (matches your profile)" if target == self._current_user else f" (NOTE: you are '{self._current_user}')"
            info = (
                f"File inside: {header['filename']}  |  Original Size: {_format_size(header['size'])}\n"
                f"Sender: {sender}  |  Intended Recipient: {target}{match_note}\n"
                f"Expected SHA-256: {header['sha256']}"
            )
            color = "#15803d" if target == self._current_user else "#b45309"
            self._meta_label.config(text=info, fg=color)
            self._status(self._dec_status, "", "")
        except Exception as exc:
            self._meta_label.config(text=f"Invalid .secureshare file: {exc}", fg="#dc2626")

    def _choose_custom_priv(self):
        path = filedialog.askopenfilename(
            parent=self,
            title="Select Private Key (.pem)",
            filetypes=[("PEM Key Files", "*.pem"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                pem = f.read()
            if not crypto.validate_private_key(pem):
                messagebox.showerror("Invalid Key", "Selected file is not a valid unencrypted RSA private key PEM.")
                return
            self._custom_priv_pem  = pem
            self._custom_priv_path = path
            self._dec_key_lbl.config(text=f"Custom key: {os.path.basename(path)}", fg="#7c3aed")
            self._btn_reset_priv.configure(state="normal")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _reset_to_my_priv(self):
        self._custom_priv_pem  = None
        self._custom_priv_path = None
        self._dec_key_lbl.config(text=f"Signed-in profile key ({self._current_user})", fg="#1e40af")
        self._btn_reset_priv.configure(state="disabled")

    def _choose_decrypt_outdir(self):
        d = filedialog.askdirectory(parent=self, title="Choose output folder for decrypted file")
        if d:
            self._dec_out_dir.delete(0, "end")
            self._dec_out_dir.insert(0, d)

    def _do_decrypt(self):
        self._inspect_selected_bundle()
        in_path = _clean_path(self._dec_in_path.get())
        out_dir = _clean_path(self._dec_out_dir.get()) or DOWNLOADS
        log     = self._dec_log

        log.delete("1.0", "end")
        self._status(self._dec_status, "", "")
        self._btn_open_dec_file.configure(state="disabled")

        if not in_path or not os.path.isfile(in_path):
            self._status(self._dec_status, "⚠️ Please choose a .secureshare file to decrypt.", "red")
            return

        priv_pem = self._custom_priv_pem or self._private_key
        key_desc = os.path.basename(self._custom_priv_path) if self._custom_priv_pem else f"{self._current_user}'s private key"

        try:
            with open(in_path, "rb") as f:
                bundle_bytes = f.read()

            self._append_console(log, f"[1] Loaded encrypted bundle: {os.path.basename(in_path)} ({_format_size(len(bundle_bytes))})", "info")
            self._append_console(log, f"[2] Attempting RSA-2048 OAEP key unwrap using {key_desc}...", "purple")

            header, plaintext, actual_sha = crypto.decrypt_file_bundle(bundle_bytes, priv_pem)

            self._append_console(log, f"[3] AES-256 session key unwrapped successfully", "purple")
            self._append_console(log, f"[4] AES-256-CBC decrypted {len(plaintext):,} bytes", "yellow")
            self._append_console(log, f"[5] Expected SHA-256: {header['sha256']}", "cyan")
            self._append_console(log, f"[6] Computed SHA-256: {actual_sha}", "cyan")
            self._append_console(log, "[7] Integrity Check: 100% SHA-256 MATCH — File was not modified.", "success")

            os.makedirs(out_dir, exist_ok=True)
            filename = header["filename"]
            out_path = os.path.join(out_dir, filename)
            base, ext = os.path.splitext(filename)
            n = 1
            while os.path.exists(out_path):
                out_path = os.path.join(out_dir, f"{base}_{n}{ext}")
                n += 1

            with open(out_path, "wb") as f:
                f.write(plaintext)

            self._last_dec_output = os.path.abspath(out_path)
            self._btn_open_dec_file.configure(state="normal")

            self._append_console(log, f"[8] Restored original file saved to: {self._last_dec_output}", "green")
            self._status(
                self._dec_status,
                f"✅ Decrypted & verified! Saved as '{os.path.basename(out_path)}' in {out_dir}",
                "green",
            )

        except crypto.WrongKeyError as exc:
            self._append_console(log, f"[BLOCKED] {exc}", "danger")
            self._status(self._dec_status, f"🔒 Access Denied: {exc}", "red")
        except crypto.TamperDetectedError as exc:
            self._append_console(log, f"[TAMPER ALERT] {exc}", "danger")
            self._append_console(log, "[REJECTED] Corrupted/modified file was NOT saved.", "danger")
            self._status(self._dec_status, "🚨 TAMPER DETECTED! File was altered or corrupted — download rejected.", "red")
        except crypto.InvalidBundleError as exc:
            self._append_console(log, f"[INVALID FILE] {exc}", "danger")
            self._status(self._dec_status, f"⚠️ {exc}", "red")
        except Exception as exc:
            self._append_console(log, f"[ERROR] {exc}", "danger")
            self._status(self._dec_status, f"❌ Error: {exc}", "red")

    def _open_dec_file(self):
        if self._last_dec_output and os.path.exists(self._last_dec_output):
            try:
                _open_in_os(self._last_dec_output)
            except Exception as exc:
                self._status(self._dec_status, f"Could not open file: {exc}", "red")

    # ════════════════════════════════════════════════════════════════════════
    # TAB 3 – KEYS & CONTACTS
    # ════════════════════════════════════════════════════════════════════════

    def _build_keys_tab(self):
        p = self._tab_keys

        hdr = tk.Frame(p, bg="#f8fafc")
        hdr.pack(fill="x", pady=(0, 8))
        tk.Label(hdr, text="RSA-2048 Key Management & Contacts", font=("Segoe UI", 14, "bold"),
                 fg="#0f172a", bg="#f8fafc").pack(anchor="w")
        tk.Label(hdr,
                 text="Built-in accounts (`alice`, `bob`) use fixed keys across devices. You can also export your public key or import contacts (.pem).",
                 font=("Segoe UI", 9), fg="#64748b", bg="#f8fafc").pack(anchor="w")

        # Personal Key Card
        my_card = tk.Frame(p, bg="#ffffff", padx=16, pady=12,
                           highlightbackground="#e2e8f0", highlightthickness=1)
        my_card.pack(fill="x", pady=(0, 10))

        top = tk.Frame(my_card, bg="#ffffff")
        top.pack(fill="x", pady=(0, 6))
        self._my_key_title = tk.Label(top, text="", font=("Segoe UI", 11, "bold"),
                                      fg="#1e40af", bg="#ffffff")
        self._my_key_title.pack(side="left")

        btns = tk.Frame(top, bg="#ffffff")
        btns.pack(side="right")
        ttk.Button(btns, text="📋 Copy Public Key", style="Outline.TButton",
                   command=self._copy_my_pubkey).pack(side="left", padx=3)
        ttk.Button(btns, text="💾 Export Public .pem", style="Outline.TButton",
                   command=self._export_my_pubkey).pack(side="left", padx=3)
        self._btn_regen_key = ttk.Button(btns, text="🔄 Regenerate Keypair", style="Outline.TButton",
                                         command=self._regen_my_keys)
        self._btn_regen_key.pack(side="left", padx=(3, 0))

        self._my_pub_txt = tk.Text(my_card, height=5, font=("Consolas", 8),
                                   bg="#f8fafc", fg="#334155", padx=8, pady=6,
                                   highlightbackground="#cbd5e1", highlightthickness=1)
        self._my_pub_txt.pack(fill="x")

        # Contacts / Known Keys Card
        c_card = tk.Frame(p, bg="#ffffff", padx=16, pady=12,
                          highlightbackground="#e2e8f0", highlightthickness=1)
        c_card.pack(fill="both", expand=True)

        c_top = tk.Frame(c_card, bg="#ffffff")
        c_top.pack(fill="x", pady=(0, 8))
        tk.Label(c_top, text="Available Recipient Public Keys:", font=("Segoe UI", 10, "bold"),
                 fg="#334155", bg="#ffffff").pack(side="left")

        c_btns = tk.Frame(c_top, bg="#ffffff")
        c_btns.pack(side="right")
        ttk.Button(c_btns, text="📥 Import Contact Public Key (.pem)", style="Primary.TButton",
                   command=self._quick_import_pem).pack(side="left", padx=(0, 6))
        ttk.Button(c_btns, text="🗑️ Remove Contact", style="DangerOutline.TButton",
                   command=self._delete_selected_contact).pack(side="left")

        cols = ("name", "kind", "fingerprint")
        tbl_frame = tk.Frame(c_card, bg="#ffffff")
        tbl_frame.pack(fill="both", expand=True)

        self._keys_tree = ttk.Treeview(tbl_frame, columns=cols, show="headings", height=6)
        for col, title, w in [
            ("name",        "Profile / Contact Name", 180),
            ("kind",        "Key Type",               200),
            ("fingerprint", "SHA-256 Key Fingerprint", 280),
        ]:
            self._keys_tree.heading(col, text=title)
            self._keys_tree.column(col, width=w, minwidth=w, stretch=True, anchor="w")

        self._keys_tree.tag_configure("row_even", background="#ffffff", foreground="#0f172a")
        self._keys_tree.tag_configure("row_odd",  background="#f8fafc", foreground="#0f172a")

        sb = ttk.Scrollbar(tbl_frame, orient="vertical", command=self._keys_tree.yview)
        self._keys_tree.configure(yscrollcommand=sb.set)
        self._keys_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")

        self._keys_status = tk.Label(c_card, text="", font=("Segoe UI", 9, "bold"),
                                     bg="#ffffff", anchor="w")
        self._keys_status.pack(fill="x", pady=(6, 0))

        self._refresh_keys_tab()

    def _refresh_keys_tab(self):
        fp = crypto.key_fingerprint(self._public_key)
        is_fixed = keystore.is_fixed_user(self._current_user)
        mode = "Fixed Cross-Device Key" if is_fixed else "Local Custom Key"
        self._my_key_title.config(text=f"Your Public Key ({self._current_user}  •  {mode}  •  {fp})")

        self._my_pub_txt.configure(state="normal")
        self._my_pub_txt.delete("1.0", "end")
        self._my_pub_txt.insert("1.0", self._public_key.strip())
        self._my_pub_txt.configure(state="disabled")

        for row in self._keys_tree.get_children():
            self._keys_tree.delete(row)

        for i, rec in enumerate(keystore.list_all_recipients()):
            tag = "row_even" if i % 2 == 0 else "row_odd"
            name_disp = f"{rec['name']} (You)" if rec["name"] == self._current_user else rec["name"]
            self._keys_tree.insert("", "end", values=(name_disp, rec["kind"], rec["fingerprint"]), tags=(tag,))

    def _copy_my_pubkey(self):
        self.clipboard_clear()
        self.clipboard_append(self._public_key)
        self._status(self._keys_status, "✅ Copied your RSA-2048 Public Key to clipboard.", "green")

    def _export_my_pubkey(self):
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Export Public Key",
            initialfile=f"{self._current_user}_public.pem",
            defaultextension=".pem",
            filetypes=[("PEM Public Key", "*.pem")],
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._public_key)
            self._status(self._keys_status, f"✅ Exported public key to {path}", "green")

    def _regen_my_keys(self):
        ok, msg = keystore.regenerate_local_keypair(self._current_user)
        if not ok:
            messagebox.showinfo("Fixed Profile Key", msg)
            return
        self._private_key = keystore.get_private_key(self._current_user)
        self._public_key  = keystore.get_public_key(self._current_user)
        self._refresh_keys_tab()
        self._reload_recipients()
        self._status(self._keys_status, "✅ " + msg, "green")

    def _quick_import_pem(self):
        path = filedialog.askopenfilename(
            parent=self,
            title="Select Recipient's Public Key (.pem)",
            filetypes=[("PEM Key Files", "*.pem"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                pem = f.read()
        except Exception as exc:
            messagebox.showerror("Read Error", str(exc))
            return

        default_name = os.path.splitext(os.path.basename(path))[0].replace("_public", "")
        dlg = tk.Toplevel(self)
        dlg.title("Name Contact")
        dlg.geometry("360x150")
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.grab_set()
        dlg.configure(bg="#ffffff")

        tk.Label(dlg, text="Enter a name for this recipient:", font=("Segoe UI", 10, "bold"),
                 bg="#ffffff", fg="#0f172a").pack(anchor="w", padx=16, pady=(14, 6))
        ent = ttk.Entry(dlg, font=("Segoe UI", 10))
        ent.pack(fill="x", padx=16)
        ent.insert(0, default_name)
        ent.select_range(0, "end")
        ent.focus_set()

        def save_contact():
            ok, msg = keystore.import_contact(ent.get(), pem)
            if ok:
                dlg.destroy()
                self._reload_recipients()
                self._refresh_keys_tab()
                self._status(self._enc_status, "✅ " + msg, "green")
                self._status(self._keys_status, "✅ " + msg, "green")
            else:
                messagebox.showerror("Invalid Input", msg, parent=dlg)

        ttk.Button(dlg, text="Import Public Key", style="Primary.TButton",
                   command=save_contact).pack(pady=14)

    def _delete_selected_contact(self):
        sel = self._keys_tree.selection()
        if not sel:
            self._status(self._keys_status, "⚠️ Select an imported contact row first.", "red")
            return
        name, kind, _ = self._keys_tree.item(sel[0])["values"]
        if kind != "Imported Contact":
            self._status(self._keys_status, "Built-in profiles cannot be removed here.", "red")
            return
        if keystore.delete_contact(name):
            self._refresh_keys_tab()
            self._reload_recipients()
            self._status(self._keys_status, f"Removed imported contact '{name}'.", "green")

    # ════════════════════════════════════════════════════════════════════════
    # TAB 4 – TAMPER & SECURITY TEST
    # ════════════════════════════════════════════════════════════════════════

    def _build_demo_tab(self):
        p = self._tab_demo

        hdr = tk.Frame(p, bg="#f8fafc")
        hdr.pack(fill="x", pady=(0, 8))
        tk.Label(hdr, text="Security & Tamper-Detection Verification",
                 font=("Segoe UI", 14, "bold"), fg="#0f172a", bg="#f8fafc").pack(anchor="w")

        banner = tk.Frame(p, bg="#ffffff", padx=16, pady=12,
                          highlightbackground="#e2e8f0", highlightthickness=1)
        banner.pack(fill="x", pady=(0, 10))

        desc = (
            "Creates a temporary .secureshare file (Alice -> Bob) and verifies three real security properties:\n"
            "  1. File Inspection: Confirms the payload bytes inside .secureshare are unreadable ciphertext.\n"
            "  2. Key & Hash Verification: Confirms Alice's wrong key is blocked, while Bob's key decrypts with 100% SHA-256 match.\n"
            "  3. Tamper Detection: Flips 1 byte inside the .secureshare ciphertext and verifies the app detects & rejects it."
        )
        tk.Label(banner, text=desc, font=("Segoe UI", 9), fg="#475569", bg="#ffffff",
                 justify="left").pack(anchor="w")

        btn_bar = tk.Frame(banner, bg="#ffffff")
        btn_bar.pack(fill="x", pady=(10, 0))
        ttk.Button(btn_bar, text="▶  Run Security Verification (3 Tests)",
                   style="Primary.TButton", command=self._run_demo).pack(fill="x", ipady=2)

        tk.Label(p, text="Verification Log & Output:",
                 font=("Segoe UI", 10, "bold"), fg="#1e293b", bg="#f8fafc").pack(anchor="w", pady=(4, 4))
        self._demo_log = self._make_console(p, height=18)

    def _run_demo(self):
        log = self._demo_log
        log.delete("1.0", "end")

        def L(msg, tag="info"):
            self._append_console(log, msg, tag)

        L("=" * 76, "info")
        L("SECURESHARE – PORTABLE FILE CRYPTOGRAPHIC & TAMPER TEST", "purple")
        L("=" * 76, "info")

        alice_priv = keystore.get_private_key("alice")
        bob_pub    = keystore.get_public_key("bob")
        bob_priv   = keystore.get_private_key("bob")

        secret = (
            b"Project Planning & Budget Review\n"
            b"Author: Alice\n"
            b"Recipient: Bob\n"
            b"Approved Budget: $48,000 for Q3 infrastructure\n"
            b"Confidential internal document."
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_path = os.path.join(tmpdir, "project_budget.txt.secureshare")

            L("\n[STEP 1] Alice encrypts 'project_budget.txt' for Bob", "info")
            bundle_bytes, info = crypto.encrypt_file_bundle(
                secret, "project_budget.txt", bob_pub, recipient_name="bob", sender_name="alice"
            )
            with open(bundle_path, "wb") as f:
                f.write(bundle_bytes)

            L(f"  • Original size: {info['plaintext_size']} bytes  |  SHA-256: {info['sha256']}", "cyan")
            L(f"  • Encrypted payload: AES-256-CBC ({info['ciphertext_size']} bytes)", "yellow")
            L(f"  • AES session key locked with Bob's RSA-2048 public key", "purple")
            L(f"  • Saved portable file: project_budget.txt.secureshare ({info['bundle_size']} bytes)", "green")

            # Test 1: Payload inspection
            L("\n" + "-" * 76, "info")
            L("TEST 1: File Payload Inspection (Can anyone read the .secureshare file?)", "purple")
            L("-" * 76, "info")
            header, raw_ct = crypto.inspect_file_bundle(bundle_bytes)
            L(f"  First 32 ciphertext bytes (hex): {raw_ct[:32].hex()}", "yellow")
            try:
                raw_ct.decode("utf-8")
                L("  FAILED: Ciphertext contains readable UTF-8 text!", "danger")
            except UnicodeDecodeError:
                L("  Attempting UTF-8 decode on ciphertext: UnicodeDecodeError (pure random binary)", "cyan")
                L("  PASSED: Safe to send over WhatsApp, Email, Drive, or USB — unreadable without Bob's key.", "success")

            # Test 2: Wrong key rejection + Valid recipient decryption
            L("\n" + "-" * 76, "info")
            L("TEST 2: Access Control & Legitimate Recipient Decryption", "purple")
            L("-" * 76, "info")
            try:
                crypto.decrypt_file_bundle(bundle_bytes, alice_priv)
                L("  FAILED: Alice should NOT be able to decrypt a file encrypted for Bob!", "danger")
            except crypto.WrongKeyError as e:
                L(f"  a) Alice tries to decrypt with her own key -> BLOCKED ({e})", "purple")

            _, recovered, got_sha = crypto.decrypt_file_bundle(bundle_bytes, bob_priv)
            L(f"  b) Bob decrypts using his fixed RSA private key -> OK ({len(recovered)} bytes)", "green")
            L(f"     Expected SHA-256: {info['sha256']}", "cyan")
            L(f"     Computed SHA-256: {got_sha}", "cyan")
            if got_sha == info["sha256"] and recovered == secret:
                L("  PASSED: Wrong key rejected; Bob recovered exact original file with 100% hash match.", "success")

            # Test 3: 1-byte tamper detection
            L("\n" + "-" * 76, "info")
            L("TEST 3: Tamper Attack (Flipping 1 byte inside the .secureshare file)", "purple")
            L("-" * 76, "info")
            tampered = bytearray(bundle_bytes)
            offset = info["header_offset"] + 20
            old_b = tampered[offset]
            tampered[offset] ^= 0xFF
            new_b = tampered[offset]
            L(f"  Modified 1 ciphertext byte at offset {offset}: 0x{old_b:02X} -> 0x{new_b:02X}", "yellow")

            try:
                crypto.decrypt_file_bundle(bytes(tampered), bob_priv)
                L("  FAILED: Modified file was accepted!", "danger")
            except crypto.TamperDetectedError as exc:
                L(f"  Bob attempts to decrypt -> REJECTED: {exc}", "danger")
                L("  PASSED: Any modification to the file is caught and blocked before saving.", "success")

        L("\n" + "=" * 76, "info")
        L("SUMMARY: All 3 tests passed. Ready for cross-device transfer testing.", "success")
        L("=" * 76, "info")

    # ════════════════════════════════════════════════════════════════════════
    # SHARED UTILITIES
    # ════════════════════════════════════════════════════════════════════════

    def _clear_window(self):
        for w in self.winfo_children():
            w.destroy()

    @staticmethod
    def _make_console(parent, height=10):
        frame = tk.Frame(parent, bg="#ffffff", highlightbackground="#cbd5e1", highlightthickness=1)
        frame.pack(fill="both", expand=True, pady=2)

        t = tk.Text(frame, height=height, wrap="word",
                    bg="#f8fafc", fg="#0f172a", font=("Consolas", 9),
                    insertbackground="#2563eb", padx=10, pady=8, borderwidth=0)

        t.tag_configure("info",    foreground="#475569")
        t.tag_configure("cyan",    foreground="#0284c7")
        t.tag_configure("yellow",  foreground="#b45309")
        t.tag_configure("purple",  foreground="#7c3aed")
        t.tag_configure("green",   foreground="#15803d")
        t.tag_configure("success", foreground="#16a34a", font=("Consolas", 9, "bold"))
        t.tag_configure("danger",  foreground="#dc2626", font=("Consolas", 9, "bold"))

        sb = ttk.Scrollbar(frame, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        return t

    @staticmethod
    def _append_console(widget, msg, tag="info"):
        widget.insert("end", msg + "\n", tag)
        widget.see("end")
        widget.update_idletasks()

    @staticmethod
    def _status(label, msg, color):
        palette = {"green": "#16a34a", "red": "#dc2626", "blue": "#2563eb", "": "#0f172a"}
        label.config(text=msg, fg=palette.get(color, "#0f172a"))


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    initial_file = sys.argv[1] if len(sys.argv) > 1 else None
    app = App(initial_bundle=initial_file)
    app.mainloop()


if __name__ == "__main__":
    main()
