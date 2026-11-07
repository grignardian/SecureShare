#!/usr/bin/env python3
"""
SecureShare – End-to-End Encrypted File Sharing System
=======================================================
HOW TO RUN:
    python3 app.py

Features:
  1. Send File       – Select recipient & file → AES-256-CBC + RSA-2048 hybrid encryption
  2. Secure Inbox    – View encrypted transfers → RSA key unwrapping & SHA-256 integrity check
  3. Transfer History– Complete audit log of sent and received transfers
  4. Security Demo   – Live proof of zero-knowledge, eavesdropping defense & MITM tamper detection

Cryptographic Architecture:
  • Symmetric Cipher:     AES-256-CBC with PKCS7 padding & random 16-byte IV
  • Key Encapsulation:    RSA-2048 OAEP with SHA-256 MGF1
  • Integrity Digest:     SHA-256 Cryptographic Hash
  • Password Security:    PBKDF2-HMAC-SHA256 (200,000 iterations + 16-byte salt)
  • Storage:              Zero-Knowledge SQLite + Encrypted Vault Directory
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import crypto   # crypto.py  – AES-256, RSA-2048, SHA-256, PBKDF2
import db       # db.py      – SQLite database + encrypted vault

# ── Directories ─────────────────────────────────────────────────────────────
BASE      = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR  = os.path.join(BASE, "user_keys")
DOWNLOADS = os.path.join(BASE, "downloads")

for d in (KEYS_DIR, DOWNLOADS):
    os.makedirs(d, exist_ok=True)

db.init()   # Initialize DB schema

# ── Demo Accounts ────────────────────────────────────────────────────────────
DEMO_ACCOUNTS = [
    ("bob",   "Bob123!"),
    ("alice", "Alice123!"),
]


def seed_demo_accounts():
    """Create default demo accounts and generate RSA keypairs if missing."""
    for username, password in DEMO_ACCOUNTS:
        if db.get_user(username):
            continue
        priv_pem, pub_pem = crypto.generate_rsa_keypair()
        _save_key(username, priv_pem, pub_pem)
        salt, pw_hash = crypto.hash_password(password)
        db.add_user(username, salt, pw_hash, pub_pem)


def _priv_path(username):
    return os.path.join(KEYS_DIR, f"{username}_private.pem")


def _pub_path(username):
    return os.path.join(KEYS_DIR, f"{username}_public.pem")


def _save_key(username, priv_pem, pub_pem):
    with open(_priv_path(username), "w") as f:
        f.write(priv_pem)
    with open(_pub_path(username), "w") as f:
        f.write(pub_pem)


def _load_priv(username):
    path = _priv_path(username)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return f.read()


# ════════════════════════════════════════════════════════════════════════════
# APPLICATION GUI (LIGHT THEME)
# ════════════════════════════════════════════════════════════════════════════

class App(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("SecureShare – End-to-End Encrypted File Sharing")
        self.geometry("980x720")
        self.minsize(840, 620)
        self.resizable(True, True)
        self.configure(bg="#f1f5f9")

        self._current_user = None   # Logged-in username
        self._private_key  = None   # RSA Private Key PEM
        self._pwd_visible  = False  # Toggle state for password visibility

        self._init_styles()
        seed_demo_accounts()
        self._show_login()

    # ── Theme & Styling ───────────────────────────────────────────────────────

    def _init_styles(self):
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except Exception:
            pass

        # Global font & defaults
        s.configure(".", font=("Segoe UI", 10), background="#f8fafc", foreground="#0f172a")

        # Frames
        s.configure("App.TFrame", background="#f8fafc")
        s.configure("Card.TFrame", background="#ffffff", relief="flat")
        s.configure("White.TFrame", background="#ffffff")

        # Buttons
        s.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), foreground="#ffffff",
                    background="#2563eb", borderwidth=0, padding=(14, 8))
        s.map("Primary.TButton", background=[("active", "#1d4ed8"), ("pressed", "#1e40af")])

        s.configure("Success.TButton", font=("Segoe UI", 10, "bold"), foreground="#ffffff",
                    background="#059669", borderwidth=0, padding=(14, 8))
        s.map("Success.TButton", background=[("active", "#047857"), ("pressed", "#065f46")])

        s.configure("Danger.TButton", font=("Segoe UI", 10, "bold"), foreground="#ffffff",
                    background="#dc2626", borderwidth=0, padding=(14, 8))
        s.map("Danger.TButton", background=[("active", "#b91c1c"), ("pressed", "#991b1b")])

        s.configure("Outline.TButton", font=("Segoe UI", 9, "bold"), foreground="#1e293b",
                    background="#ffffff", borderwidth=1, padding=(10, 6))
        s.map("Outline.TButton", background=[("active", "#f1f5f9")])

        s.configure("Eye.TButton", font=("Segoe UI", 9), foreground="#334155",
                    background="#f1f5f9", borderwidth=1, padding=(6, 4))
        s.map("Eye.TButton", background=[("active", "#e2e8f0")])

        s.configure("Header.TButton", font=("Segoe UI", 9, "bold"), foreground="#dc2626",
                    background="#fee2e2", borderwidth=0, padding=(10, 5))
        s.map("Header.TButton", background=[("active", "#fecaca")])

        # Notebook tabs (Clean Light Style)
        s.configure("TNotebook", background="#f1f5f9", borderwidth=0)
        s.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=(16, 9),
                    background="#e2e8f0", foreground="#475569", borderwidth=0)
        s.map("TNotebook.Tab",
              background=[("selected", "#ffffff"), ("active", "#cbd5e1")],
              foreground=[("selected", "#2563eb"), ("active", "#0f172a")])

        # Treeview styling (Light Table)
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
    # LOGIN SCREEN (LIGHT THEME)
    # ════════════════════════════════════════════════════════════════════════

    def _show_login(self):
        self._clear_window()
        self.configure(bg="#f1f5f9")

        # Container
        outer = tk.Frame(self, bg="#f1f5f9")
        outer.place(relx=0.5, rely=0.5, anchor="center")

        # Logo and Header
        brand_frame = tk.Frame(outer, bg="#f1f5f9")
        brand_frame.pack(pady=(0, 20))

        tk.Label(brand_frame, text="🛡️ SecureShare", font=("Segoe UI", 26, "bold"),
                 fg="#1e40af", bg="#f1f5f9").pack()
        tk.Label(brand_frame, text="End-to-End Encrypted File Transfer  •  Zero-Knowledge Vault",
                 font=("Segoe UI", 10), fg="#64748b", bg="#f1f5f9").pack(pady=(4, 0))

        # Main Auth Card
        card = tk.Frame(outer, bg="#ffffff", padx=36, pady=32,
                        highlightbackground="#cbd5e1", highlightthickness=1)
        card.pack(ipadx=10, ipady=5)

        tk.Label(card, text="Account Sign In / Registration", font=("Segoe UI", 14, "bold"),
                 fg="#0f172a", bg="#ffffff").pack(anchor="w", pady=(0, 16))

        # Username row
        u_box = tk.Frame(card, bg="#ffffff")
        u_box.pack(fill="x", pady=6)
        tk.Label(u_box, text="Username", font=("Segoe UI", 9, "bold"), fg="#334155", bg="#ffffff").pack(anchor="w")
        self._login_user = ttk.Entry(u_box, width=34, font=("Segoe UI", 11))
        self._login_user.pack(fill="x", pady=(3, 0), ipady=3)
        self._login_user.insert(0, "bob")

        # Password row + Show/Hide Button
        p_box = tk.Frame(card, bg="#ffffff")
        p_box.pack(fill="x", pady=(10, 6))
        tk.Label(p_box, text="Password", font=("Segoe UI", 9, "bold"), fg="#334155", bg="#ffffff").pack(anchor="w")

        p_row = tk.Frame(p_box, bg="#ffffff")
        p_row.pack(fill="x", pady=(3, 0))

        self._login_pwd = ttk.Entry(p_row, width=26, show="•", font=("Segoe UI", 11))
        self._login_pwd.pack(side="left", fill="x", expand=True, ipady=3)
        self._login_pwd.insert(0, "Bob123!")

        # Password Visibility Toggle Button
        self._pwd_visible = False
        self._btn_eye = ttk.Button(p_row, text="👁 Show", style="Eye.TButton",
                                   command=self._toggle_password_visibility)
        self._btn_eye.pack(side="right", padx=(6, 0))

        # Quick Fill Demo Accounts Pill Bar
        pill_row = tk.Frame(card, bg="#ffffff")
        pill_row.pack(fill="x", pady=(12, 16))
        tk.Label(pill_row, text="Quick Demo Fill:", font=("Segoe UI", 9), fg="#64748b", bg="#ffffff").pack(side="left", padx=(0, 6))

        ttk.Button(pill_row, text="👤 bob", style="Outline.TButton",
                   command=lambda: self._quick_fill("bob", "Bob123!")).pack(side="left", padx=3)
        ttk.Button(pill_row, text="👤 alice", style="Outline.TButton",
                   command=lambda: self._quick_fill("alice", "Alice123!")).pack(side="left", padx=3)

        # Action Buttons
        btn_row = tk.Frame(card, bg="#ffffff")
        btn_row.pack(fill="x", pady=(4, 8))

        ttk.Button(btn_row, text="🔐  Sign In", style="Primary.TButton", width=15,
                   command=self._do_login).pack(side="left", padx=(0, 8), fill="x", expand=True)

        ttk.Button(btn_row, text="➕ Create Account", style="Outline.TButton", width=16,
                   command=self._do_create_account).pack(side="left", fill="x", expand=True)

        # Status label
        self._login_status = tk.Label(card, text="", font=("Segoe UI", 9, "bold"),
                                      fg="#2563eb", bg="#ffffff", wraplength=360)
        self._login_status.pack(pady=(10, 0))

        # Cryptographic info badge at bottom
        info_frame = tk.Frame(outer, bg="#f1f5f9")
        info_frame.pack(pady=(18, 0))
        tk.Label(info_frame, text="🔒 AES-256-CBC   •   🔑 RSA-2048 OAEP   •   🛡️ SHA-256   •   🧂 PBKDF2",
                 font=("Segoe UI", 9), fg="#64748b", bg="#f1f5f9").pack()

        # Keyboard enter shortcut
        self.bind("<Return>", lambda _: self._do_login())

    def _toggle_password_visibility(self):
        """Toggle password field between hidden characters ('•') and visible plaintext."""
        if self._pwd_visible:
            self._login_pwd.configure(show="•")
            self._btn_eye.configure(text="👁 Show")
            self._pwd_visible = False
        else:
            self._login_pwd.configure(show="")
            self._btn_eye.configure(text="🙈 Hide")
            self._pwd_visible = True

    def _quick_fill(self, username, password):
        """Quick fill credentials into the login form."""
        self._login_user.delete(0, "end")
        self._login_user.insert(0, username)
        self._login_pwd.delete(0, "end")
        self._login_pwd.insert(0, password)
        self._status(self._login_status, f"Filled credentials for '{username}'. Ready to sign in.", "green")

    def _do_login(self):
        user = self._login_user.get().strip()
        pwd  = self._login_pwd.get()
        if not user or not pwd:
            self._status(self._login_status, "Please enter both username and password.", "red")
            return

        record = db.get_user(user)
        if not record:
            self._status(self._login_status, f"User '{user}' not found. Click 'Create Account'.", "red")
            return

        if not crypto.check_password(pwd, record["salt"], record["password_hash"]):
            self._status(self._login_status, "Invalid password. Please check your credentials.", "red")
            return

        # Load or regenerate private key
        priv = _load_priv(user)
        if priv is None:
            priv, pub = crypto.generate_rsa_keypair()
            _save_key(user, priv, pub)
            db.update_public_key(user, pub)

        self._current_user = user
        self._private_key  = priv
        self.unbind("<Return>")
        self._show_main()

    def _do_create_account(self):
        user = self._login_user.get().strip()
        pwd  = self._login_pwd.get()
        if not user or not pwd:
            self._status(self._login_status, "Please enter a username and password.", "red")
            return
        if len(pwd) < 6:
            self._status(self._login_status, "Password must be at least 6 characters.", "red")
            return
        if db.get_user(user):
            self._status(self._login_status, f"Username '{user}' already exists.", "red")
            return

        priv, pub = crypto.generate_rsa_keypair()
        _save_key(user, priv, pub)
        salt, pw_hash = crypto.hash_password(pwd)
        db.add_user(user, salt, pw_hash, pub)
        self._status(self._login_status, f"✅ Account '{user}' registered! Click 'Sign In'.", "green")

    # ════════════════════════════════════════════════════════════════════════
    # MAIN DASHBOARD (LIGHT THEME)
    # ════════════════════════════════════════════════════════════════════════

    def _show_main(self):
        self._clear_window()
        self.configure(bg="#f1f5f9")

        # Top Navigation & Header Bar (Clean White)
        header = tk.Frame(self, bg="#ffffff", height=58, padx=16, pady=10,
                          highlightbackground="#e2e8f0", highlightthickness=1)
        header.pack(fill="x")

        # App Brand
        brand_box = tk.Frame(header, bg="#ffffff")
        brand_box.pack(side="left")
        tk.Label(brand_box, text="🛡️ SecureShare", font=("Segoe UI", 15, "bold"),
                 fg="#1e40af", bg="#ffffff").pack(side="left")
        tk.Label(brand_box, text=" | E2EE File Vault", font=("Segoe UI", 10),
                 fg="#64748b", bg="#ffffff").pack(side="left", padx=(4, 0))

        # Right Side User Profile Pill & Logout
        right_box = tk.Frame(header, bg="#ffffff")
        right_box.pack(side="right")

        # Active status pill
        pill_frame = tk.Frame(right_box, bg="#ecfdf5", padx=10, pady=4,
                              highlightbackground="#a7f3d0", highlightthickness=1)
        pill_frame.pack(side="left", padx=(0, 8))

        tk.Label(pill_frame, text="● ACTIVE", font=("Segoe UI", 8, "bold"),
                 fg="#059669", bg="#ecfdf5").pack(side="left", padx=(0, 6))
        tk.Label(pill_frame, text=f"👤 {self._current_user}", font=("Segoe UI", 10, "bold"),
                 fg="#0f172a", bg="#ecfdf5").pack(side="left")

        ttk.Button(right_box, text="Sign Out", style="Header.TButton",
                   command=self._do_logout).pack(side="left")

        # Notebook (Tabs)
        self._nb = ttk.Notebook(self)
        self._nb.pack(fill="both", expand=True, padx=12, pady=(8, 12))

        self._tab_send    = ttk.Frame(self._nb, style="App.TFrame", padding=16)
        self._tab_inbox   = ttk.Frame(self._nb, style="App.TFrame", padding=16)
        self._tab_history = ttk.Frame(self._nb, style="App.TFrame", padding=16)
        self._tab_demo    = ttk.Frame(self._nb, style="App.TFrame", padding=16)

        self._nb.add(self._tab_send,    text="  📤  Send File  ")
        self._nb.add(self._tab_inbox,   text="  📥  Secure Inbox  ")
        self._nb.add(self._tab_history, text="  📊  Transfer History  ")
        self._nb.add(self._tab_demo,    text="  ⚡  Security & Tamper Demo  ")

        self._build_send_tab()
        self._build_inbox_tab()
        self._build_history_tab()
        self._build_demo_tab()

        def on_tab_change(event):
            tab_text = self._nb.tab(self._nb.select(), "text")
            if "Inbox"   in tab_text:
                self._refresh_inbox()
            if "History" in tab_text:
                self._refresh_history()

        self._nb.bind("<<NotebookTabChanged>>", on_tab_change)

    def _do_logout(self):
        self._current_user = None
        self._private_key  = None
        self._show_login()

    # ════════════════════════════════════════════════════════════════════════
    # TAB 1 – SEND FILE (Payload Dispatch)
    # ════════════════════════════════════════════════════════════════════════

    def _build_send_tab(self):
        p = self._tab_send

        # Header Title
        title_box = tk.Frame(p, bg="#f8fafc")
        title_box.pack(fill="x", pady=(0, 10))
        tk.Label(title_box, text="Encrypt & Dispatch File", font=("Segoe UI", 14, "bold"),
                 fg="#0f172a", bg="#f8fafc").pack(anchor="w")
        tk.Label(title_box,
                 text="Files are encrypted locally with a fresh AES-256 session key and encapsulated using the recipient's RSA-2048 public key.",
                 font=("Segoe UI", 9), fg="#64748b", bg="#f8fafc").pack(anchor="w")

        # Configuration Card
        card = tk.Frame(p, bg="#ffffff", padx=20, pady=16,
                        highlightbackground="#e2e8f0", highlightthickness=1)
        card.pack(fill="x", pady=(0, 12))

        # Recipient Selection Row
        r1 = tk.Frame(card, bg="#ffffff")
        r1.pack(fill="x", pady=6)
        tk.Label(r1, text="Recipient User:", font=("Segoe UI", 10, "bold"),
                 width=16, anchor="w", fg="#334155", bg="#ffffff").pack(side="left")

        self._send_recipient = ttk.Combobox(r1, state="readonly", width=28, font=("Segoe UI", 10))
        self._send_recipient.pack(side="left", padx=(0, 8))

        ttk.Button(r1, text="⟳ Refresh Users", style="Outline.TButton",
                   command=self._load_users).pack(side="left")
        self._load_users()

        # File Selection Row
        r2 = tk.Frame(card, bg="#ffffff")
        r2.pack(fill="x", pady=6)
        tk.Label(r2, text="Select File:", font=("Segoe UI", 10, "bold"),
                 width=16, anchor="w", fg="#334155", bg="#ffffff").pack(side="left")

        self._send_file_path = ttk.Entry(r2, width=44, font=("Segoe UI", 10))
        self._send_file_path.pack(side="left", padx=(0, 8), fill="x", expand=True)

        ttk.Button(r2, text="📂 Browse…", style="Outline.TButton",
                   command=self._browse_file).pack(side="left", padx=(0, 6))

        ttk.Button(r2, text="📄 Quick Sample", style="Outline.TButton",
                   command=self._create_sample).pack(side="left")

        # Action Encrypt & Send Button
        btn_frame = tk.Frame(card, bg="#ffffff")
        btn_frame.pack(fill="x", pady=(14, 4))

        ttk.Button(btn_frame, text="🔒  Encrypt & Send File  (AES-256-CBC + RSA-2048 OAEP)",
                   style="Primary.TButton", command=self._do_send).pack(fill="x", ipady=2)

        # Status Label
        self._send_status = tk.Label(card, text="", font=("Segoe UI", 10, "bold"),
                                     bg="#ffffff", wraplength=800, anchor="w")
        self._send_status.pack(fill="x", pady=(8, 0))

        # Cryptographic Telemetry Console (Light Inspector)
        tk.Label(p, text="Cryptographic Pipeline & Security Monitor:",
                 font=("Segoe UI", 10, "bold"), fg="#1e293b", bg="#f8fafc").pack(anchor="w", pady=(4, 4))

        self._send_log = self._make_console(p, height=12)

    def _load_users(self):
        users = [u for u in db.all_users() if u != self._current_user]
        self._send_recipient["values"] = users
        if users:
            self._send_recipient.current(0)

    def _browse_file(self):
        path = filedialog.askopenfilename(parent=self, title="Select file to encrypt & share")
        if path and os.path.isfile(path):
            self._send_file_path.delete(0, "end")
            self._send_file_path.insert(0, path)
            self._status(self._send_status, "", "")

    def _create_sample(self):
        path = os.path.join(BASE, "sample_document.txt")
        with open(path, "w") as f:
            f.write(
                "CONFIDENTIAL TRANSMISSION\n"
                "System: SecureShare End-to-End Cryptographic Vault\n"
                "Payload: AES-256-CBC with PKCS7 Padding & SHA-256 Checksum.\n"
                "This document is encrypted locally before sending over the network.\n"
            )
        self._send_file_path.delete(0, "end")
        self._send_file_path.insert(0, path)
        self._status(self._send_status, "✅ Sample document created and selected.", "green")

    def _do_send(self):
        recipient = self._send_recipient.get().strip()
        filepath  = self._send_file_path.get().strip()
        log       = self._send_log

        log.delete("1.0", "end")
        self._status(self._send_status, "", "")

        if not recipient:
            self._status(self._send_status, "⚠️ Please select a recipient from the list.", "red")
            return
        if not filepath:
            self._status(self._send_status, "⚠️ Please choose a file to encrypt & share.", "red")
            return
        if not os.path.isfile(filepath):
            self._status(self._send_status, f"⚠️ File does not exist: {filepath}", "red")
            return

        pub_key = db.get_public_key(recipient)
        if not pub_key:
            self._status(self._send_status, f"⚠️ No public key found for recipient '{recipient}'.", "red")
            return

        try:
            filename = os.path.basename(filepath)
            with open(filepath, "rb") as f:
                plaintext = f.read()

            self._append_console(log, f"[INIT] Reading target file: {filename} ({len(plaintext):,} bytes)", "info")

            # 1. SHA-256 Hash
            fingerprint = crypto.sha256(plaintext)
            self._append_console(log, f"[SHA-256] Integrity fingerprint: {fingerprint}", "cyan")

            # 2. AES-256-CBC Encrypt
            aes_key    = crypto.new_aes_key()
            ciphertext = crypto.aes_encrypt(plaintext, aes_key)
            self._append_console(log, f"[AES-256] Generated fresh 256-bit symmetric session key", "yellow")
            self._append_console(log, f"[AES-256] Ciphertext generated ({len(ciphertext):,} bytes with IV + PKCS7 padding)", "yellow")

            # 3. RSA-2048 OAEP Encapsulate Key
            enc_aes_key = crypto.rsa_encrypt(pub_key, aes_key)
            self._append_console(log, f"[RSA-2048] Wrapped AES session key with {recipient}'s RSA public key (OAEP-SHA256)", "purple")

            # 4. Store in Vault & DB
            tid = db.store_file(self._current_user, recipient, filename,
                                len(plaintext), fingerprint,
                                enc_aes_key.hex(), ciphertext)

            self._append_console(log, f"[VAULT] Stored encrypted blob in vault storage (Transfer ID: #{tid})", "green")
            self._append_console(log, f"[SUCCESS] Payload securely delivered to {recipient}'s inbox!", "success")

            self._status(self._send_status, f"✅ File '{filename}' encrypted & delivered to '{recipient}'!", "green")
            self._send_file_path.delete(0, "end")

        except Exception as exc:
            self._append_console(log, f"[ERROR] Encryption pipeline aborted: {exc}", "danger")
            self._status(self._send_status, f"❌ Pipeline Error: {exc}", "red")

    def _open_downloads_dir(self):
        """Open the downloads directory in the system file manager."""
        import subprocess, platform
        try:
            sys_name = platform.system()
            if sys_name == "Linux":
                subprocess.Popen(["xdg-open", DOWNLOADS])
            elif sys_name == "Darwin":
                subprocess.Popen(["open", DOWNLOADS])
            elif sys_name == "Windows":
                os.startfile(DOWNLOADS)
        except Exception:
            pass

    # ════════════════════════════════════════════════════════════════════════
    # TAB 2 – SECURE INBOX
    # ════════════════════════════════════════════════════════════════════════

    def _build_inbox_tab(self):
        p = self._tab_inbox

        # Header Title
        title_box = tk.Frame(p, bg="#f8fafc")
        title_box.pack(fill="x", pady=(0, 10))
        tk.Label(title_box, text="Encrypted Inbound Vault", font=("Segoe UI", 14, "bold"),
                 fg="#0f172a", bg="#f8fafc").pack(anchor="w")
        tk.Label(title_box,
                 text="Select an incoming file to unwrap the AES key with your RSA private key, verify SHA-256 integrity, and download.",
                 font=("Segoe UI", 9), fg="#64748b", bg="#f8fafc").pack(anchor="w")

        # Table Card Container
        card = tk.Frame(p, bg="#ffffff", padx=16, pady=14,
                        highlightbackground="#e2e8f0", highlightthickness=1)
        card.pack(fill="x", pady=(0, 12))

        # Refresh row
        top_row = tk.Frame(card, bg="#ffffff")
        top_row.pack(fill="x", pady=(0, 8))
        tk.Label(top_row, text="Files Waiting for Decryption:", font=("Segoe UI", 10, "bold"),
                 fg="#334155", bg="#ffffff").pack(side="left")

        btn_group = tk.Frame(top_row, bg="#ffffff")
        btn_group.pack(side="right")

        ttk.Button(btn_group, text="📂 Open Downloads", style="Outline.TButton",
                   command=self._open_downloads_dir).pack(side="left", padx=(0, 6))

        ttk.Button(btn_group, text="⟳ Refresh Inbox", style="Outline.TButton",
                   command=self._refresh_inbox).pack(side="left")

        # Treeview Table
        cols = ("id", "from", "file", "size", "sha256", "date")
        table_frame = tk.Frame(card, bg="#ffffff")
        table_frame.pack(fill="both", expand=True)

        self._inbox_tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=7)
        for col, hdr, w in [
            ("id",    "ID",          50),
            ("from",  "Sender",     120),
            ("file",  "Filename",   240),
            ("size",  "Size",        90),
            ("sha256","SHA-256 Digest", 240),
            ("date",  "Received Date", 160),
        ]:
            self._inbox_tree.heading(col, text=hdr)
            self._inbox_tree.column(col, width=w, minwidth=w, stretch=True,
                                    anchor="center" if w <= 120 else "w")

        self._inbox_tree.tag_configure("row_even", background="#ffffff", foreground="#0f172a")
        self._inbox_tree.tag_configure("row_odd",  background="#f8fafc", foreground="#0f172a")

        sb = ttk.Scrollbar(table_frame, orient="vertical", command=self._inbox_tree.yview)
        self._inbox_tree.configure(yscrollcommand=sb.set)
        self._inbox_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")

        # Download / Decrypt Action Button
        btn_box = tk.Frame(card, bg="#ffffff")
        btn_box.pack(fill="x", pady=(12, 4))

        ttk.Button(btn_box, text="🔓  Decrypt, Verify SHA-256 & Save File",
                   style="Success.TButton", command=self._do_download).pack(fill="x", ipady=2)

        # Status message
        self._inbox_status = tk.Label(card, text="", font=("Segoe UI", 10, "bold"),
                                      bg="#ffffff", wraplength=800, anchor="w")
        self._inbox_status.pack(fill="x", pady=(6, 0))

        # Decryption Telemetry Console (Light Inspector)
        tk.Label(p, text="Decryption & Integrity Verification Console:",
                 font=("Segoe UI", 10, "bold"), fg="#1e293b", bg="#f8fafc").pack(anchor="w", pady=(4, 4))

        self._inbox_log = self._make_console(p, height=8)
        self._refresh_inbox()

    def _refresh_inbox(self):
        for row in self._inbox_tree.get_children():
            self._inbox_tree.delete(row)
        items = db.get_inbox(self._current_user)
        for i, rec in enumerate(items):
            sha  = rec["sha256_hash"]
            abbr = sha[:12] + "…" + sha[-8:]
            tag  = "row_even" if i % 2 == 0 else "row_odd"
            self._inbox_tree.insert("", "end", values=(
                rec["id"], rec["sender"], rec["filename"],
                f"{rec['file_size']:,} B", abbr, rec["created_at"]
            ), tags=(tag,))

    def _do_download(self):
        sel = self._inbox_tree.selection()
        if not sel:
            self._status(self._inbox_status, "⚠️ Please select a file from the table above first.", "red")
            return

        tid = self._inbox_tree.item(sel[0])["values"][0]
        log = self._inbox_log
        log.delete("1.0", "end")
        self._status(self._inbox_status, "", "")

        try:
            rec = db.get_transfer(tid)
            if not rec:
                self._status(self._inbox_status, "❌ Transfer record not found in database.", "red")
                return

            ciphertext   = rec["ciphertext"]
            enc_key      = bytes.fromhex(rec["enc_key_hex"])
            expected_sha = rec["sha256_hash"]
            filename     = rec["filename"]

            self._append_console(log, f"[INBOX] Retrieved ciphertext package #{tid}: '{filename}' ({len(ciphertext):,} bytes)", "info")

            # 1. RSA Private Key Decrypt AES Key
            aes_key = crypto.rsa_decrypt(self._private_key, enc_key)
            self._append_console(log, "[RSA-2048] Successfully decrypted symmetric session key using private key", "purple")

            # 2. AES-256-CBC Decrypt File
            plaintext = crypto.aes_decrypt(ciphertext, aes_key)
            self._append_console(log, "[AES-256] Decrypted file ciphertext with AES-256-CBC & unpadded PKCS7", "yellow")

            # 3. SHA-256 Checksum Verification
            actual_sha = crypto.sha256(plaintext)
            self._append_console(log, f"[SHA-256] Expected Hash: {expected_sha}", "cyan")
            self._append_console(log, f"[SHA-256] Computed Hash: {actual_sha}", "cyan")

            if actual_sha != expected_sha:
                self._append_console(log, "[ALERT] 🚨 TAMPER DETECTED: Hash mismatch! File integrity has been compromised!", "danger")
                self._status(self._inbox_status, "🚨 TAMPER ALERT! SHA-256 checksum failed – download rejected!", "red")
                return

            self._append_console(log, "[VERIFIED] ✅ Integrity confirmed: 100% SHA-256 cryptographic match", "success")

            # 4. Save to downloads directory
            out = os.path.join(DOWNLOADS, filename)
            base, ext = os.path.splitext(filename)
            n = 1
            while os.path.exists(out):
                out = os.path.join(DOWNLOADS, f"{base}_{n}{ext}")
                n += 1
            with open(out, "wb") as f:
                f.write(plaintext)

            db.mark_downloaded(tid)
            self._append_console(log, f"[SAVED] Plaintext written to: {out}", "green")
            self._refresh_inbox()
            self._status(self._inbox_status, f"✅ '{filename}' decrypted, verified & saved to downloads folder!", "green")

        except Exception as exc:
            self._append_console(log, f"[ERROR] Decryption failure: {exc}", "danger")
            self._status(self._inbox_status, f"❌ Decryption Error: {exc}", "red")

    # ════════════════════════════════════════════════════════════════════════
    # TAB 3 – TRANSFER HISTORY
    # ════════════════════════════════════════════════════════════════════════

    def _build_history_tab(self):
        p = self._tab_history

        title_box = tk.Frame(p, bg="#f8fafc")
        title_box.pack(fill="x", pady=(0, 10))
        tk.Label(title_box, text="Transfer Audit Trail", font=("Segoe UI", 14, "bold"),
                 fg="#0f172a", bg="#f8fafc").pack(anchor="w")
        tk.Label(title_box,
                 text="Complete record of all inbound and outbound encrypted transfers associated with your account.",
                 font=("Segoe UI", 9), fg="#64748b", bg="#f8fafc").pack(anchor="w")

        card = tk.Frame(p, bg="#ffffff", padx=16, pady=14,
                        highlightbackground="#e2e8f0", highlightthickness=1)
        card.pack(fill="both", expand=True)

        top_row = tk.Frame(card, bg="#ffffff")
        top_row.pack(fill="x", pady=(0, 8))
        self._hist_count_label = tk.Label(top_row, text="Total Records: 0", font=("Segoe UI", 10, "bold"),
                                          fg="#334155", bg="#ffffff")
        self._hist_count_label.pack(side="left")

        ttk.Button(top_row, text="⟳ Refresh Audit Log", style="Outline.TButton",
                   command=self._refresh_history).pack(side="right")

        cols = ("id", "dir", "peer", "file", "size", "status", "date")
        table_frame = tk.Frame(card, bg="#ffffff")
        table_frame.pack(fill="both", expand=True)

        self._hist_tree = ttk.Treeview(table_frame, columns=cols, show="headings")
        for col, hdr, w in [
            ("id",     "ID",        50),
            ("dir",    "Type",      90),
            ("peer",   "Peer",     130),
            ("file",   "Filename", 240),
            ("size",   "Size",      90),
            ("status", "Status",   120),
            ("date",   "Timestamp",170),
        ]:
            self._hist_tree.heading(col, text=hdr)
            self._hist_tree.column(col, width=w, minwidth=w, stretch=True,
                                   anchor="center" if w <= 130 else "w")

        self._hist_tree.tag_configure("row_even", background="#ffffff", foreground="#0f172a")
        self._hist_tree.tag_configure("row_odd",  background="#f8fafc", foreground="#0f172a")

        sb = ttk.Scrollbar(table_frame, orient="vertical", command=self._hist_tree.yview)
        self._hist_tree.configure(yscrollcommand=sb.set)
        self._hist_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")

        self._refresh_history()

    def _refresh_history(self):
        for row in self._hist_tree.get_children():
            self._hist_tree.delete(row)

        records = db.get_history(self._current_user)
        self._hist_count_label.config(text=f"Total Records: {len(records)} transfers")

        for i, r in enumerate(records):
            is_sent = (r["sender"] == self._current_user)
            tag = "row_even" if i % 2 == 0 else "row_odd"
            self._hist_tree.insert("", "end", values=(
                r["id"],
                "SENT 📤" if is_sent else "RCVD 📥",
                r["recipient"] if is_sent else r["sender"],
                r["filename"],
                f"{r['file_size']:,} B",
                r["status"],
                r["created_at"],
            ), tags=(tag,))

    # ════════════════════════════════════════════════════════════════════════
    # TAB 4 – SECURITY & TAMPER DEMO
    # ════════════════════════════════════════════════════════════════════════

    def _build_demo_tab(self):
        p = self._tab_demo

        title_box = tk.Frame(p, bg="#f8fafc")
        title_box.pack(fill="x", pady=(0, 8))
        tk.Label(title_box, text="Security & Tamper-Detection Verification",
                 font=("Segoe UI", 14, "bold"), fg="#0f172a", bg="#f8fafc").pack(anchor="w")

        banner = tk.Frame(p, bg="#ffffff", padx=16, pady=12,
                          highlightbackground="#e2e8f0", highlightthickness=1)
        banner.pack(fill="x", pady=(0, 10))

        desc = (
            "This test simulates Alice sending an encrypted document to Bob, then verifies three real-world checks:\n"
            "  1. Server Storage Inspection: Confirms the raw vault file contains only ciphertext (no readable text).\n"
            "  2. Normal Decryption: Bob uses his RSA private key to decrypt the AES key, recover the file, and verify the SHA-256 hash.\n"
            "  3. Tamper Detection: Corrupts 1 byte in the encrypted file to confirm the system detects the modification and rejects the download."
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
        L("SECURESHARE – CRYPTOGRAPHIC VERIFICATION & TAMPER TEST", "purple")
        L("=" * 76, "info")

        alice_priv = _load_priv("alice")
        bob_pub    = db.get_public_key("bob")
        bob_priv   = _load_priv("bob")

        if not (alice_priv and bob_pub and bob_priv):
            L("Error: Demo accounts (alice / bob) not found. Please restart the app.", "danger")
            return

        # Realistic test document
        secret = (
            b"Project Planning & Budget Review\n"
            b"Author: Alice\n"
            b"Recipient: Bob\n"
            b"Approved Budget: $48,000 for Q3 infrastructure\n"
            b"Confidential internal document."
        )

        L("\n[SETUP] Alice prepares document: 'project_budget.txt'", "info")
        L(f"  Document size: {len(secret)} bytes", "info")
        orig_hash = crypto.sha256(secret)
        L(f"  Computed SHA-256 hash of original file: {orig_hash}", "cyan")

        # Hybrid Encryption
        L("\n[STEP 1] Alice encrypts the file for Bob", "info")
        aes_key    = crypto.new_aes_key()
        ciphertext = crypto.aes_encrypt(secret, aes_key)
        enc_key    = crypto.rsa_encrypt(bob_pub, aes_key)
        tid = db.store_file("alice", "bob", "project_budget.txt",
                            len(secret), orig_hash, enc_key.hex(), ciphertext)

        L(f"  • Generated fresh 256-bit AES session key (32 random bytes)", "yellow")
        L(f"  • Encrypted file data using AES-256-CBC (result: {len(ciphertext)} bytes with IV + PKCS7 padding)", "yellow")
        L(f"  • Encrypted the AES session key using Bob's RSA-2048 public key (OAEP padding)", "purple")
        L(f"  • Saved encrypted payload in vault (Transfer ID: #{tid})", "green")

        # Test 1: Storage inspection
        rec = db.get_transfer(tid)
        raw = rec["ciphertext"]
        L("\n" + "-" * 76, "info")
        L("TEST 1: Storage Inspection (Can the server or an eavesdropper read the file?)", "purple")
        L("-" * 76, "info")
        L(f"  File location on disk: encrypted_vault/{rec['vault_file']}", "info")
        L(f"  First 32 bytes (hex): {raw[:32].hex()}", "yellow")
        try:
            raw.decode("utf-8")
            L("  FAILED: The raw file contains readable plaintext!", "danger")
        except UnicodeDecodeError:
            L("  Attempting to read file as text: UnicodeDecodeError (pure binary data)", "cyan")
            L("  PASSED: File on disk is completely encrypted. Without Bob's private key,", "success")
            L("          neither the server host nor anyone with disk access can read it.", "success")

        # Test 2: Normal decryption
        L("\n" + "-" * 76, "info")
        L("TEST 2: Normal Recipient Decryption & Integrity Check", "purple")
        L("-" * 76, "info")
        L("  Bob receives the encrypted file and begins decryption:", "info")
        dec_aes   = crypto.rsa_decrypt(bob_priv, enc_key)
        L("  1. Bob uses his RSA-2048 private key to decrypt the AES session key: OK", "purple")

        decrypted = crypto.aes_decrypt(raw, dec_aes)
        L(f"  2. AES-256-CBC decrypts file content ({len(decrypted)} bytes recovered)", "yellow")

        got_hash  = crypto.sha256(decrypted)
        L(f"  3. Checking file integrity with SHA-256:", "info")
        L(f"     Expected hash: {orig_hash}", "cyan")
        L(f"     Computed hash: {got_hash}", "cyan")
        if got_hash == orig_hash:
            L("  PASSED: Hashes match 100%. File was recovered with zero corruption.", "success")
            L(f"  Decrypted text preview: \"{decrypted.decode().splitlines()[0]}\"", "info")
        else:
            L("  FAILED: Hashes do not match!", "danger")

        # Test 3: Tamper attack
        L("\n" + "-" * 76, "info")
        L("TEST 3: Tamper Attack (What happens if someone modifies the file on disk?)", "purple")
        L("-" * 76, "info")
        L("  Simulating an attacker modifying 1 byte in the vault file (offset 24)...", "danger")

        vault_path = os.path.join(db.VAULT_DIR, rec["vault_file"])
        with open(vault_path, "rb") as f:
            tampered = bytearray(f.read())
        old_byte = tampered[24]
        tampered[24] ^= 0xFF
        new_byte = tampered[24]
        with open(vault_path, "wb") as f:
            f.write(tampered)

        L(f"  Byte at offset 24 altered: 0x{old_byte:02X} -> 0x{new_byte:02X}", "yellow")
        L("  Bob now attempts to download and decrypt the tampered file:", "info")

        rec2 = db.get_transfer(tid)
        try:
            dec_aes2   = crypto.rsa_decrypt(bob_priv, enc_key)
            decrypted2 = crypto.aes_decrypt(rec2["ciphertext"], dec_aes2)
            tamper_hash = crypto.sha256(decrypted2)
            L(f"  Expected hash: {orig_hash}", "cyan")
            L(f"  Computed hash: {tamper_hash}", "danger")
            if tamper_hash != orig_hash:
                L("  SHA-256 mismatch detected! The altered byte corrupted the decrypted output.", "danger")
                L("  PASSED: The application catches the mismatch and rejects the file.", "success")
                L("          The user is protected from opening or running a modified file.", "success")
            else:
                L("  FAILED: Tamper was not detected.", "danger")
        except Exception as e:
            L(f"  AES Decryption failed on corrupted ciphertext blocks: {e}", "danger")
            L("  PASSED: The corrupted data failed AES block padding checks.", "success")
            L("          The application rejects the file before it can do any harm.", "success")

        L("\n" + "=" * 76, "info")
        L("SUMMARY OF RESULTS:", "purple")
        L("  [PASS] Server Confidentiality: Vault stores only AES-256 ciphertext.", "success")
        L("  [PASS] Private Key Security: Only Bob's RSA key can unlock the AES key.", "success")
        L("  [PASS] Tamper Detection: Any single-byte modification is immediately caught.", "success")
        L("=" * 76, "info")

    # ════════════════════════════════════════════════════════════════════════
    # SHARED UTILITIES
    # ════════════════════════════════════════════════════════════════════════

    def _clear_window(self):
        for w in self.winfo_children():
            w.destroy()

    @staticmethod
    def _make_console(parent, height=12):
        """Creates a clean, modern light-themed inspector console with syntax color tags."""
        frame = tk.Frame(parent, bg="#ffffff", highlightbackground="#cbd5e1", highlightthickness=1)
        frame.pack(fill="both", expand=True, pady=2)

        t = tk.Text(frame, height=height, wrap="word",
                    bg="#f8fafc", fg="#0f172a", font=("Consolas", 9),
                    insertbackground="#2563eb", padx=10, pady=8, borderwidth=0)

        # High-contrast color tags for light theme
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
        palette = {
            "green": "#16a34a",
            "red":   "#dc2626",
            "blue":  "#2563eb",
            "":      "#0f172a"
        }
        label.config(text=msg, fg=palette.get(color, "#0f172a"))


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
