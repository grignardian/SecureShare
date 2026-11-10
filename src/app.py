#!/usr/bin/env python3
"""
app.py - Graphical User Interface for SecureShare
-------------------------------------------------
Provides a simple, beginner-friendly Tkinter desktop application.
Connects to the SecureShare server over TLS to:
1. Register new accounts and generate local password-protected RSA-2048 keys.
2. Log in and unlock the local private key.
3. Encrypt files locally (AES-256-CBC + HMAC-SHA256 + RSA-2048) and upload to server.
4. View received files, download them, verify HMAC & SHA-256 integrity, and decrypt.
5. View sent and received file transfer history.
"""

import os
import sys
import tempfile
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Ensure project root is on sys.path when run as `python src/app.py`
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src import client, crypto, keystore


def main():
    # Dictionary to hold active logged-in session details
    session = {
        "token": None,
        "username": None,
        "private_key_pem": None,
        "server_ip": "127.0.0.1",
        "server_port": 5555,
        "cert_path": client.DEFAULT_CERT_PATH
    }

    root = tk.Tk()
    root.title("SecureShare - Encrypted File Sharing")
    root.geometry("820x640")
    root.minsize(740, 560)

    # Top Banner
    banner_frame = tk.Frame(root, bg="#1e293b", pady=10)
    banner_frame.pack(fill=tk.X)

    tk.Label(
        banner_frame,
        text="SecureShare",
        font=("Arial", 16, "bold"),
        fg="#ffffff",
        bg="#1e293b"
    ).pack()

    tk.Label(
        banner_frame,
        text="End-to-End Encrypted Client-Server File Sharing (AES-256-CBC + RSA-2048 + HMAC + SHA-256)",
        font=("Arial", 9),
        fg="#cbd5e1",
        bg="#1e293b"
    ).pack()

    # Main container that swaps between Login View and Dashboard View
    main_container = ttk.Frame(root, padding=16)
    main_container.pack(fill=tk.BOTH, expand=True)

    # =======================================================================
    # SCREEN 1: LOGIN & REGISTRATION FRAME
    # =======================================================================
    auth_frame = ttk.Frame(main_container)

    # --- Server Connection Settings ---
    conn_box = ttk.LabelFrame(auth_frame, text=" Server Connection Settings ", padding=12)
    conn_box.pack(fill=tk.X, pady=(0, 14))

    conn_row1 = ttk.Frame(conn_box)
    conn_row1.pack(fill=tk.X, pady=4)

    ttk.Label(conn_row1, text="Server IP Address:", width=18).pack(side=tk.LEFT)
    server_ip_entry = ttk.Entry(conn_row1, width=22)
    server_ip_entry.insert(0, "127.0.0.1")
    server_ip_entry.pack(side=tk.LEFT, padx=(0, 16))

    ttk.Label(conn_row1, text="Port:").pack(side=tk.LEFT, padx=(0, 6))
    server_port_entry = ttk.Entry(conn_row1, width=8)
    server_port_entry.insert(0, "5555")
    server_port_entry.pack(side=tk.LEFT)

    conn_row2 = ttk.Frame(conn_box)
    conn_row2.pack(fill=tk.X, pady=4)

    ttk.Label(conn_row2, text="TLS Certificate:", width=18).pack(side=tk.LEFT)
    cert_path_entry = ttk.Entry(conn_row2)
    cert_path_entry.insert(0, client.DEFAULT_CERT_PATH)
    cert_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

    def browse_cert_file():
        selected = filedialog.askopenfilename(
            title="Select Server Public Certificate (server.crt)",
            filetypes=[("Certificate Files", "*.crt *.pem"), ("All Files", "*.*")]
        )
        if selected:
            cert_path_entry.delete(0, tk.END)
            cert_path_entry.insert(0, selected)

    def read_connection_inputs():
        ip_text = server_ip_entry.get().strip()
        port_text = server_port_entry.get().strip()
        cert_text = cert_path_entry.get().strip()

        if not ip_text:
            messagebox.showwarning("Input Required", "Please enter the server IP address.")
            return None

        try:
            port_num = int(port_text)
        except ValueError:
            messagebox.showerror("Invalid Port", "Port must be a number (default is 5555).")
            return None

        if port_num < 1 or port_num > 65535:
            messagebox.showerror("Invalid Port", "Port must be between 1 and 65535.")
            return None

        return ip_text, port_num, cert_text

    def on_test_connection():
        conn_info = read_connection_inputs()
        if conn_info is None:
            return
        ip_text, port_num, cert_text = conn_info
        try:
            msg = client.ping_server(ip_text, port_num, cert_path=cert_text)
            messagebox.showinfo("Connection Successful", "TLS connection verified!\n\n" + msg)
        except Exception as exc:
            messagebox.showerror("Connection Error", str(exc))

    ttk.Button(conn_row2, text="Browse...", command=browse_cert_file).pack(side=tk.LEFT, padx=(0, 8))
    ttk.Button(conn_row2, text="Test Connection", command=on_test_connection).pack(side=tk.RIGHT)

    # --- Login / Register Box ---
    login_box = ttk.LabelFrame(auth_frame, text=" Account Login or Registration ", padding=16)
    login_box.pack(fill=tk.BOTH, expand=True)

    user_row = ttk.Frame(login_box)
    user_row.pack(fill=tk.X, pady=6)
    ttk.Label(user_row, text="Username:", width=16).pack(side=tk.LEFT)
    username_entry = ttk.Entry(user_row, width=32)
    username_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

    pass_row = ttk.Frame(login_box)
    pass_row.pack(fill=tk.X, pady=6)
    ttk.Label(pass_row, text="Password:", width=16).pack(side=tk.LEFT)
    password_entry = ttk.Entry(pass_row, width=32, show="*")
    password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

    auth_buttons_row = ttk.Frame(login_box)
    auth_buttons_row.pack(fill=tk.X, pady=16)

    def on_register_click():
        conn_info = read_connection_inputs()
        if conn_info is None:
            return
        ip_text, port_num, cert_text = conn_info

        raw_user = username_entry.get().strip().lower()
        raw_pass = password_entry.get()

        if not raw_user or not raw_pass:
            messagebox.showwarning("Missing Fields", "Please enter both a username and a password.")
            return

        if len(raw_pass) < 4:
            messagebox.showwarning("Weak Password", "Password must be at least 4 characters long.")
            return

        # Confirm before replacing any existing local keys for this username
        overwrite_keys = False
        if keystore.has_private_key(raw_user):
            confirm = messagebox.askyesno(
                "Existing Key Detected",
                "A local private key already exists for '" + raw_user + "' in keys/.\n"
                "Do you want to overwrite it with a new key pair?"
            )
            if not confirm:
                return
            overwrite_keys = True

        # Generate RSA-2048 key pair in memory first
        try:
            private_key_obj, public_pem = keystore.generate_rsa_keypair()
        except Exception as exc:
            messagebox.showerror("Key Generation Error", str(exc))
            return

        # Register account and send ONLY public key to the server
        try:
            ok, msg = client.register(ip_text, port_num, raw_user, raw_pass, public_pem, cert_path=cert_text)
        except Exception as exc:
            messagebox.showerror("Registration Failed", str(exc))
            return

        if not ok:
            messagebox.showerror("Registration Rejected", msg)
            return

        # Save password-protected private key locally ONLY after server accepts registration
        try:
            priv_path = keystore.save_private_key(raw_user, private_key_obj, raw_pass, overwrite=overwrite_keys)
            keystore.save_public_key(raw_user, public_pem, overwrite=overwrite_keys)
            messagebox.showinfo(
                "Registration Successful",
                msg + "\n\nYour password-protected private key has been saved locally at:\n" + priv_path +
                "\n\nNever share or commit your private key!"
            )
        except Exception as exc:
            messagebox.showerror("Key Save Error", "Account created on server, but failed to save local key: " + str(exc))

    def on_import_key_click():
        raw_user = username_entry.get().strip().lower()
        raw_pass = password_entry.get()
        if not raw_user or not raw_pass:
            messagebox.showwarning("Input Required", "Enter your username and password before importing your key.")
            return

        selected_file = filedialog.askopenfilename(
            title="Select Backup Encrypted Private Key (.pem)",
            filetypes=[("PEM Key Files", "*.pem"), ("All Files", "*.*")]
        )
        if not selected_file:
            return

        overwrite_flag = False
        if keystore.has_private_key(raw_user):
            confirm = messagebox.askyesno(
                "Confirm Replacement",
                "A local key already exists for '" + raw_user + "'. Overwrite it?"
            )
            if not confirm:
                return
            overwrite_flag = True

        try:
            saved_path = keystore.import_private_key(raw_user, selected_file, raw_pass, overwrite=overwrite_flag)
            messagebox.showinfo("Key Imported", "Private key imported successfully to:\n" + saved_path)
        except Exception as exc:
            messagebox.showerror("Import Failed", str(exc))

    def on_login_click():
        conn_info = read_connection_inputs()
        if conn_info is None:
            return
        ip_text, port_num, cert_text = conn_info

        raw_user = username_entry.get().strip().lower()
        raw_pass = password_entry.get()

        if not raw_user or not raw_pass:
            messagebox.showwarning("Missing Fields", "Please enter username and password.")
            return

        # Step 1: Verify password with the server over TLS
        try:
            ok, result_or_msg, clean_user = client.login(ip_text, port_num, raw_user, raw_pass, cert_path=cert_text)
        except Exception as exc:
            messagebox.showerror("Connection Error", str(exc))
            return

        if not ok:
            messagebox.showerror("Login Failed", result_or_msg)
            return

        token = result_or_msg

        # Step 2: Unlock local encrypted private key using the user's password
        try:
            unlocked_priv_pem = keystore.load_private_key(clean_user, raw_pass)
        except FileNotFoundError:
            client.logout(ip_text, port_num, token, cert_path=cert_text)
            messagebox.showerror(
                "Private Key Missing",
                "Your login credentials are correct, but no local private key was found for '" + clean_user + "'.\n\n"
                "If you are logging in from a new computer, click 'Import Private Key' to load your backup .pem file."
            )
            return
        except Exception as exc:
            client.logout(ip_text, port_num, token, cert_path=cert_text)
            messagebox.showerror("Key Unlock Error", str(exc))
            return

        # Save session in memory and show dashboard
        session["token"] = token
        session["username"] = clean_user
        session["private_key_pem"] = unlocked_priv_pem
        session["server_ip"] = ip_text
        session["server_port"] = port_num
        session["cert_path"] = cert_text

        password_entry.delete(0, tk.END)
        show_dashboard_screen()

    btn_login = tk.Button(
        auth_buttons_row, text="Login", command=on_login_click,
        bg="#2563eb", fg="#ffffff", font=("Arial", 10, "bold"), relief=tk.FLAT, padx=20, pady=6
    )
    btn_login.pack(side=tk.LEFT, padx=(0, 10))

    btn_register = tk.Button(
        auth_buttons_row, text="Register New Account", command=on_register_click,
        bg="#059669", fg="#ffffff", font=("Arial", 10, "bold"), relief=tk.FLAT, padx=16, pady=6
    )
    btn_register.pack(side=tk.LEFT, padx=(0, 10))

    ttk.Button(auth_buttons_row, text="Import Private Key (.pem)", command=on_import_key_click).pack(side=tk.RIGHT)

    note_text = (
        "Security Note: When you register, your RSA-2048 key pair is created on your computer.\n"
        "Only your public key is sent to the server. Your private key stays locally encrypted with your password."
    )
    ttk.Label(login_box, text=note_text, foreground="#475569").pack(anchor=tk.W, pady=(10, 0))

    # =======================================================================
    # SCREEN 2: MAIN DASHBOARD (SEND, RECEIVED, HISTORY)
    # =======================================================================
    dash_frame = ttk.Frame(main_container)

    # Top bar showing current user and logout button
    top_bar = ttk.Frame(dash_frame)
    top_bar.pack(fill=tk.X, pady=(0, 10))

    user_status_label = ttk.Label(top_bar, text="", font=("Arial", 10, "bold"))
    user_status_label.pack(side=tk.LEFT)

    def on_logout_click():
        client.logout(
            session["server_ip"],
            session["server_port"],
            session["token"],
            cert_path=session["cert_path"]
        )
        session["token"] = None
        session["username"] = None
        session["private_key_pem"] = None
        show_login_screen()

    ttk.Button(top_bar, text="Logout", command=on_logout_click).pack(side=tk.RIGHT)

    notebook = ttk.Notebook(dash_frame)
    notebook.pack(fill=tk.BOTH, expand=True)

    tab_send = ttk.Frame(notebook, padding=14)
    tab_received = ttk.Frame(notebook, padding=14)
    tab_history = ttk.Frame(notebook, padding=14)

    notebook.add(tab_send, text="  Send File  ")
    notebook.add(tab_received, text="  Received Files  ")
    notebook.add(tab_history, text="  File History  ")

    # -----------------------------------------------------------------------
    # TAB 1: SEND FILE
    # -----------------------------------------------------------------------
    ttk.Label(tab_send, text="1. Select File to Encrypt and Send:", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(4, 4))
    send_file_row = ttk.Frame(tab_send)
    send_file_row.pack(fill=tk.X, pady=(0, 12))

    send_file_entry = ttk.Entry(send_file_row)
    send_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

    def browse_send_file():
        selected = filedialog.askopenfilename(title="Select File to Share Securely")
        if selected:
            send_file_entry.delete(0, tk.END)
            send_file_entry.insert(0, selected)

    ttk.Button(send_file_row, text="Browse...", command=browse_send_file).pack(side=tk.RIGHT)

    ttk.Label(tab_send, text="2. Select Recipient:", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(4, 4))
    recipient_row = ttk.Frame(tab_send)
    recipient_row.pack(fill=tk.X, pady=(0, 14))

    recipient_combo = ttk.Combobox(recipient_row, state="readonly", width=30)
    recipient_combo.pack(side=tk.LEFT, padx=(0, 10))

    def refresh_users_list():
        if not session["token"]:
            return
        try:
            users = client.list_users(
                session["server_ip"],
                session["server_port"],
                session["token"],
                cert_path=session["cert_path"]
            )
            recipient_combo["values"] = users
            if users:
                # Default to a user other than current user if available
                chosen = users[0]
                for u in users:
                    if u != session["username"]:
                        chosen = u
                        break
                recipient_combo.set(chosen)
        except Exception as exc:
            messagebox.showerror("Error", "Could not fetch users from server:\n" + str(exc))

    ttk.Button(recipient_row, text="Refresh Users", command=refresh_users_list).pack(side=tk.LEFT)

    def on_send_file_click():
        file_path = send_file_entry.get().strip()
        recipient = recipient_combo.get().strip()

        if not file_path:
            messagebox.showwarning("Missing File", "Please choose a file to send.")
            return
        if not os.path.isfile(file_path):
            messagebox.showerror("File Error", "Selected file does not exist.")
            return
        if not recipient:
            messagebox.showwarning("Missing Recipient", "Please select a recipient username.")
            return

        send_status_box.config(state=tk.NORMAL)
        send_status_box.delete("1.0", tk.END)

        temp_enc_path = None
        try:
            # Step 1: Retrieve recipient's RSA public key from server
            recipient_pub_pem = client.get_public_key(
                session["server_ip"],
                session["server_port"],
                session["token"],
                recipient,
                cert_path=session["cert_path"]
            )

            # Step 2: Create a temporary encrypted file locally
            fd, temp_enc_path = tempfile.mkstemp(suffix=".secureshare")
            os.close(fd)

            enc_info = crypto.encrypt_file(
                input_path=file_path,
                output_path=temp_enc_path,
                recipient_public_key_pem=recipient_pub_pem,
                sender_name=session["username"],
                recipient_name=recipient,
                overwrite=True
            )

            # Step 3: Upload encrypted bundle over TLS in chunks
            upload_resp = client.upload_encrypted_file(
                server_ip=session["server_ip"],
                server_port=session["server_port"],
                token=session["token"],
                receiver=recipient,
                original_filename=enc_info["filename"],
                original_file_size=enc_info["file_size"],
                sha256=enc_info["sha256"],
                encrypted_file_path=temp_enc_path,
                cert_path=session["cert_path"]
            )

            send_status_box.insert(tk.END, "File encrypted locally and sent successfully!\n\n")
            send_status_box.insert(tk.END, f"Transfer ID:     {upload_resp['file_id']}\n")
            send_status_box.insert(tk.END, f"Recipient:       {recipient}\n")
            send_status_box.insert(tk.END, f"Original File:   {enc_info['filename']} ({enc_info['file_size']} bytes)\n")
            send_status_box.insert(tk.END, f"Encrypted Size:  {enc_info['encrypted_size']} bytes\n")
            send_status_box.insert(tk.END, f"SHA-256 Digest:  {enc_info['sha256']}\n")
            send_status_box.config(state=tk.DISABLED)

            messagebox.showinfo("Upload Complete", "Encrypted file sent to " + recipient + " successfully!")
            refresh_received_files()
            refresh_file_history()

        except Exception as exc:
            send_status_box.insert(tk.END, "Upload failed:\n" + str(exc))
            send_status_box.config(state=tk.DISABLED)
            messagebox.showerror("Send Failed", str(exc))
        finally:
            if temp_enc_path and os.path.exists(temp_enc_path):
                os.remove(temp_enc_path)

    btn_send = tk.Button(
        tab_send, text="Encrypt and Send File", command=on_send_file_click,
        bg="#2563eb", fg="#ffffff", font=("Arial", 11, "bold"), relief=tk.FLAT, pady=8
    )
    btn_send.pack(fill=tk.X, pady=(0, 12))

    send_status_box = tk.Text(tab_send, height=8, bg="#f8fafc", fg="#0f172a", font=("Monospace", 9))
    send_status_box.pack(fill=tk.BOTH, expand=True)
    send_status_box.insert(tk.END, "Select a file and recipient, then click 'Encrypt and Send File'.")
    send_status_box.config(state=tk.DISABLED)

    # -----------------------------------------------------------------------
    # TAB 2: RECEIVED FILES
    # -----------------------------------------------------------------------
    recv_toolbar = ttk.Frame(tab_received)
    recv_toolbar.pack(fill=tk.X, pady=(0, 8))

    ttk.Label(recv_toolbar, text="Files encrypted for you:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)

    recv_columns = ("file_id", "sender", "filename", "size", "uploaded_at")
    recv_tree = ttk.Treeview(tab_received, columns=recv_columns, show="headings", height=9)
    recv_tree.heading("file_id", text="ID")
    recv_tree.heading("sender", text="Sender")
    recv_tree.heading("filename", text="Original Filename")
    recv_tree.heading("size", text="Size (bytes)")
    recv_tree.heading("uploaded_at", text="Uploaded Time")

    recv_tree.column("file_id", width=50, anchor=tk.CENTER)
    recv_tree.column("sender", width=110)
    recv_tree.column("filename", width=230)
    recv_tree.column("size", width=100, anchor=tk.E)
    recv_tree.column("uploaded_at", width=170)
    recv_tree.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

    def refresh_received_files():
        if not session["token"]:
            return
        try:
            files = client.list_received_files(
                session["server_ip"],
                session["server_port"],
                session["token"],
                cert_path=session["cert_path"]
            )
            for item in recv_tree.get_children():
                recv_tree.delete(item)
            for record in files:
                recv_tree.insert("", tk.END, values=(
                    record["file_id"],
                    record["sender"],
                    record["original_filename"],
                    record["file_size"],
                    record["uploaded_at"]
                ))
        except Exception as exc:
            messagebox.showerror("Error", "Failed to load received files:\n" + str(exc))

    def on_download_decrypt_click():
        selected = recv_tree.selection()
        if not selected:
            messagebox.showwarning("Select File", "Please select a file from the Received Files list.")
            return

        values = recv_tree.item(selected[0], "values")
        file_id = int(values[0])
        orig_filename = values[2]

        # Ask user where to save the decrypted file (preventing accidental overwrite)
        save_path = filedialog.asksaveasfilename(
            title="Save Decrypted File As",
            initialfile=orig_filename
        )
        if not save_path:
            return

        temp_enc_path = None
        recv_status_box.config(state=tk.NORMAL)
        recv_status_box.delete("1.0", tk.END)

        try:
            fd, temp_enc_path = tempfile.mkstemp(suffix=".secureshare")
            os.close(fd)

            # Step 1: Download encrypted bundle from server
            client.download_encrypted_file(
                server_ip=session["server_ip"],
                server_port=session["server_port"],
                token=session["token"],
                file_id=file_id,
                dest_encrypted_path=temp_enc_path,
                cert_path=session["cert_path"]
            )

            # Step 2: Verify HMAC, decrypt AES-256-CBC, and verify SHA-256
            dec_info = crypto.decrypt_file(
                input_path=temp_enc_path,
                output_path=save_path,
                recipient_private_key_pem=session["private_key_pem"],
                overwrite=True  # User already confirmed destination in save dialog
            )

            recv_status_box.insert(tk.END, "Download and decryption succeeded!\n")
            recv_status_box.insert(tk.END, "Security Check: HMAC-SHA256 verified and SHA-256 checksum matched.\n\n")
            recv_status_box.insert(tk.END, f"Sender:          {dec_info['sender']}\n")
            recv_status_box.insert(tk.END, f"Restored File:   {dec_info['output_path']}\n")
            recv_status_box.insert(tk.END, f"Restored Size:   {dec_info['file_size']} bytes\n")
            recv_status_box.insert(tk.END, f"SHA-256 Digest:  {dec_info['sha256']}\n")
            recv_status_box.config(state=tk.DISABLED)

            messagebox.showinfo(
                "Decryption Verified",
                "File decrypted successfully and integrity verified!\nSaved to:\n" + save_path
            )
        except Exception as exc:
            recv_status_box.insert(tk.END, "SECURITY ALERT OR ERROR:\n" + str(exc))
            recv_status_box.config(state=tk.DISABLED)
            messagebox.showerror("Decryption Failed", str(exc))
        finally:
            if temp_enc_path and os.path.exists(temp_enc_path):
                os.remove(temp_enc_path)

    ttk.Button(recv_toolbar, text="Refresh Inbox", command=refresh_received_files).pack(side=tk.RIGHT)

    btn_download = tk.Button(
        tab_received, text="Download, Decrypt and Verify Selected File", command=on_download_decrypt_click,
        bg="#059669", fg="#ffffff", font=("Arial", 10, "bold"), relief=tk.FLAT, pady=7
    )
    btn_download.pack(fill=tk.X, pady=(0, 10))

    recv_status_box = tk.Text(tab_received, height=6, bg="#f8fafc", fg="#0f172a", font=("Monospace", 9))
    recv_status_box.pack(fill=tk.X)
    recv_status_box.insert(tk.END, "Select a received file and click Download to decrypt and verify integrity.")
    recv_status_box.config(state=tk.DISABLED)

    # -----------------------------------------------------------------------
    # TAB 3: FILE HISTORY
    # -----------------------------------------------------------------------
    hist_toolbar = ttk.Frame(tab_history)
    hist_toolbar.pack(fill=tk.X, pady=(0, 8))

    ttk.Label(hist_toolbar, text="Your Sent and Received File Transfers:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)

    hist_columns = ("file_id", "direction", "sender", "receiver", "filename", "size", "uploaded_at")
    hist_tree = ttk.Treeview(tab_history, columns=hist_columns, show="headings")
    hist_tree.heading("file_id", text="ID")
    hist_tree.heading("direction", text="Type")
    hist_tree.heading("sender", text="Sender")
    hist_tree.heading("receiver", text="Recipient")
    hist_tree.heading("filename", text="Filename")
    hist_tree.heading("size", text="Size")
    hist_tree.heading("uploaded_at", text="Timestamp")

    hist_tree.column("file_id", width=45, anchor=tk.CENTER)
    hist_tree.column("direction", width=85, anchor=tk.CENTER)
    hist_tree.column("sender", width=95)
    hist_tree.column("receiver", width=95)
    hist_tree.column("filename", width=190)
    hist_tree.column("size", width=80, anchor=tk.E)
    hist_tree.column("uploaded_at", width=150)
    hist_tree.pack(fill=tk.BOTH, expand=True)

    def refresh_file_history():
        if not session["token"]:
            return
        try:
            history = client.list_file_history(
                session["server_ip"],
                session["server_port"],
                session["token"],
                cert_path=session["cert_path"]
            )
            for item in hist_tree.get_children():
                hist_tree.delete(item)
            for record in history:
                if record["sender"] == session["username"]:
                    direction = "SENT"
                else:
                    direction = "RECEIVED"
                hist_tree.insert("", tk.END, values=(
                    record["file_id"],
                    direction,
                    record["sender"],
                    record["receiver"],
                    record["original_filename"],
                    record["file_size"],
                    record["uploaded_at"]
                ))
        except Exception as exc:
            messagebox.showerror("Error", "Failed to load file history:\n" + str(exc))

    ttk.Button(hist_toolbar, text="Refresh History", command=refresh_file_history).pack(side=tk.RIGHT)

    # =======================================================================
    # SCREEN SWITCHING HELPERS
    # =======================================================================
    def show_login_screen():
        dash_frame.pack_forget()
        auth_frame.pack(fill=tk.BOTH, expand=True)

    def show_dashboard_screen():
        auth_frame.pack_forget()
        user_status_label.config(
            text=f"Logged in as: {session['username']}   |   Server: {session['server_ip']}:{session['server_port']}"
        )
        dash_frame.pack(fill=tk.BOTH, expand=True)
        refresh_users_list()
        refresh_received_files()
        refresh_file_history()

    # Start on login screen
    show_login_screen()
    root.mainloop()


if __name__ == "__main__":
    main()
