"""
server.py - Central TLS Socket Server for SecureShare
-----------------------------------------------------
Listens for incoming TLS client connections on a configurable IP and port.
Handles one request per connection sequentially in a straightforward loop:
- User registration & login (using PBKDF2 in auth.py and SQLite in database.py)
- In-memory session tokens (invalidated on server restart)
- Public key lookup
- Encrypted file upload & download (streamed in chunks)
- File history queries

The server stores ONLY encrypted files and metadata. It NEVER receives
plaintext files, plaintext passwords, or user private keys.
"""

import os
import sys
import ssl
import json
import uuid
import socket
import struct
import secrets
import argparse
import datetime
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Ensure project root is on sys.path when run as `python src/server.py`
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src import auth, database


DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5555
CHUNK_SIZE = 4096
MAX_HEADER_SIZE = 64 * 1024          # 64 KB max JSON header
MAX_FILE_SIZE = 50 * 1024 * 1024     # 50 MB max encrypted file size

CERTS_DIR = os.path.join(PROJECT_ROOT, "certs")
DEFAULT_CERT_PATH = os.path.join(CERTS_DIR, "server.crt")
DEFAULT_KEY_PATH = os.path.join(CERTS_DIR, "server.key")


# ---------------------------------------------------------------------------
# 1. TLS Certificate Helper
# ---------------------------------------------------------------------------

def get_local_lan_ip():
    """
    Detect this computer's LAN IP address on the local Wi-Fi/network.
    Falls back to 127.0.0.1 if offline.
    """
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not send actual packets; just determines outbound interface IP
        temp_sock.connect(("8.8.8.8", 80))
        lan_ip = temp_sock.getsockname()[0]
        return lan_ip
    except OSError:
        return "127.0.0.1"
    finally:
        temp_sock.close()


def cert_has_ip(cert_path, target_ip):
    """Check if an existing X.509 certificate includes target_ip in its SAN list."""
    try:
        with open(cert_path, "rb") as file_obj:
            cert = x509.load_pem_x509_certificate(file_obj.read())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        ip_list = san.get_values_for_type(x509.IPAddress)
        target_addr = ipaddress.ip_address(target_ip)
        return target_addr in ip_list
    except Exception:
        return False


def generate_self_signed_cert(cert_path=DEFAULT_CERT_PATH, key_path=DEFAULT_KEY_PATH, extra_ips=None):
    """
    Generate a self-signed TLS certificate and private key for the server.
    Includes localhost, 127.0.0.1, the current LAN IP, and any extra IPs
    in the Subject Alternative Name (SAN) extension so clients can verify it.
    """
    cert_dir = os.path.dirname(cert_path)
    if cert_dir and not os.path.exists(cert_dir):
        os.makedirs(cert_dir, exist_ok=True)

    lan_ip = get_local_lan_ip()
    ip_strings = ["127.0.0.1"]
    if lan_ip and lan_ip not in ip_strings:
        ip_strings.append(lan_ip)
    if extra_ips:
        for ip_str in extra_ips:
            if ip_str and ip_str not in ip_strings:
                ip_strings.append(ip_str)

    san_entries = [x509.DNSName("localhost")]
    for ip_str in ip_strings:
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_str)))
        except ValueError:
            san_entries.append(x509.DNSName(ip_str))

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureShare PBL"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureShare Server"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(private_key, hashes.SHA256())
    )

    # Save TLS private key with owner-only permissions
    with open(key_path, "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass

    # Save public TLS certificate (safe to share with client laptops)
    with open(cert_path, "wb") as cert_file:
        cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

    return ip_strings


def ensure_server_certificate(cert_path=DEFAULT_CERT_PATH, key_path=DEFAULT_KEY_PATH, extra_ips=None, force=False):
    """Ensure valid TLS certificate and private key exist for the current network IP."""
    lan_ip = get_local_lan_ip()
    needs_generation = force or (not os.path.exists(cert_path)) or (not os.path.exists(key_path))

    if not needs_generation and not cert_has_ip(cert_path, lan_ip):
        print(f"Network IP changed to {lan_ip}. Updating TLS certificate SAN list...")
        needs_generation = True

    if not needs_generation and extra_ips:
        for ip_str in extra_ips:
            if not cert_has_ip(cert_path, ip_str):
                needs_generation = True
                break

    if needs_generation:
        ips = generate_self_signed_cert(cert_path, key_path, extra_ips=extra_ips)
        print("Generated new TLS certificate for IPs:", ", ".join(ips))
        print("Public certificate saved at:", cert_path)
        print("IMPORTANT: Copy server.crt (NOT server.key) to client laptops for TLS verification.")


# ---------------------------------------------------------------------------
# 2. Network Framing Helpers (Length-Prefixed JSON + Binary Chunk Streaming)
# ---------------------------------------------------------------------------

def recv_exact(sock, num_bytes):
    """Read exactly num_bytes from the socket or raise ConnectionError if interrupted."""
    chunks = []
    received = 0
    while received < num_bytes:
        chunk = sock.recv(num_bytes - received)
        if not chunk:
            raise ConnectionError("Client disconnected unexpectedly.")
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def send_json(sock, data_dict):
    """Send a JSON dictionary prefixed with its 4-byte unsigned length."""
    json_bytes = json.dumps(data_dict).encode("utf-8")
    if len(json_bytes) > MAX_HEADER_SIZE:
        raise ValueError("Response header exceeds maximum size.")
    length_prefix = struct.pack(">I", len(json_bytes))
    sock.sendall(length_prefix + json_bytes)


def recv_json(sock):
    """Receive a 4-byte length-prefixed JSON dictionary from the socket."""
    length_bytes = recv_exact(sock, 4)
    header_len = struct.unpack(">I", length_bytes)[0]
    if header_len == 0 or header_len > MAX_HEADER_SIZE:
        raise ValueError("Invalid header length received.")
    json_bytes = recv_exact(sock, header_len)
    return json.loads(json_bytes.decode("utf-8"))


# ---------------------------------------------------------------------------
# 3. Request Handlers
# ---------------------------------------------------------------------------

def require_session(request, active_sessions):
    """Validate session token from request and return username, or None if invalid."""
    token = request.get("token", "")
    if not token:
        return None
    return active_sessions.get(token)


def handle_upload(tls_conn, request, sender, db_path, files_dir):
    """Validate upload metadata, confirm ready, and stream encrypted chunks to disk."""
    receiver = str(request.get("receiver", "")).strip().lower()
    original_filename = os.path.basename(str(request.get("filename", "file"))) or "file"
    file_size = request.get("file_size", 0)
    sha256 = str(request.get("sha256", ""))
    payload_size = request.get("payload_size", 0)

    if not receiver or database.get_user(receiver, db_path=db_path) is None:
        send_json(tls_conn, {"status": "error", "message": "Recipient user not found."})
        return

    if not isinstance(payload_size, int) or payload_size <= 0 or payload_size > MAX_FILE_SIZE:
        send_json(tls_conn, {"status": "error", "message": "Invalid encrypted file payload size."})
        return

    # Signal client to start streaming encrypted binary chunks
    send_json(tls_conn, {"status": "ready"})

    # Store file under a safe random UUID name (never trust client filename on disk)
    stored_filename = uuid.uuid4().hex + ".enc"
    stored_path = os.path.join(files_dir, stored_filename)

    bytes_received = 0
    try:
        with open(stored_path, "wb") as out_file:
            while bytes_received < payload_size:
                to_read = min(CHUNK_SIZE, payload_size - bytes_received)
                chunk = tls_conn.recv(to_read)
                if not chunk:
                    raise ConnectionError("Upload interrupted before completion.")
                out_file.write(chunk)
                bytes_received += len(chunk)
    except Exception as exc:
        # Remove incomplete file if transfer fails
        if os.path.exists(stored_path):
            os.remove(stored_path)
        raise exc

    file_id = database.save_file_record(
        sender=sender,
        receiver=receiver,
        original_filename=original_filename,
        stored_filename=stored_filename,
        file_size=file_size,
        sha256=sha256,
        db_path=db_path
    )

    send_json(tls_conn, {
        "status": "ok",
        "file_id": file_id,
        "message": "Encrypted file uploaded successfully for " + receiver + "."
    })


def handle_download(tls_conn, request, username, db_path, files_dir):
    """Authorize recipient and stream encrypted file chunks back to the client."""
    file_id = request.get("file_id")
    if not isinstance(file_id, int):
        send_json(tls_conn, {"status": "error", "message": "Valid file_id is required."})
        return

    record = database.get_file_by_id(file_id, db_path=db_path)
    if record is None:
        send_json(tls_conn, {"status": "error", "message": "File record not found."})
        return

    # Strict access control: only the intended recipient can download this file
    if record["receiver"] != username:
        send_json(tls_conn, {
            "status": "error",
            "message": "Access denied: you are not the intended recipient of this file."
        })
        return

    stored_path = os.path.join(files_dir, record["stored_filename"])
    if not os.path.exists(stored_path):
        send_json(tls_conn, {"status": "error", "message": "Encrypted file is missing on server."})
        return

    payload_size = os.path.getsize(stored_path)
    send_json(tls_conn, {
        "status": "ok",
        "filename": record["original_filename"],
        "sender": record["sender"],
        "file_size": record["file_size"],
        "sha256": record["sha256"],
        "payload_size": payload_size
    })

    # Stream raw encrypted file in chunks
    with open(stored_path, "rb") as in_file:
        while True:
            chunk = in_file.read(CHUNK_SIZE)
            if not chunk:
                break
            tls_conn.sendall(chunk)


def process_client_request(tls_conn, active_sessions, db_path, files_dir):
    """Process a single request received over a TLS connection."""
    request = recv_json(tls_conn)
    action = request.get("action", "")

    if action == "PING":
        send_json(tls_conn, {"status": "ok", "message": "SecureShare server is running."})
        return

    if action == "REGISTER":
        username = str(request.get("username", ""))
        password = str(request.get("password", ""))
        public_key = str(request.get("public_key", ""))
        success, msg = auth.register_user(username, password, public_key, db_path=db_path)
        if success:
            send_json(tls_conn, {"status": "ok", "message": msg})
        else:
            send_json(tls_conn, {"status": "error", "message": msg})
        return

    if action == "LOGIN":
        username = str(request.get("username", ""))
        password = str(request.get("password", ""))
        success, msg = auth.login_user(username, password, db_path=db_path)
        if not success:
            send_json(tls_conn, {"status": "error", "message": msg})
            return

        # Create in-memory session token
        clean_user = username.strip().lower()
        token = secrets.token_hex(32)
        active_sessions[token] = clean_user
        send_json(tls_conn, {
            "status": "ok",
            "token": token,
            "username": clean_user,
            "message": msg
        })
        return

    if action == "LOGOUT":
        token = request.get("token", "")
        if token in active_sessions:
            del active_sessions[token]
        send_json(tls_conn, {"status": "ok", "message": "Logged out."})
        return

    # All remaining actions require an active authenticated session
    current_user = require_session(request, active_sessions)
    if current_user is None:
        send_json(tls_conn, {"status": "error", "message": "Authentication required. Please log in."})
        return

    if action == "LIST_USERS":
        users = database.list_users(db_path=db_path)
        send_json(tls_conn, {"status": "ok", "users": users})

    elif action == "GET_PUBLIC_KEY":
        target_user = str(request.get("username", "")).strip().lower()
        pub_key = database.get_public_key(target_user, db_path=db_path)
        if pub_key is None:
            send_json(tls_conn, {"status": "error", "message": "User '" + target_user + "' not found."})
        else:
            send_json(tls_conn, {"status": "ok", "public_key": pub_key})

    elif action == "UPLOAD_FILE":
        handle_upload(tls_conn, request, current_user, db_path, files_dir)

    elif action == "LIST_RECEIVED":
        files = database.get_received_files(current_user, db_path=db_path)
        send_json(tls_conn, {"status": "ok", "files": files})

    elif action == "LIST_HISTORY":
        files = database.get_file_history(current_user, db_path=db_path)
        send_json(tls_conn, {"status": "ok", "files": files})

    elif action == "DOWNLOAD_FILE":
        handle_download(tls_conn, request, current_user, db_path, files_dir)

    else:
        send_json(tls_conn, {"status": "error", "message": "Unknown request action."})


# ---------------------------------------------------------------------------
# 4. Main Server Loop
# ---------------------------------------------------------------------------

def run_server(
    host=DEFAULT_HOST,
    port=DEFAULT_PORT,
    cert_path=DEFAULT_CERT_PATH,
    key_path=DEFAULT_KEY_PATH,
    db_path=database.DEFAULT_DB_PATH,
    files_dir=database.FILES_DIR,
    extra_ips=None,
    force_cert=False,
    ready_callback=None,
    stop_flag=None
):
    """Start the sequential TLS TCP server and process client requests continuously."""
    database.ensure_server_directories(files_dir=files_dir)
    database.init_db(db_path=db_path)
    ensure_server_certificate(cert_path=cert_path, key_path=key_path, extra_ips=extra_ips, force=force_cert)

    # Configure TLS context for server
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    # Active session tokens kept strictly in memory (cleared when server stops)
    active_sessions = {}

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(5)

    # Use short timeout when stop_flag is provided (e.g. during unit tests)
    if stop_flag is not None:
        server_sock.settimeout(0.2)

    actual_port = server_sock.getsockname()[1]
    lan_ip = get_local_lan_ip()

    print("\n=== SecureShare TLS Server Started ===")
    print(f"Listening on:    {host}:{actual_port}")
    print(f"LAN IP Address:  {lan_ip} (give this IP to clients on the same Wi-Fi)")
    print(f"Database:        {db_path}")
    print(f"Storage Folder:  {files_dir}")
    print("Waiting for connections... (Press Ctrl+C to stop)\n")

    if ready_callback is not None:
        ready_callback(actual_port)

    try:
        while True:
            if stop_flag is not None and stop_flag.get("stop"):
                break

            try:
                raw_conn, client_addr = server_sock.accept()
            except socket.timeout:
                continue

            raw_conn.settimeout(30)
            try:
                with ssl_context.wrap_socket(raw_conn, server_side=True) as tls_conn:
                    process_client_request(tls_conn, active_sessions, db_path, files_dir)
            except ssl.SSLError as exc:
                print(f"[TLS Error] from {client_addr}: {exc}")
            except ConnectionError as exc:
                print(f"[Connection Closed] {client_addr}: {exc}")
            except Exception as exc:
                print(f"[Request Error] {client_addr}: {exc}")
            finally:
                try:
                    raw_conn.close()
                except OSError:
                    pass
    except KeyboardInterrupt:
        print("\nServer shutting down cleanly...")
    finally:
        server_sock.close()


def main():
    parser = argparse.ArgumentParser(description="Start the SecureShare TLS File Sharing Server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Bind IP address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Listen port (default: 5555)")
    parser.add_argument("--ip", action="append", help="Extra LAN IP to include in TLS certificate")
    parser.add_argument("--gen-cert", action="store_true", help="Force regenerate TLS certificate")
    args = parser.parse_args()

    run_server(
        host=args.host,
        port=args.port,
        extra_ips=args.ip,
        force_cert=args.gen_cert
    )


if __name__ == "__main__":
    main()
