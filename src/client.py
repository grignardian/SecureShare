"""
client.py - TLS Network Client for SecureShare
----------------------------------------------
Connects to the SecureShare server using TCP sockets protected with TLS.
Handles:
- Connecting and verifying the server's public TLS certificate (certs/server.crt)
- Registering and logging in users
- Retrieving recipient public keys
- Streaming encrypted file uploads in binary chunks
- Listing received files and transfer history
- Streaming encrypted file downloads in binary chunks
"""

import os
import ssl
import json
import socket
import struct


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DEFAULT_CERT_PATH = os.path.join(PROJECT_ROOT, "certs", "server.crt")

CHUNK_SIZE = 4096
MAX_HEADER_SIZE = 64 * 1024


# ---------------------------------------------------------------------------
# 1. Socket & TLS Connection Helpers
# ---------------------------------------------------------------------------

def recv_exact(sock, num_bytes):
    """Read exactly num_bytes from the socket or raise ConnectionError."""
    chunks = []
    received = 0
    while received < num_bytes:
        chunk = sock.recv(num_bytes - received)
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly by the server.")
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def send_json(sock, data_dict):
    """Send a length-prefixed JSON message over the socket."""
    json_bytes = json.dumps(data_dict).encode("utf-8")
    if len(json_bytes) > MAX_HEADER_SIZE:
        raise ValueError("Request header is too large.")
    length_prefix = struct.pack(">I", len(json_bytes))
    sock.sendall(length_prefix + json_bytes)


def recv_json(sock):
    """Receive a length-prefixed JSON response from the socket."""
    length_bytes = recv_exact(sock, 4)
    header_len = struct.unpack(">I", length_bytes)[0]
    if header_len == 0 or header_len > MAX_HEADER_SIZE:
        raise ValueError("Invalid response length received from server.")
    json_bytes = recv_exact(sock, header_len)
    return json.loads(json_bytes.decode("utf-8"))


def open_tls_connection(server_ip, server_port, cert_path=DEFAULT_CERT_PATH):
    """
    Open a TCP socket to the server and wrap it with verified TLS.
    Requires the server's public certificate file (certs/server.crt).
    """
    if not cert_path or not os.path.exists(cert_path):
        raise FileNotFoundError(
            "Server TLS certificate not found at: " + str(cert_path) + "\n"
            "Copy server.crt from the server laptop into your certs/ folder."
        )

    ssl_context = ssl.create_default_context(cafile=cert_path)
    ssl_context.check_hostname = True
    ssl_context.verify_mode = ssl.CERT_REQUIRED

    try:
        raw_sock = socket.create_connection((server_ip, int(server_port)), timeout=15)
    except socket.timeout:
        raise ConnectionError(f"Connection to {server_ip}:{server_port} timed out.")
    except OSError as exc:
        raise ConnectionError(
            f"Could not connect to server at {server_ip}:{server_port} ({exc}). "
            "Check that the server is running and the IP/port/firewall settings are correct."
        )

    try:
        tls_sock = ssl_context.wrap_socket(raw_sock, server_hostname=server_ip)
        return tls_sock
    except ssl.SSLCertVerificationError as exc:
        raw_sock.close()
        raise ConnectionError(
            f"TLS certificate verification failed for '{server_ip}': {exc}\n"
            "Make sure certs/server.crt matches the server certificate and includes this IP."
        )
    except ssl.SSLError as exc:
        raw_sock.close()
        raise ConnectionError(f"TLS connection failed: {exc}")


def send_simple_request(server_ip, server_port, request_dict, cert_path=DEFAULT_CERT_PATH):
    """Open one TLS connection, send a JSON request, and return the JSON response."""
    tls_sock = open_tls_connection(server_ip, server_port, cert_path=cert_path)
    try:
        send_json(tls_sock, request_dict)
        response = recv_json(tls_sock)
        return response
    finally:
        tls_sock.close()


# ---------------------------------------------------------------------------
# 2. High-Level Client API Functions
# ---------------------------------------------------------------------------

def ping_server(server_ip, server_port, cert_path=DEFAULT_CERT_PATH):
    """Test connection and TLS verification against the server."""
    response = send_simple_request(server_ip, server_port, {"action": "PING"}, cert_path=cert_path)
    if response.get("status") != "ok":
        raise RuntimeError(response.get("message", "Server ping failed."))
    return response.get("message", "Connected.")


def register(server_ip, server_port, username, password, public_key_pem, cert_path=DEFAULT_CERT_PATH):
    """Send registration request and user's RSA public key to the server."""
    request = {
        "action": "REGISTER",
        "username": username,
        "password": password,
        "public_key": public_key_pem
    }
    response = send_simple_request(server_ip, server_port, request, cert_path=cert_path)
    return response.get("status") == "ok", response.get("message", "Unknown response.")


def login(server_ip, server_port, username, password, cert_path=DEFAULT_CERT_PATH):
    """Authenticate user with the server and return (success, token_or_message, clean_username)."""
    request = {
        "action": "LOGIN",
        "username": username,
        "password": password
    }
    response = send_simple_request(server_ip, server_port, request, cert_path=cert_path)
    if response.get("status") == "ok":
        return True, response["token"], response.get("username", username)
    return False, response.get("message", "Login failed."), ""


def logout(server_ip, server_port, token, cert_path=DEFAULT_CERT_PATH):
    """Invalidate the active session token on the server."""
    if not token:
        return
    try:
        send_simple_request(server_ip, server_port, {"action": "LOGOUT", "token": token}, cert_path=cert_path)
    except Exception:
        pass


def list_users(server_ip, server_port, token, cert_path=DEFAULT_CERT_PATH):
    """Fetch list of registered usernames from the server."""
    response = send_simple_request(
        server_ip, server_port,
        {"action": "LIST_USERS", "token": token},
        cert_path=cert_path
    )
    if response.get("status") != "ok":
        raise RuntimeError(response.get("message", "Failed to retrieve users."))
    return response.get("users", [])


def get_public_key(server_ip, server_port, token, target_username, cert_path=DEFAULT_CERT_PATH):
    """Fetch a recipient's RSA public key from the server."""
    response = send_simple_request(
        server_ip, server_port,
        {"action": "GET_PUBLIC_KEY", "token": token, "username": target_username},
        cert_path=cert_path
    )
    if response.get("status") != "ok":
        raise ValueError(response.get("message", "Recipient public key not found."))
    return response["public_key"]


def upload_encrypted_file(
    server_ip,
    server_port,
    token,
    receiver,
    original_filename,
    original_file_size,
    sha256,
    encrypted_file_path,
    cert_path=DEFAULT_CERT_PATH
):
    """
    Upload an already-encrypted binary file to the server in chunks over TLS.
    """
    if not os.path.exists(encrypted_file_path):
        raise FileNotFoundError("Encrypted file missing before upload: " + encrypted_file_path)

    payload_size = os.path.getsize(encrypted_file_path)

    tls_sock = open_tls_connection(server_ip, server_port, cert_path=cert_path)
    try:
        # Step 1: Send JSON metadata header
        header = {
            "action": "UPLOAD_FILE",
            "token": token,
            "receiver": receiver,
            "filename": original_filename,
            "file_size": original_file_size,
            "sha256": sha256,
            "payload_size": payload_size
        }
        send_json(tls_sock, header)

        # Step 2: Wait for server permission to stream bytes
        ready_resp = recv_json(tls_sock)
        if ready_resp.get("status") != "ready":
            raise RuntimeError(ready_resp.get("message", "Server rejected upload."))

        # Step 3: Stream raw binary encrypted file in 4 KB chunks
        with open(encrypted_file_path, "rb") as file_obj:
            while True:
                chunk = file_obj.read(CHUNK_SIZE)
                if not chunk:
                    break
                tls_sock.sendall(chunk)

        # Step 4: Read final confirmation from server
        final_resp = recv_json(tls_sock)
        if final_resp.get("status") != "ok":
            raise RuntimeError(final_resp.get("message", "Upload failed on server."))
        return final_resp
    finally:
        tls_sock.close()


def list_received_files(server_ip, server_port, token, cert_path=DEFAULT_CERT_PATH):
    """Fetch list of files shared with the current user."""
    response = send_simple_request(
        server_ip, server_port,
        {"action": "LIST_RECEIVED", "token": token},
        cert_path=cert_path
    )
    if response.get("status") != "ok":
        raise RuntimeError(response.get("message", "Failed to load received files."))
    return response.get("files", [])


def list_file_history(server_ip, server_port, token, cert_path=DEFAULT_CERT_PATH):
    """Fetch full sent & received file history for the current user."""
    response = send_simple_request(
        server_ip, server_port,
        {"action": "LIST_HISTORY", "token": token},
        cert_path=cert_path
    )
    if response.get("status") != "ok":
        raise RuntimeError(response.get("message", "Failed to load file history."))
    return response.get("files", [])


def download_encrypted_file(
    server_ip,
    server_port,
    token,
    file_id,
    dest_encrypted_path,
    cert_path=DEFAULT_CERT_PATH
):
    """
    Download an encrypted file from the server in chunks over TLS.
    Writes the encrypted bundle to dest_encrypted_path and returns metadata dict.
    """
    tls_sock = open_tls_connection(server_ip, server_port, cert_path=cert_path)
    try:
        send_json(tls_sock, {
            "action": "DOWNLOAD_FILE",
            "token": token,
            "file_id": int(file_id)
        })

        header = recv_json(tls_sock)
        if header.get("status") != "ok":
            raise PermissionError(header.get("message", "Failed to download file."))

        payload_size = header.get("payload_size", 0)
        if payload_size <= 0:
            raise ValueError("Server returned invalid file payload size.")

        bytes_received = 0
        try:
            with open(dest_encrypted_path, "wb") as out_file:
                while bytes_received < payload_size:
                    to_read = min(CHUNK_SIZE, payload_size - bytes_received)
                    chunk = tls_sock.recv(to_read)
                    if not chunk:
                        raise ConnectionError("Download interrupted before file finished.")
                    out_file.write(chunk)
                    bytes_received += len(chunk)
        except Exception as exc:
            if os.path.exists(dest_encrypted_path):
                os.remove(dest_encrypted_path)
            raise exc

        return header
    finally:
        tls_sock.close()
