import socket
import struct
import threading
import select
import os
import logging

# ============================================================
# CONFIGURATION (Environment Variables)
# ============================================================

HOST = os.environ.get("SOCKS5_HOST", "::")          # Use "::" for dual-stack, "0.0.0.0" for IPv4 only
PORT = int(os.environ.get("SOCKS5_PORT", "1080"))
USERNAME = os.environ.get("SOCKS5_USERNAME", "alex")
PASSWORD = os.environ.get("SOCKS5_PASSWORD", "change-this-password")

BUFFER_SIZE = 65536
CONNECTION_TIMEOUT = 15
MAX_CONNECTIONS = 100
MAX_HTTP_HEADER_SIZE = 65536

active_connections = 0
connection_lock = threading.Lock()

# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.info

# ============================================================
# HELPER: RECEIVE EXACTLY N BYTES
# ============================================================

def recv_exact(sock, length):
    data = b""
    while len(data) < length:
        try:
            chunk = sock.recv(length - len(data))
        except socket.timeout:
            return None
        except OSError:
            return None
        if not chunk:
            return None
        data += chunk
    return data

# ============================================================
# BUILD SOCKS5 RESPONSE
# ============================================================

def build_response(reply, address="0.0.0.0", port=0):
    try:
        ip_bytes = socket.inet_pton(socket.AF_INET, address)
        atyp = 0x01
    except OSError:
        try:
            ip_bytes = socket.inet_pton(socket.AF_INET6, address)
            atyp = 0x04
        except OSError:
            ip_bytes = b"\x00\x00\x00\x00"
            atyp = 0x01
    return b"\x05" + bytes([reply]) + b"\x00" + bytes([atyp]) + ip_bytes + struct.pack("!H", port)

def socks_response(client, reply, address="0.0.0.0", port=0):
    try:
        client.sendall(build_response(reply, address, port))
    except OSError:
        pass

# ============================================================
# AUTHENTICATION (RFC 1929)
# ============================================================

def authenticate(client):
    header = recv_exact(client, 2)
    if header is None:
        return False
    version, ulen = header[0], header[1]

    if version != 1:
        client.sendall(b"\x01\x01")
        return False

    username = recv_exact(client, ulen)
    if username is None:
        return False

    plen_data = recv_exact(client, 1)
    if plen_data is None:
        return False
    plen = plen_data[0]

    password = recv_exact(client, plen)
    if password is None:
        return False

    username = username.decode("utf-8", errors="ignore")
    password = password.decode("utf-8", errors="ignore")

    if username == USERNAME and password == PASSWORD:
        client.sendall(b"\x01\x00")
        return True

    client.sendall(b"\x01\x01")
    return False

# ============================================================
# SOCKS5 HANDSHAKE
# ============================================================

def handshake(client):
    header = recv_exact(client, 2)
    if header is None:
        return False
    version, nmethods = header[0], header[1]

    if version != 5:
        return False

    methods = recv_exact(client, nmethods)
    if methods is None:
        return False

    if 0x02 not in methods:
        client.sendall(b"\x05\xff")
        return False

    client.sendall(b"\x05\x02")
    return authenticate(client)

# ============================================================
# READ DESTINATION REQUEST
# ============================================================

def read_destination(client):
    header = recv_exact(client, 4)
    if header is None:
        return None
    version, command, rsv, atyp = header[0], header[1], header[2], header[3]

    if version != 5 or rsv != 0:
        socks_response(client, 0x01)
        return None

    if command != 0x01:  # Only CONNECT supported
        socks_response(client, 0x07)
        return None

    if atyp == 0x01:  # IPv4
        data = recv_exact(client, 4)
        if data is None:
            return None
        address = socket.inet_ntop(socket.AF_INET, data)

    elif atyp == 0x03:  # Domain name
        len_data = recv_exact(client, 1)
        if len_data is None:
            return None
        length = len_data[0]
        domain = recv_exact(client, length)
        if domain is None:
            return None
        address = domain.decode("utf-8", errors="ignore")

    elif atyp == 0x04:  # IPv6
        data = recv_exact(client, 16)
        if data is None:
            return None
        address = socket.inet_ntop(socket.AF_INET6, data)

    else:
        socks_response(client, 0x08)
        return None

    port_data = recv_exact(client, 2)
    if port_data is None:
        return None
    port = struct.unpack("!H", port_data)[0]

    return address, port

# ============================================================
# CONNECT TO DESTINATION
# ============================================================

def connect_destination(address, port):
    try:
        destination = socket.create_connection((address, port), timeout=CONNECTION_TIMEOUT)
        destination.settimeout(None)
        return destination
    except Exception as error:
        log(f"Connection failed: {address}:{port} ({error})")
        return None

# ============================================================
# RELAY DATA
# ============================================================

def relay(client, destination):
    sockets = [client, destination]
    while True:
        try:
            readable, _, exceptional = select.select(sockets, [], sockets)
            if exceptional:
                break
            for source in readable:
                data = source.recv(BUFFER_SIZE)
                if not data:
                    return
                if source is client:
                    destination.sendall(data)
                else:
                    client.sendall(data)
        except (socket.error, OSError):
            break

# ============================================================
# MINI HTTP SERVER (for home page)
# ============================================================

def serve_homepage(client):
    html = """<!DOCTYPE html>
<html>
<head>
    <title>SOCKS5 Proxy Server</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 40px; text-align: center; }
        .container { background: white; max-width: 600px; margin: auto; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        p { color: #666; }
        code { background: #eee; padding: 2px 5px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>SOCKS5 Proxy Server</h1>
        <p>This server is running as a SOCKS5 proxy.</p>
        <p>Configure your application to use <code>proxy-address:port</code> with your credentials.</p>
        <p>For web browsing, set up the proxy in your browser's network settings.</p>
    </div>
</body>
</html>"""
    body = html.encode("utf-8")
    response = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("iso-8859-1") + body
    try:
        client.sendall(response)
    except OSError:
        pass

def handle_http_direct(client):
    """Read a simple HTTP GET request and serve the homepage."""
    data = b""
    while b"\r\n\r\n" not in data:
        try:
            chunk = client.recv(4096)
        except socket.timeout:
            return
        except OSError:
            return
        if not chunk:
            return
        data += chunk
        if len(data) > MAX_HTTP_HEADER_SIZE:
            return
    # Only handle GET / (or any path) for simplicity
    serve_homepage(client)

# ============================================================
# HANDLE CLIENT CONNECTION (SOCKS5 OR HTTP)
# ============================================================

def handle_client(client, address):
    global active_connections

    with connection_lock:
        active_connections += 1
    log(f"Client connected: {address}")

    destination = None
    try:
        client.settimeout(CONNECTION_TIMEOUT)

        # Peek at first byte to decide protocol
        first_byte = client.recv(1, socket.MSG_PEEK)
        if not first_byte:
            return

        # If first byte is 0x05, it's SOCKS5
        if first_byte == b"\x05":
            # SOCKS5 negotiation
            if not handshake(client):
                log(f"Authentication failed: {address}")
                return
            log(f"Authenticated: {address}")

            target = read_destination(client)
            if not target:
                return
            dest_host, dest_port = target
            log(f"{address} -> {dest_host}:{dest_port}")

            destination = connect_destination(dest_host, dest_port)
            if destination is None:
                socks_response(client, 0x05)
                return

            local_ip, local_port = destination.getsockname()
            socks_response(client, 0x00, local_ip, local_port)

            client.settimeout(None)
            relay(client, destination)

        else:
            # Assume HTTP request to the proxy itself
            handle_http_direct(client)

    except Exception as error:
        log(f"Client error {address}: {error}")
    finally:
        try:
            client.close()
        except OSError:
            pass
        if destination:
            try:
                destination.close()
            except OSError:
                pass
        with connection_lock:
            active_connections -= 1
        log(f"Client disconnected: {address}")

# ============================================================
# CREATE SERVER SOCKET (IPv6 dual-stack with IPv4 fallback)
# ============================================================

def create_server_socket(host, port):
    if ':' in host or host in ('', '::'):
        try:
            server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            server.bind((host if host else '::', port))
            server.listen(100)
            return server
        except (OSError, socket.error) as e:
            server.close()
            if host in ('', '::'):
                log(f"IPv6 bind failed: {e}, falling back to IPv4")
            else:
                raise

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bind_host = '0.0.0.0' if host in ('', '::') else host
    server.bind((bind_host, port))
    server.listen(100)
    return server

# ============================================================
# START SERVER
# ============================================================

def start_server():
    global active_connections

    try:
        server = create_server_socket(HOST, PORT)
    except Exception as error:
        log(f"Failed to start server: {error}")
        return

    log(f"SOCKS5 proxy listening on {HOST}:{PORT}")
    log(f"Username: {USERNAME}")
    log(f"Home page available at http://<server-address>:{PORT}/")

    try:
        while True:
            try:
                client, address = server.accept()

                with connection_lock:
                    if active_connections >= MAX_CONNECTIONS:
                        log(f"Connection limit reached: {address}")
                        client.close()
                        continue

                thread = threading.Thread(
                    target=handle_client,
                    args=(client, address),
                    daemon=True
                )
                thread.start()

            except KeyboardInterrupt:
                log("Server shutting down")
                break
            except Exception as error:
                log(f"Server error: {error}")
    finally:
        server.close()

# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    start_server()