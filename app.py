import socket
import struct
import threading
import select
import time

# =========================
# CONFIGURATION
# =========================

HOST = "0.0.0.0"
PORT = 1080

USERNAME = "alex"
PASSWORD = "change-this-password"

BUFFER_SIZE = 65536
CONNECTION_TIMEOUT = 15
MAX_CONNECTIONS = 100

active_connections = 0
connection_lock = threading.Lock()


# =========================
# LOGGING
# =========================

def log(message):
    print(f"[SOCKS5] {message}", flush=True)


# =========================
# SEND SOCKS5 RESPONSE
# =========================

def socks_response(client, reply, address="0.0.0.0", port=0):
    try:
        ip = socket.inet_aton(address)

        response = (
            b"\x05" +
            bytes([reply]) +
            b"\x00" +
            b"\x01" +
            ip +
            struct.pack("!H", port)
        )

        client.sendall(response)

    except Exception:
        pass


# =========================
# AUTHENTICATION
# =========================

def authenticate(client):

    # Username/password authentication
    #
    # RFC 1929:
    #
    #  +----+------+----------+------+----------+
    #  |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    #  +----+------+----------+------+----------+

    data = client.recv(2)

    if len(data) != 2:
        return False

    version = data[0]
    username_length = data[1]

    if version != 1:
        return False

    username = client.recv(username_length)

    if len(username) != username_length:
        return False

    password_length_data = client.recv(1)

    if len(password_length_data) != 1:
        return False

    password_length = password_length_data[0]

    password = client.recv(password_length)

    if len(password) != password_length:
        return False

    username = username.decode("utf-8", errors="ignore")
    password = password.decode("utf-8", errors="ignore")

    if username == USERNAME and password == PASSWORD:

        client.sendall(b"\x01\x00")

        return True

    client.sendall(b"\x01\x01")

    return False


# =========================
# SOCKS5 HANDSHAKE
# =========================

def handshake(client):

    # Client sends:
    #
    # VER
    # NMETHODS
    # METHODS

    header = client.recv(2)

    if len(header) != 2:
        return False

    version = header[0]
    method_count = header[1]

    if version != 5:
        return False

    methods = client.recv(method_count)

    if len(methods) != method_count:
        return False

    # Require username/password authentication
    if 0x02 not in methods:

        # 0xFF = no acceptable methods
        client.sendall(b"\x05\xff")

        return False

    # Select username/password authentication
    client.sendall(b"\x05\x02")

    return authenticate(client)


# =========================
# READ DESTINATION
# =========================

def read_destination(client):

    # Request:
    #
    # VER
    # CMD
    # RSV
    # ATYP
    # DST.ADDR
    # DST.PORT

    header = client.recv(4)

    if len(header) != 4:
        return None

    version = header[0]
    command = header[1]
    address_type = header[3]

    if version != 5:
        return None

    # Only CONNECT supported
    if command != 1:
        socks_response(client, 0x07)
        return None

    # IPv4
    if address_type == 1:

        data = client.recv(4)

        if len(data) != 4:
            return None

        address = socket.inet_ntoa(data)

    # Domain name
    elif address_type == 3:

        length_data = client.recv(1)

        if len(length_data) != 1:
            return None

        length = length_data[0]

        domain = client.recv(length)

        if len(domain) != length:
            return None

        address = domain.decode("utf-8", errors="ignore")

    # IPv6
    elif address_type == 4:

        data = client.recv(16)

        if len(data) != 16:
            return None

        address = socket.inet_ntop(
            socket.AF_INET6,
            data
        )

    else:
        socks_response(client, 0x08)
        return None

    port_data = client.recv(2)

    if len(port_data) != 2:
        return None

    port = struct.unpack("!H", port_data)[0]

    return address, port


# =========================
# CONNECT TO DESTINATION
# =========================

def connect_destination(address, port):

    try:

        destination = socket.create_connection(
            (address, port),
            timeout=CONNECTION_TIMEOUT
        )

        destination.settimeout(None)

        return destination

    except Exception as error:

        log(f"Connection failed: {address}:{port} ({error})")

        return None


# =========================
# RELAY DATA
# =========================

def relay(client, destination):

    sockets = [client, destination]

    while True:

        try:

            readable, _, exceptional = select.select(
                sockets,
                [],
                sockets,
                60
            )

            if exceptional:
                break

            if not readable:
                break

            for source in readable:

                data = source.recv(BUFFER_SIZE)

                if not data:
                    return

                if source is client:
                    destination.sendall(data)

                else:
                    client.sendall(data)

        except Exception:
            break


# =========================
# HANDLE CLIENT
# =========================

def handle_client(client, address):

    global active_connections

    with connection_lock:

        active_connections += 1

    log(f"Client connected: {address}")

    destination = None

    try:

        client.settimeout(CONNECTION_TIMEOUT)

        # SOCKS5 negotiation
        if not handshake(client):

            log(f"Authentication failed: {address}")

            return

        log(f"Authenticated: {address}")

        # Get requested destination
        target = read_destination(client)

        if not target:
            return

        destination_host, destination_port = target

        log(
            f"{address} -> "
            f"{destination_host}:{destination_port}"
        )

        # Connect to destination
        destination = connect_destination(
            destination_host,
            destination_port
        )

        if destination is None:

            socks_response(
                client,
                0x05
            )

            return

        # Tell SOCKS5 client connection succeeded
        local_address = destination.getsockname()

        socks_response(
            client,
            0x00,
            local_address[0],
            local_address[1]
        )

        # Relay data
        client.settimeout(None)

        relay(
            client,
            destination
        )

    except Exception as error:

        log(
            f"Client error {address}: {error}"
        )

    finally:

        try:
            client.close()
        except:
            pass

        if destination:

            try:
                destination.close()
            except:
                pass

        with connection_lock:
            active_connections -= 1

        log(f"Client disconnected: {address}")


# =========================
# START SERVER
# =========================

def start_server():

    global active_connections

    server = socket.socket(
        socket.AF_INET6,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    # Allow IPv4 connections too
    server.setsockopt(
        socket.IPPROTO_IPV6,
        socket.IPV6_V6ONLY,
        0
    )

    server.bind(
        (HOST, PORT)
    )

    server.listen(100)

    log(
        f"SOCKS5 server listening on "
        f"{HOST}:{PORT}"
    )

    log(
        f"Username: {USERNAME}"
    )

    while True:

        try:

            client, address = server.accept()

            with connection_lock:

                if active_connections >= MAX_CONNECTIONS:

                    log(
                        f"Connection limit reached: {address}"
                    )

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

            server.close()

            break

        except Exception as error:

            log(
                f"Server error: {error}"
            )


# =========================
# MAIN
# =========================

if __name__ == "__main__":

    start_server()