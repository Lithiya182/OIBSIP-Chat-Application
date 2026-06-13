
import socket
import threading
import logging

from cryptography.fernet import Fernet

import crypto
import storage
import network
from network import (
    TAG_HISTORY_TEXT, TAG_HISTORY_IMAGE, TAG_IMAGE,
    TAG_TYPING, TAG_USERS, TAG_AUTH_OK, TAG_AUTH_FAIL,
    send_encrypted, recv_encrypted, recv_encrypted_bytes,
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# Server setup
storage.init_db()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((network.HOST, network.PORT))
server_socket.listen()
logger.info("Server listening on %s:%s", network.HOST, network.PORT)

rsa_private_key = crypto.generate_rsa_keypair()
rsa_public_pem  = crypto.export_public_key(rsa_private_key)

_lock    = threading.Lock()
clients  : dict[str, socket.socket] = {}
ciphers  : dict[str, Fernet]        = {}

def broadcast(message: str, exclude: str | None = None):

    with _lock:
        targets = {u: (s, ciphers[u]) for u, s in clients.items() if u != exclude}
    for username, (sock, cipher) in targets.items():
        try:
            send_encrypted(sock, cipher, message)
        except OSError as e:
            logger.warning("Broadcast to %s failed: %s", username, e)


def broadcast_users():

    with _lock:
        user_list = ",".join(clients.keys())
    broadcast(f"{TAG_USERS}{user_list}")


def send_to(username: str, message: str):

    with _lock:
        sock   = clients.get(username)
        cipher = ciphers.get(username)
    if sock and cipher:
        try:
            send_encrypted(sock, cipher, message)
        except OSError as e:
            logger.warning("Private send to %s failed: %s", username, e)


# History streaming

def stream_history(username: str, sock: socket.socket, cipher: Fernet):

    history = storage.load_history()
    logger.info("Streaming %d history entries to %s", len(history), username)
    for row in history:
        try:
            if row["msg_type"] == "text":
                msg = f"{TAG_HISTORY_TEXT}{row['timestamp']}|{row['sender']}|{row['content']}"
                send_encrypted(sock, cipher, msg)

            elif row["msg_type"] == "image":
                img_bytes = storage.load_image_bytes(row["content"])
                if img_bytes is None:
                    continue
                header = f"{TAG_HISTORY_IMAGE}{len(img_bytes)}|{row['sender']}|{row['timestamp']}"
                send_encrypted(sock, cipher, header)

                send_encrypted(sock, cipher, img_bytes)

        except (OSError, Exception) as e:
            logger.exception("History stream error for %s: %s", username, e)
            break


# Client handler

def handle_client(username: str, sock: socket.socket, cipher: Fernet):
    while True:
        try:
            message = recv_encrypted(sock, cipher)

            if message.startswith(TAG_TYPING):
                broadcast(message, exclude=username)
                continue

            if message.startswith(TAG_IMAGE):

                parts = message.split("|")
                if len(parts) < 3:
                    logger.warning("Malformed image header from %s", username)
                    continue
                declared_size = int(parts[1])
                sender        = parts[2]


                img_bytes = recv_encrypted_bytes(sock, cipher)

                if len(img_bytes) != declared_size:
                    logger.warning(
                        "Image size mismatch from %s: declared %d got %d",
                        username, declared_size, len(img_bytes),
                    )
                    continue

                if not storage.is_valid_image(img_bytes):
                    logger.warning("Invalid image magic bytes from %s — dropped", username)
                    continue

                storage.save_image_message(sender, img_bytes)

                relay_header = f"{TAG_IMAGE}{len(img_bytes)}|{sender}"
                broadcast(relay_header)

                with _lock:
                    targets = {u: (s, ciphers[u]) for u, s in clients.items()}
                for uname, (csock, ccipher) in targets.items():
                    try:
                        send_encrypted(csock, ccipher, img_bytes)
                    except OSError as e:
                        logger.warning("Image relay to %s failed: %s", uname, e)
                continue

            parts = message.split(" ", 2)
            if len(parts) >= 3 and parts[1] == "/msg":
                recipient     = parts[2].split(" ", 1)[0]
                private_text  = parts[2].split(" ", 1)[1] if " " in parts[2] else ""
                sender_name   = parts[0].rstrip(":")
                send_to(recipient, f"{sender_name} (private): {private_text}")
                continue

            if ":" in message:
                sender_name, body = message.split(":", 1)
                storage.save_message(sender_name.strip(), body.strip())
            broadcast(message)

        except ConnectionError as e:
            logger.info("%s disconnected: %s", username, e)
            break
        except Exception as e:
            logger.exception("Unexpected error handling %s: %s", username, e)
            break

    with _lock:
        clients.pop(username, None)
        ciphers.pop(username, None)
    sock.close()
    logger.info("%s removed from session", username)
    broadcast(f"{username} left the chat!")
    broadcast_users()

def authenticate_client(sock: socket.socket, address):
    try:
        from crypto import frame
        sock.sendall(frame(rsa_public_pem))

        encrypted_session_key = crypto.recv_frame(sock)
        session_key = crypto.decrypt_session_key(rsa_private_key, encrypted_session_key)
        cipher = Fernet(session_key)

        logger.info("Key exchange complete with %s", address)

        while True:
            try:
                auth_data = recv_encrypted(sock, cipher)
            except ConnectionError:
                logger.info("Client %s disconnected during auth", address)
                sock.close()
                return

            if ":" not in auth_data or not (
                auth_data.startswith("LOGIN") or auth_data.startswith("REGISTER")
            ):
                continue

            try:
                action, username, password = auth_data.split(":", 2)
            except ValueError:
                continue

            username = username.strip()
            if not username or not password:
                send_encrypted(sock, cipher, f"{TAG_AUTH_FAIL}Fields cannot be empty.")
                continue

            if action == "REGISTER":
                if storage.register_user(username, password):
                    send_encrypted(sock, cipher, TAG_AUTH_OK)
                    break
                else:
                    send_encrypted(sock, cipher, f"{TAG_AUTH_FAIL}Username already exists.")

            elif action == "LOGIN":
                with _lock:
                    already_on = username in clients
                if already_on:
                    send_encrypted(sock, cipher, f"{TAG_AUTH_FAIL}User already logged in.")
                elif storage.verify_user(username, password):
                    send_encrypted(sock, cipher, TAG_AUTH_OK)
                    break
                else:
                    send_encrypted(sock, cipher, f"{TAG_AUTH_FAIL}Invalid username or password.")

        with _lock:
            clients[username] = sock
            ciphers[username] = cipher

        logger.info("%s authenticated from %s", username, address)

        stream_history(username, sock, cipher)
        broadcast(f"{username} joined the chat!")
        broadcast_users()

        handle_client(username, sock, cipher)

    except Exception as e:
        logger.exception("Auth error from %s: %s", address, e)
        sock.close()


# Accept loop

def accept_loop():
    while True:
        try:
            sock, address = server_socket.accept()
            threading.Thread(
                target=authenticate_client,
                args=(sock, address),
                daemon=True,
            ).start()
        except OSError as e:
            logger.error("Accept error: %s", e)
            break


accept_loop()
