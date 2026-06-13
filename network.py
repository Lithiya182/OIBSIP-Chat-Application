"""
network.py — Shared protocol constants and encrypted send helpers.

Both server.py and chat_gui.py import from here so the wire protocol
stays consistent and isn't duplicated.
"""

HOST = "127.0.0.1"
PORT = 55555

# ── Protocol tags ─────────────────────────────────────────────────────
TAG_HISTORY_TEXT  = "__HISTORY__|"
TAG_HISTORY_IMAGE = "__HISTORY_IMAGE__|"
TAG_IMAGE         = "__IMAGE_TRANSFER__|"   # note: | not : (avoids split confusion)
TAG_TYPING        = "__TYPING__|"
TAG_USERS         = "__USERS__|"
TAG_AUTH_OK       = "AUTH_SUCCESS"
TAG_AUTH_FAIL     = "AUTH_FAIL:"


def send_encrypted(sock, cipher, data: bytes | str):
    """
    Encrypt *data* with *cipher* (Fernet), frame it, and send.
    Accepts bytes or str; str is UTF-8 encoded automatically.
    """
    from crypto import frame
    if isinstance(data, str):
        data = data.encode()
    sock.sendall(frame(cipher.encrypt(data)))


def recv_encrypted(sock, cipher) -> str:
    """
    Receive one framed message, decrypt, and return as str.
    Raises ConnectionError on socket close.
    """
    from crypto import recv_frame
    payload = recv_frame(sock)
    return cipher.decrypt(payload).decode()


def recv_encrypted_bytes(sock, cipher) -> bytes:
    """Like recv_encrypted but returns raw decrypted bytes (for images)."""
    from crypto import recv_frame
    payload = recv_frame(sock)
    return cipher.decrypt(payload)
