"""
crypto.py — Key exchange and symmetric encryption helpers.

Flow:
  1. Server generates an RSA key pair on startup.
  2. On each new connection the server sends its RSA public key in PEM format.
  3. The client generates a fresh Fernet session key, encrypts it with the
     server's public key (OAEP/SHA-256), and sends the ciphertext back.
  4. The server decrypts the ciphertext with its private key and both sides
     now share the same Fernet key — never stored in source code.
"""

import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

logger = logging.getLogger(__name__)


# ── RSA helpers (server-side) ─────────────────────────────────────────

def generate_rsa_keypair():
    """Return a new 2048-bit RSA private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def export_public_key(private_key) -> bytes:
    """Serialise the public key to PEM bytes for sending over the wire."""
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def decrypt_session_key(private_key, ciphertext: bytes) -> bytes:
    """Decrypt the client-supplied Fernet key using our RSA private key."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ── RSA helpers (client-side) ─────────────────────────────────────────

def load_public_key(pem_bytes: bytes):
    """Deserialise a PEM public key received from the server."""
    return serialization.load_pem_public_key(pem_bytes)


def generate_and_encrypt_session_key(server_public_key) -> tuple[bytes, bytes]:
    """
    Generate a fresh Fernet key, encrypt it with the server's RSA public key.
    Returns (raw_fernet_key, rsa_ciphertext).
    """
    fernet_key = Fernet.generate_key()
    ciphertext = server_public_key.encrypt(
        fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return fernet_key, ciphertext


# ── Framing ───────────────────────────────────────────────────────────
# Every message on the wire is length-prefixed: 4-byte big-endian uint32
# followed by the payload bytes.  This eliminates recv() boundary issues.

import struct

HEADER_SIZE = 4  # bytes


def frame(data: bytes) -> bytes:
    """Prepend a 4-byte length header to *data*."""
    return struct.pack(">I", len(data)) + data


def recv_frame(sock) -> bytes:
    """
    Read exactly one framed message from *sock*.
    Raises ConnectionError if the socket closes mid-read.
    """
    raw_len = _recv_exactly(sock, HEADER_SIZE)
    (length,) = struct.unpack(">I", raw_len)
    return _recv_exactly(sock, length)


def _recv_exactly(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed unexpectedly")
        buf += chunk
    return buf
