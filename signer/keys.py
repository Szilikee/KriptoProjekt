"""Encrypted Ed25519 private-key storage and public-key serialization."""
import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a new Ed25519 keypair."""
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key()


def _derive(password: bytes, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password)


def save_private_key(sk: Ed25519PrivateKey, path: str | Path, password: bytes) -> None:
    """Encrypt and save a raw private key using scrypt and AES-GCM."""
    salt, nonce = os.urandom(16), os.urandom(12)
    raw = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    ciphertext = AESGCM(_derive(password, salt)).encrypt(nonce, raw, None)
    enc = lambda value: base64.b64encode(value).decode('ascii')
    Path(path).write_text(json.dumps({'kdf': 'scrypt', 'cipher': 'AES-256-GCM', 'salt': enc(salt), 'nonce': enc(nonce), 'ciphertext': enc(ciphertext)}, indent=2), encoding='utf-8')


def load_private_key(path: str | Path, password: bytes) -> Ed25519PrivateKey:
    """Load a private key; reject an incorrect password or modified ciphertext."""
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if data['kdf'] != 'scrypt' or data['cipher'] != 'AES-256-GCM':
        raise ValueError('Unsupported key encryption')
    decode = lambda name: base64.b64decode(data[name], validate=True)
    try:
        raw = AESGCM(_derive(password, decode('salt'))).decrypt(decode('nonce'), decode('ciphertext'), None)
    except InvalidTag as exc:
        raise ValueError('Wrong password or corrupted private key') from exc
    return Ed25519PrivateKey.from_private_bytes(raw)


def save_public_key(pk: Ed25519PublicKey, path: str | Path) -> None:
    """Save the raw public key as hexadecimal."""
    raw = pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    Path(path).write_text(raw.hex(), encoding='ascii')


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    """Load a public key from hexadecimal."""
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(Path(path).read_text(encoding='ascii').strip()))
