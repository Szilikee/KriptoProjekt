"""Create and store signed firmware bundles."""
import base64
import json
from dataclasses import dataclass
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signer.manifest import build_manifest, canonical_bytes


@dataclass
class Bundle:
    """Firmware, its unsigned manifest, and its detached signature."""
    firmware: bytes
    manifest: dict
    signature: bytes


def create_bundle(firmware: bytes, sk: Ed25519PrivateKey, device_model: str, version: int, version_str: str, release_date: str) -> Bundle:
    """Sign a new firmware bundle."""
    manifest = build_manifest(firmware, device_model, version, version_str, release_date)
    return Bundle(firmware, manifest, sk.sign(canonical_bytes(manifest)))


def write_bundle(bundle: Bundle, directory: str | Path) -> None:
    """Write the firmware, signed manifest, and detached signature."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    sig = base64.b64encode(bundle.signature).decode('ascii')
    manifest = {**bundle.manifest, 'signature': sig}
    (directory / 'firmware.bin').write_bytes(bundle.firmware)
    (directory / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    (directory / 'signature.b64').write_text(sig, encoding='ascii')


def read_bundle(directory: str | Path) -> Bundle:
    """Read a bundle from its firmware and signed manifest files."""
    directory = Path(directory)
    manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
    signature = manifest.pop('signature', None)
    try:
        sig = base64.b64decode(signature, validate=True) if isinstance(signature, str) else b''
    except ValueError:
        sig = b''
    return Bundle((directory / 'firmware.bin').read_bytes(), manifest, sig)
