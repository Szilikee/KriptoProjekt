"""Build and canonicalize signed firmware manifests."""
import hashlib
import json


def build_manifest(firmware: bytes, device_model: str, version: int, version_str: str, release_date: str) -> dict:
    """Build the manifest for the supplied firmware."""
    return {'format_version': 1, 'device_model': device_model, 'version': version, 'version_str': version_str, 'release_date': release_date, 'firmware_size': len(firmware), 'firmware_sha256': hashlib.sha256(firmware).hexdigest()}


def canonical_bytes(manifest: dict) -> bytes:
    """Serialize a manifest canonically, excluding any signature field."""
    return json.dumps({k: v for k, v in manifest.items() if k != 'signature'}, sort_keys=True, separators=(',', ':')).encode('utf-8')
