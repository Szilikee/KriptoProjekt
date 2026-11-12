"""Formatting helpers shared by the teaching UI and tests."""
from signer.manifest import canonical_bytes


def format_canonical_json(manifest: dict) -> str:
    """Return the exact signed JSON bytes decoded as UTF-8 for display."""
    return canonical_bytes(manifest).decode('utf-8')
