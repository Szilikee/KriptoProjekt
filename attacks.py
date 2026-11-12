"""Run isolated demonstrations of common update attacks."""
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from device.verify import (CheckStep, UpdateRejected, SignatureInvalid, FormatInvalid, HashMismatch, RollbackRejected, verify_and_install)
from signer.manifest import canonical_bytes
from signer.sign import Bundle, create_bundle


@dataclass
class AttackResult:
    """Expected and observed outcome of one simulated attack."""
    name: str
    expected_rejection: type[UpdateRejected]
    actual: str
    passed: bool
    trace: list[CheckStep] = field(default_factory=list)


def run_attacks(bundle: Bundle, public_key: Ed25519PublicKey, device_model: str, state_path: str | Path) -> list[AttackResult]:
    """Run five attacks in isolated temporary state, leaving the real state untouched."""
    del state_path  # Deliberately never read or modify real device state.
    results: list[AttackResult] = []
    with TemporaryDirectory() as tmp:
        def run(name: str, expected: type[UpdateRejected], candidate: Bundle, key: Ed25519PublicKey, state: Path) -> None:
            try:
                verify_and_install(candidate, key, state, device_model)
            except UpdateRejected as exc:
                results.append(AttackResult(name, expected, type(exc).__name__, type(exc) is expected, exc.trace))
            else:
                results.append(AttackResult(name, expected, 'Accepted', False))
        changed = deepcopy(bundle)
        data = bytearray(changed.firmware)
        if data:
            data[1000 if len(data) > 1000 else len(data) // 2] ^= 1
        else:
            data.append(1)
        changed.firmware = bytes(data)
        run('Flip firmware bit', HashMismatch, changed, public_key, Path(tmp) / 'flip.json')
        changed = deepcopy(bundle)
        changed.manifest['version_str'] = str(changed.manifest.get('version_str', '')) + '-tampered'
        run('Modify version string', SignatureInvalid, changed, public_key, Path(tmp) / 'manifest.json')
        changed = deepcopy(bundle)
        changed.signature = Ed25519PrivateKey.generate().sign(canonical_bytes(changed.manifest))
        run('Sign with different key', SignatureInvalid, changed, public_key, Path(tmp) / 'key.json')
        # A second valid version cannot be created with only a public key. Use an
        # independent temporary signer and its matching device key for this case.
        sk = Ed25519PrivateKey.generate()
        state = Path(tmp) / 'rollback.json'
        high = create_bundle(bundle.firmware, sk, device_model, 2, '2', '2024-01-01')
        low = create_bundle(bundle.firmware, sk, device_model, 1, '1', '2024-01-01')
        verify_and_install(high, sk.public_key(), state, device_model)
        run('Rollback to older version', RollbackRejected, low, sk.public_key(), state)
        changed = deepcopy(bundle)
        changed.manifest.pop('signature', None)
        changed.signature = b''
        run('Remove signature', FormatInvalid, changed, public_key, Path(tmp) / 'missing.json')
    return results
