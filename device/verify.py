"""Verify signed firmware and enforce model and rollback policies."""
import hashlib
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from device.explanations import CHECK_EXPLANATIONS
from device.state import read_installed_version, write_installed_version
from signer.manifest import canonical_bytes
from signer.sign import Bundle


@dataclass
class CheckStep:
    """One verification check and its teaching explanation."""
    index: int
    name: str
    what_is_checked: str
    expected: str
    actual: str
    passed: bool
    why: str
    expected_full: str = ''
    actual_full: str = ''


class UpdateRejected(Exception):
    """Base rejection carrying the verification log and trace."""
    def __init__(self, message: str, log: list[str], trace: list[CheckStep] | None = None) -> None:
        super().__init__(message)
        self.log = log.copy()
        self.trace = list(trace or [])


class SignatureInvalid(UpdateRejected):
    """The signature did not verify."""


class FormatInvalid(UpdateRejected):
    """The update has an invalid format."""


class HashMismatch(UpdateRejected):
    """The firmware length or digest did not match."""


class RollbackRejected(UpdateRejected):
    """The version is not newer than the installed version."""


class ModelMismatch(UpdateRejected):
    """The update targets a different model."""


def _verify(bundle: Bundle, public_key: Ed25519PublicKey, state_path: str | Path, device_model: str, log: list[str]) -> tuple[int, list[str], list[CheckStep]]:
    trace: list[CheckStep] = []
    names = list(CHECK_EXPLANATIONS)

    def step(index: int, expected: str, actual: str, passed: bool, message: str, error: type[UpdateRejected] | None = None, expected_full: str = '', actual_full: str = '') -> None:
        name = names[index - 1]
        text = CHECK_EXPLANATIONS[name]
        trace.append(CheckStep(index, name, text['what'], expected, actual, passed, text['why'], expected_full, actual_full))
        log.append(message)
        if not passed and error is not None:
            raise error(message, log, trace)

    # A missing signature is a format error before cryptographic verification.
    if not bundle.signature:
        step(1, 'Érvényes aláírás', 'Hiányzó vagy hibás aláírás', False, 'Az aláírás hiányzik vagy hibás', FormatInvalid)
    try:
        public_key.verify(bundle.signature, canonical_bytes(bundle.manifest))
    except InvalidSignature:
        step(1, 'Érvényes aláírás', 'Érvénytelen aláírás', False, 'Az aláírás érvénytelen', SignatureInvalid)
    except (TypeError, ValueError):
        step(1, 'Érvényes aláírás', 'Hibás manifest vagy aláírás', False, 'Hibás manifest vagy aláírás', FormatInvalid)
    step(1, 'Érvényes aláírás', 'Érvényes aláírás', True, 'Az aláírás érvényes')
    m = bundle.manifest
    try:
        valid_date = isinstance(m.get('release_date'), str) and date.fromisoformat(m['release_date']).isoformat() == m['release_date']
    except ValueError:
        valid_date = False
    valid_format = not (type(m.get('format_version')) is not int or m['format_version'] != 1
        or not isinstance(m.get('device_model'), str) or type(m.get('version')) is not int or m['version'] < 0
        or not isinstance(m.get('version_str'), str) or not valid_date
        or type(m.get('firmware_size')) is not int or m['firmware_size'] < 0
        or not isinstance(m.get('firmware_sha256'), str) or len(m['firmware_sha256']) != 64
        or any(c not in '0123456789abcdef' for c in m['firmware_sha256']))
    step(2, '1-es formátum, érvényes mezők', f"Formátumverzió: {m.get('format_version', 'hiányzik')}; mezők: {'érvényesek' if valid_format else 'hibásak'}", valid_format, 'A manifest formátuma érvényes' if valid_format else 'A manifest formátuma érvénytelen', FormatInvalid)
    matches = device_model == m['device_model']
    step(3, device_model, m['device_model'], matches, 'Az eszközmodell egyezik' if matches else 'Az eszközmodell eltér', ModelMismatch)
    expected_hash = m['firmware_sha256']
    actual_hash = hashlib.sha256(bundle.firmware).hexdigest()
    hash_ok = len(bundle.firmware) == m['firmware_size'] and actual_hash == expected_hash
    step(4, f"{expected_hash[:16]}…; {m['firmware_size']} bájt", f'{actual_hash[:16]}…; {len(bundle.firmware)} bájt', hash_ok, 'A firmware mérete és hash-e egyezik' if hash_ok else 'A firmware mérete vagy hash-e eltér', HashMismatch, expected_hash, actual_hash)
    installed = read_installed_version(state_path)
    version = m['version']
    newer = version > installed
    step(5, f'> {installed}', str(version), newer, f'A(z) {version} verzió újabb, mint {installed}' if newer else f'A(z) {version} verzió nem újabb, mint {installed}', RollbackRejected)
    write_installed_version(state_path, version)
    log.append(f'Telepített verzió: {version}')
    return version, log, trace


def verify_with_trace(bundle: Bundle, public_key: Ed25519PublicKey, state_path: str | Path, device_model: str, *, _log: list[str] | None = None) -> tuple[int, list[CheckStep]]:
    """Verify and install an update, returning its version and structured trace.

    Rejected updates raise an UpdateRejected subclass carrying both trace and log.
    """
    version, _, trace = _verify(bundle, public_key, state_path, device_model, _log if _log is not None else [])
    return version, trace


def verify_and_install(bundle: Bundle, public_key: Ed25519PublicKey, state_path: str | Path, device_model: str) -> tuple[int, list[str]]:
    """Verify and install an update, preserving the original version and log API."""
    log: list[str] = []
    version, _ = verify_with_trace(bundle, public_key, state_path, device_model, _log=log)
    return version, log
