import json
from pathlib import Path
from unittest.mock import patch
import pytest
from attacks import run_attacks
from bench import benchmark, plot_benchmark
from device.state import read_installed_version, write_installed_version
from device.verify import (FormatInvalid, HashMismatch, ModelMismatch, RollbackRejected, SignatureInvalid, verify_and_install)
from signer.keys import generate_keypair, load_private_key, load_public_key, save_private_key, save_public_key
from signer.manifest import canonical_bytes
from signer.sign import create_bundle, read_bundle, write_bundle


@pytest.fixture
def signed():
    sk, pk = generate_keypair()
    return create_bundle(b'firmware' * 300, sk, 'model', 3, '3.0', '2024-01-01'), sk, pk


def test_round_trip(tmp_path, signed):
    bundle, sk, pk = signed
    save_private_key(sk, tmp_path / 'private', b'password')
    save_public_key(pk, tmp_path / 'public')
    loaded = load_private_key(tmp_path / 'private', b'password')
    write_bundle(bundle, tmp_path / 'bundle')
    recovered = read_bundle(tmp_path / 'bundle')
    assert loaded.sign(b'test') == sk.sign(b'test')
    version, log = verify_and_install(recovered, load_public_key(tmp_path / 'public'), tmp_path / 'state', 'model')
    assert version == 3 and len(log) == 6


def test_attacks_are_isolated(tmp_path, signed):
    bundle, _, pk = signed
    state = tmp_path / 'state'
    write_installed_version(state, 42)
    results = run_attacks(bundle, pk, 'model', state)
    assert [r.expected_rejection for r in results] == [HashMismatch, SignatureInvalid, SignatureInvalid, RollbackRejected, FormatInvalid]
    assert all(r.passed and r.actual == r.expected_rejection.__name__ for r in results)
    assert read_installed_version(state) == 42


def test_wrong_password(tmp_path):
    sk, _ = generate_keypair()
    save_private_key(sk, tmp_path / 'key', b'good')
    with pytest.raises(ValueError):
        load_private_key(tmp_path / 'key', b'bad')


def test_canonical_order_and_signature():
    assert canonical_bytes({'b': 2, 'a': 1, 'signature': 'ignore'}) == canonical_bytes({'a': 1, 'b': 2})


def test_atomic_failure(tmp_path):
    state = tmp_path / 'state.json'
    write_installed_version(state, 3)
    with patch('device.state.os.replace', side_effect=OSError('failure')):
        with pytest.raises(OSError):
            write_installed_version(state, 4)
    assert read_installed_version(state) == 3
    assert list(tmp_path.iterdir()) == [state]


def test_benchmark():
    df = benchmark([128, 1024], repeats=1)
    assert list(df.columns) == ['size_kib', 'sign_ms_mean', 'verify_ms_mean']
    assert len(df) == 2
    assert plot_benchmark(df) is not None


def test_order_and_logs(tmp_path, signed):
    bundle, sk, pk = signed
    bundle.manifest['format_version'] = 2
    with pytest.raises(SignatureInvalid) as e:
        verify_and_install(bundle, pk, tmp_path / 'state', 'wrong')
    assert e.value.log
    bundle.signature = sk.sign(canonical_bytes(bundle.manifest))
    with pytest.raises(FormatInvalid):
        verify_and_install(bundle, pk, tmp_path / 'state', 'wrong')
    bundle.manifest['format_version'] = 1
    bundle.signature = sk.sign(canonical_bytes(bundle.manifest))
    with pytest.raises(ModelMismatch):
        verify_and_install(bundle, pk, tmp_path / 'state', 'wrong')


def test_removed_signature_from_disk(tmp_path, signed):
    bundle, _, pk = signed
    write_bundle(bundle, tmp_path)
    manifest = json.loads((tmp_path / 'manifest.json').read_text())
    del manifest['signature']
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(FormatInvalid) as e:
        verify_and_install(read_bundle(tmp_path), pk, tmp_path / 'state', 'model')
    assert e.value.log
