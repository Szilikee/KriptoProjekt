"""Tests for structured verification traces and teaching content."""
from copy import deepcopy
import hashlib
import pytest
from attacks import run_attacks
from device.explanations import CHECK_EXPLANATIONS, EXCEPTION_EXPLANATIONS
from device.state import write_installed_version
from device.verify import (CheckStep, FormatInvalid, HashMismatch, ModelMismatch, RollbackRejected, SignatureInvalid, verify_with_trace)
from signer.keys import generate_keypair
from signer.manifest import canonical_bytes
from signer.sign import create_bundle
from ui_helpers import format_canonical_json


@pytest.fixture
def inputs():
    sk, pk = generate_keypair()
    return create_bundle(b'firmware', sk, 'model', 3, 'v3', '2024-01-01'), sk, pk


def test_success_trace(tmp_path, inputs):
    bundle, _, pk = inputs
    version, trace = verify_with_trace(bundle, pk, tmp_path / 'state', 'model')
    assert version == 3
    assert len(trace) == 5
    assert [t.index for t in trace] == list(range(1, 6))
    assert all(isinstance(t, CheckStep) and t.passed and t.what_is_checked and t.why for t in trace)
    assert trace[4].expected == '> 0' and trace[4].actual == '3'
    digest = hashlib.sha256(bundle.firmware).hexdigest()
    assert digest[:16] in trace[3].actual and trace[3].actual_full == digest
    assert trace[3].expected_full == digest
    assert all(t.name in CHECK_EXPLANATIONS for t in trace)


@pytest.mark.parametrize('failure,index', [(SignatureInvalid, 1), (FormatInvalid, 2), (ModelMismatch, 3), (HashMismatch, 4), (RollbackRejected, 5)])
def test_failure_stops_at_check(tmp_path, inputs, failure, index):
    bundle, sk, pk = inputs
    bundle = deepcopy(bundle)
    model = 'model'
    state = tmp_path / 'state'
    if failure is SignatureInvalid:
        bundle.manifest['version_str'] = 'tampered'
    elif failure is FormatInvalid:
        bundle.manifest['format_version'] = 2
        bundle.signature = sk.sign(canonical_bytes(bundle.manifest))
    elif failure is ModelMismatch:
        model = 'other'
    elif failure is HashMismatch:
        bundle.firmware += b'x'
    else:
        write_installed_version(state, 3)
    before = state.read_bytes() if state.exists() else None
    with pytest.raises(failure) as caught:
        verify_with_trace(bundle, pk, state, model)
    trace = caught.value.trace
    assert len(trace) == index
    assert all(t.passed and t.what_is_checked and t.why for t in trace[:-1])
    assert not trace[-1].passed and trace[-1].what_is_checked and trace[-1].why
    assert caught.value.log and len(caught.value.log) == index
    assert (state.read_bytes() if state.exists() else None) == before


def test_missing_signature_trace(tmp_path, inputs):
    bundle, _, pk = inputs
    bundle.signature = b''
    with pytest.raises(FormatInvalid) as caught:
        verify_with_trace(bundle, pk, tmp_path / 'state', 'model')
    assert len(caught.value.trace) == 1 and not caught.value.trace[0].passed


def test_attack_traces(tmp_path, inputs):
    bundle, _, pk = inputs
    results = run_attacks(bundle, pk, 'model', tmp_path / 'state')
    assert [len(r.trace) for r in results] == [4, 1, 1, 5, 1]
    assert all(r.passed and not r.trace[-1].passed for r in results)


def test_exception_explanations():
    assert all(EXCEPTION_EXPLANATIONS.get(cls.__name__) for cls in [SignatureInvalid, FormatInvalid, HashMismatch, RollbackRejected, ModelMismatch])


def test_canonical_ui_formatter(inputs):
    bundle, _, _ = inputs
    bundle.manifest['signature'] = 'ignored'
    assert format_canonical_json(bundle.manifest).encode('utf-8') == canonical_bytes(bundle.manifest)
