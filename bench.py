"""Benchmark signing and verification of randomly generated firmware."""
import os
import time
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def benchmark(sizes_bytes: list[int] | None = None, repeats: int = 5) -> pd.DataFrame:
    """Measure Ed25519 signing and verification time for each firmware size."""
    if sizes_bytes is None:
        sizes_bytes = [64 * 1024, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024]
    if repeats < 1:
        raise ValueError('repeats must be positive')
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    rows = []
    for size in sizes_bytes:
        firmware = os.urandom(size)
        sign_times, verify_times = [], []
        for _ in range(repeats):
            start = time.perf_counter()
            signature = sk.sign(firmware)
            sign_times.append((time.perf_counter() - start) * 1000)
            start = time.perf_counter()
            pk.verify(signature, firmware)
            verify_times.append((time.perf_counter() - start) * 1000)
        rows.append({'size_kib': size / 1024, 'sign_ms_mean': sum(sign_times) / repeats, 'verify_ms_mean': sum(verify_times) / repeats})
    return pd.DataFrame(rows, columns=['size_kib', 'sign_ms_mean', 'verify_ms_mean'])


def plot_benchmark(df: pd.DataFrame) -> Figure:
    """Plot grouped signing and verification times."""
    fig, ax = plt.subplots()
    x = range(len(df))
    ax.bar([i - .2 for i in x], df['sign_ms_mean'], width=.4, label='Sign')
    ax.bar([i + .2 for i in x], df['verify_ms_mean'], width=.4, label='Verify')
    ax.set_xticks(list(x), [f'{v:g}' for v in df['size_kib']])
    ax.set_xlabel('Firmware size (KiB)')
    ax.set_ylabel('Mean time (ms)')
    ax.legend()
    fig.tight_layout()
    return fig
