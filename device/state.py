"""Persistent, atomically replaced device version state."""
import json
import os
import tempfile
from pathlib import Path


def read_installed_version(path: str | Path) -> int:
    """Return the installed version, or zero if no state exists."""
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
    except FileNotFoundError:
        return 0
    version = data['installed_version']
    if type(version) is not int or version < 0:
        raise ValueError('Invalid installed version')
    return version


def write_installed_version(path: str | Path, version: int) -> None:
    """Atomically replace the installed version in the target directory."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=target.parent, prefix=f'.{target.name}.', delete=False) as f:
            name = f.name
            json.dump({'installed_version': version}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, target)
    finally:
        if name is not None and os.path.exists(name):
            os.unlink(name)
