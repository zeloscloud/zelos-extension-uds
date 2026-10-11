"""Seed/key plugins: a Python file per ECU defining `key(level: int, seed: bytes) -> bytes`.

Production algorithms are OEM-secret, so none ships here. The file runs in the
extension process, with the extension's own trust.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Callable
from pathlib import Path

KeyFn = Callable[[int, bytes], bytes]


def load_key_file(path: str) -> KeyFn:
    """The file's `key` function; ValueError naming the file when it cannot be used."""
    file = Path(path).expanduser()
    if not file.is_file():
        raise ValueError(f"key file {file} not found")
    spec = importlib.util.spec_from_file_location(f"uds_key_file_{file.stem}", file)
    if spec is None or spec.loader is None:
        raise ValueError(f"key file {file} is not a Python file")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        raise ValueError(f"key file {file}: {type(e).__name__}: {e}") from e
    key = getattr(module, "key", None)
    if not callable(key):
        raise ValueError(f"key file {file} defines no key(level, seed) function")
    return key


def compute_key(key_fn: KeyFn, level: int, seed: bytes) -> bytes:
    """`key_fn(level, seed)` as bytes; ValueError when it fails or returns something else."""
    try:
        key = key_fn(level, bytes(seed))
    except Exception as e:
        raise ValueError(f"key file failed for level 0x{level:02X}: {type(e).__name__}: {e}") from e
    if not isinstance(key, bytes | bytearray) or not key:
        raise ValueError(f"key file returned {type(key).__name__}, not bytes")
    return bytes(key)
