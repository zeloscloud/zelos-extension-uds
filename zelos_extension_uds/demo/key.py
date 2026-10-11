"""The demo ECU's seed/key: key = seed XOR the level's constant, big-endian.

Published on purpose, as the bench DC-DC's (zelos-examples `uds_keys.py`). A
production ECU's algorithm is the OEM's secret and never ships here.
"""

#: Per security level, as its requestSeed sub-function: extended, programming.
XOR = {0x01: 0x5A5AA5A5, 0x11: 0xC3A53C5A}


def key(level: int, seed: bytes) -> bytes:
    """The key for seed at level, its requestSeed (odd) or sendKey (even) sub-function."""
    xor = XOR[level if level & 1 else level - 1]
    return (int.from_bytes(seed, "big") ^ xor).to_bytes(len(seed), "big")
