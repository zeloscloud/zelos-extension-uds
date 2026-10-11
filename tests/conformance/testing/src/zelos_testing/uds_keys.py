"""Seed to key for the bench's UDS servers: the DC-DC node and the UDS extension's demo ECU.

A production ECU's algorithm is the OEM's secret; this one is published on
purpose. The extension's demo key file mirrors it: `key(level, seed)`.
"""

# Per security level, as its requestSeed sub-function: extended, programming.
XOR = {0x01: 0x5A5AA5A5, 0x11: 0xC3A53C5A}


def key(level: int, seed: bytes) -> bytes:
    """The key for seed at level, its requestSeed (odd) or sendKey (even) sub-function."""
    xor = XOR[level if level & 1 else level - 1]
    return (int.from_bytes(seed, "big") ^ xor).to_bytes(len(seed), "big")
