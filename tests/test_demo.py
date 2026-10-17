"""The demo ECU's DTC lifecycle and reads, as the firmware's (CCR 1968.2 (d)(2.2)-(2.4))."""

from zelos_extension_uds.demo.ecu import (
    AGING_CYCLES,
    BMS_LOST,
    CDTC,
    PDTC,
    TF,
    TFSLC,
    TFTOC,
    WIR,
    DemoEcu,
)

U0111 = b"\xc1\x11\x00"


def _cycle(ecu: DemoEcu, failed: bool) -> int:
    """One operation cycle ended by ECUReset, its test run once; U0111's status."""
    assert ecu.request(b"\x11\x01") == b"\x51\x01"
    ecu.force[BMS_LOST] = failed
    ecu.sample()
    return ecu.dtcs[BMS_LOST].status


def test_two_trip_confirmation_healing_and_aging():
    ecu = DemoEcu()
    ecu.force = [False] * len(ecu.force)
    assert _cycle(ecu, True) == TF | TFTOC | PDTC | TFSLC  # pending, no MIL
    assert ecu.request(b"\x19\x03") == b"\x59\x03" + b"".join(
        U0111 + bytes([r]) for r in (0, 1, 0xF0)
    )
    assert _cycle(ecu, True) == TF | TFTOC | PDTC | CDTC | TFSLC | WIR  # confirmed, MIL on
    assert ecu.request(b"\x19\x06" + U0111 + b"\x01")[6:] == b"\x01\x02"  # two failed cycles
    # The MIL stays while healing and goes after three passed cycles; confirmed stays.
    assert [_cycle(ecu, False) for _ in range(3)] == [
        PDTC | CDTC | TFSLC | WIR, CDTC | TFSLC | WIR, CDTC | TFSLC | WIR,
    ]  # fmt: skip
    assert _cycle(ecu, False) == CDTC | TFSLC
    for _ in range(AGING_CYCLES - 1):
        assert _cycle(ecu, False) == CDTC | TFSLC
    assert _cycle(ecu, False) == TFSLC  # aged out, its frames with it
    assert ecu.request(b"\x19\x03") == b"\x59\x03"


def test_snapshot_records_and_multi_did_read():
    ecu = DemoEcu()
    ecu.force = [False] * len(ecu.force)
    _cycle(ecu, True)
    first = ecu.request(b"\x19\x04" + U0111 + b"\x00")
    # Record 0x00: four PIDs as DIDs 0xF400 + PID (1F, 42, 46, 5B).
    assert first[:8] == b"\x59\x04" + U0111 + bytes([0x27, 0x00, 4])
    assert [first[i : i + 2] for i in (8, 12, 16, 19)] == [
        b"\xf4\x1f",
        b"\xf4\x42",
        b"\xf4\x46",
        b"\xf4\x5b",
    ]
    every = ecu.request(b"\x19\x04" + U0111 + b"\xff")
    # 0xFF: 00, then 01 (the node's 5 DIDs), then F0 (the same frame in its first cycle).
    assert every.startswith(first) and every[len(first) : len(first) + 2] == b"\x01\x05"
    assert every.endswith(b"\xf0\x04" + first[8:])
    assert ecu.request(b"\x19\x04" + U0111 + b"\x02") == b"\x7f\x19\x31"
