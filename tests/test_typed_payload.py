"""Unit tests for parse_typed_payload and format_typed_representations."""

import struct

import pytest

from zelos_extension_uds.utils import (
    ENDIANNESS_BIG,
    ENDIANNESS_LITTLE,
    PAYLOAD_TYPE_CHOICES,
    PAYLOAD_TYPE_HEX,
    format_typed_representations,
    parse_typed_payload,
)


def test_hex_bytes_passthrough():
    assert parse_typed_payload("01 02 03 04", PAYLOAD_TYPE_HEX) == b"\x01\x02\x03\x04"
    assert parse_typed_payload("0x1234", PAYLOAD_TYPE_HEX) == b"\x12\x34"


def test_hex_bytes_invalid_returns_error():
    result = parse_typed_payload("zz", PAYLOAD_TYPE_HEX)
    assert isinstance(result, dict) and "error" in result


@pytest.mark.parametrize(
    "payload_type,fmt,size",
    [
        ("int8", ">b", 1),
        ("uint8", ">B", 1),
        ("int16", ">h", 2),
        ("uint16", ">H", 2),
        ("int32", ">i", 4),
        ("uint32", ">I", 4),
        ("int64", ">q", 8),
        ("uint64", ">Q", 8),
    ],
)
def test_integer_decimal(payload_type: str, fmt: str, size: int):
    result = parse_typed_payload("100", payload_type)
    assert result == struct.pack(fmt, 100)
    assert len(result) == size


@pytest.mark.parametrize("payload_type", ["int16", "uint16", "int32", "uint32"])
def test_integer_hex_input(payload_type: str):
    # 0x1234 == 4660 — both forms should produce identical bytes
    decimal_result = parse_typed_payload("4660", payload_type)
    hex_result = parse_typed_payload("0x1234", payload_type)
    assert decimal_result == hex_result


def test_signed_negative():
    assert parse_typed_payload("-1", "int8") == b"\xff"
    assert parse_typed_payload("-1", "int16") == b"\xff\xff"
    assert parse_typed_payload("-1", "int32") == b"\xff\xff\xff\xff"


def test_uint_rejects_negative():
    result = parse_typed_payload("-1", "uint16")
    assert isinstance(result, dict) and "out of range" in result["error"]


def test_int16_overflow_rejected():
    result = parse_typed_payload("100000", "int16")  # > 32767
    assert isinstance(result, dict) and "out of range" in result["error"]


def test_float32_register_size_4():
    result = parse_typed_payload("3.14", "float")
    assert result == struct.pack(">f", 3.14)
    assert len(result) == 4


def test_double_register_size_8():
    result = parse_typed_payload("3.14", "double")
    assert result == struct.pack(">d", 3.14)
    assert len(result) == 8


def test_float_scientific_notation():
    assert parse_typed_payload("1e-3", "float") == struct.pack(">f", 1e-3)


def test_invalid_number_string():
    result = parse_typed_payload("not-a-number", "uint16")
    assert isinstance(result, dict) and "Invalid uint16" in result["error"]


def test_empty_value_for_typed():
    result = parse_typed_payload("   ", "uint16")
    assert isinstance(result, dict) and "Empty" in result["error"]


def test_unknown_type():
    result = parse_typed_payload("1", "BOGUS")
    assert isinstance(result, dict) and "Unknown payload type" in result["error"]


def test_payload_type_and_endianness_case_insensitive():
    # Programmatic callers passing UPPER/Mixed case must still work,
    # symmetric with click's case_sensitive=False CLI parsing.
    assert parse_typed_payload("0x1234", "UINT16", "BIG") == b"\x12\x34"
    assert parse_typed_payload("0x1234", "Uint16", "Little") == b"\x34\x12"
    assert parse_typed_payload("01 02", "HEX") == b"\x01\x02"


def test_hex_is_first_choice():
    # UI default depends on this — 'hex' must be the leading entry
    assert PAYLOAD_TYPE_CHOICES[0] == PAYLOAD_TYPE_HEX
    assert PAYLOAD_TYPE_HEX == "hex"


# ---- endianness ----


def test_endianness_constant_values():
    # Wire-level: dropdown emits exactly these strings
    assert ENDIANNESS_BIG == "big"
    assert ENDIANNESS_LITTLE == "little"


def test_uint16_big_vs_little_endian():
    # 0x1234: big = 12 34, little = 34 12
    assert parse_typed_payload("0x1234", "uint16", ENDIANNESS_BIG) == b"\x12\x34"
    assert parse_typed_payload("0x1234", "uint16", ENDIANNESS_LITTLE) == b"\x34\x12"


def test_float_endianness_swaps_bytes():
    be = parse_typed_payload("3.14", "float", ENDIANNESS_BIG)
    le = parse_typed_payload("3.14", "float", ENDIANNESS_LITTLE)
    assert be == struct.pack(">f", 3.14)
    assert le == struct.pack("<f", 3.14)
    assert be == bytes(reversed(le))


def test_endianness_no_op_for_uint8():
    # Single-byte types are endian-invariant
    assert (
        parse_typed_payload("0x42", "uint8", ENDIANNESS_BIG)
        == parse_typed_payload("0x42", "uint8", ENDIANNESS_LITTLE)
        == b"\x42"
    )


def test_endianness_ignored_for_hex_bytes():
    # Hex bytes are positional; endianness must not reorder
    for endian in (ENDIANNESS_BIG, ENDIANNESS_LITTLE):
        assert parse_typed_payload("01 02 03 04", PAYLOAD_TYPE_HEX, endian) == b"\x01\x02\x03\x04"


def test_endianness_default_is_big():
    # Backwards-compat: omitting endianness must match big
    assert parse_typed_payload("0x1234", "uint16") == parse_typed_payload(
        "0x1234", "uint16", ENDIANNESS_BIG
    )


# ---- read-side representations ----


def test_representations_empty_for_unsupported_size():
    assert format_typed_representations(b"") == {}
    assert format_typed_representations(b"\x01\x02\x03") == {}  # 3 bytes
    assert format_typed_representations(b"\x00" * 16) == {}


def test_representations_1_byte_no_endianness():
    reps = format_typed_representations(b"\xff")
    assert reps == {"uint8": 255, "int8": -1}


def test_representations_2_bytes():
    reps = format_typed_representations(b"\x12\x34")
    assert reps["uint16_be"] == 0x1234
    assert reps["uint16_le"] == 0x3412
    assert reps["int16_be"] == 0x1234
    assert reps["int16_le"] == 0x3412
    # signed wraparound
    reps_neg = format_typed_representations(b"\xff\xff")
    assert reps_neg["uint16_be"] == 0xFFFF
    assert reps_neg["int16_be"] == -1


def test_representations_4_bytes_includes_float():
    pi_bytes = struct.pack(">f", 3.14)
    reps = format_typed_representations(pi_bytes)
    assert "uint32_be" in reps and "uint32_le" in reps
    assert "int32_be" in reps and "int32_le" in reps
    assert reps["float_be"] == pytest.approx(3.14, rel=1e-6)
    assert reps["float_le"] == pytest.approx(struct.unpack("<f", pi_bytes)[0])


def test_representations_8_bytes_includes_double():
    pi_bytes = struct.pack(">d", 3.141592653589793)
    reps = format_typed_representations(pi_bytes)
    assert "uint64_be" in reps and "uint64_le" in reps
    assert "int64_be" in reps and "int64_le" in reps
    assert reps["double_be"] == pytest.approx(3.141592653589793)


def test_round_trip_through_typed_payload_and_representation():
    encoded = parse_typed_payload("-1", "int16", ENDIANNESS_BIG)
    assert isinstance(encoded, bytes)
    reps = format_typed_representations(encoded)
    assert reps["int16_be"] == -1
    assert reps["uint16_be"] == 0xFFFF
