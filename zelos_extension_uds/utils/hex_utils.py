"""Hex string conversion and validation utilities for UDS operations."""

import struct
from typing import Any

PAYLOAD_TYPE_HEX = "hex"
PAYLOAD_TYPE_CHOICES: list[str] = [
    PAYLOAD_TYPE_HEX,
    "int8",
    "uint8",
    "int16",
    "uint16",
    "int32",
    "uint32",
    "int64",
    "uint64",
    "float",
    "double",
]

ENDIANNESS_BIG = "big"
ENDIANNESS_LITTLE = "little"
ENDIANNESS_CHOICES: list[str] = [ENDIANNESS_BIG, ENDIANNESS_LITTLE]

_PAYLOAD_FORMATS: dict[str, str] = {
    "int8": "b",
    "uint8": "B",
    "int16": "h",
    "uint16": "H",
    "int32": "i",
    "uint32": "I",
    "int64": "q",
    "uint64": "Q",
    "float": "f",
    "double": "d",
}


def parse_hex_string(hex_str: str) -> bytes | dict[str, Any]:
    """Parse a hex string into bytes, handling various formats.

    Accepts formats:
    - "01 02 03 04" (space-separated)
    - "0x01020304" (0x prefix)
    - "01020304" (raw hex)
    - "0x01 0x02" (mixed)

    :param hex_str: Hex string to parse
    :return: Bytes if successful, error dict if invalid
    """
    if not hex_str:
        return {"error": "Empty hex string provided"}

    try:
        # Remove common prefixes and whitespace
        cleaned = hex_str.replace("0x", "").replace(" ", "").strip()

        if not cleaned:
            return {"error": "Hex string contains only whitespace"}

        # Validate hex characters
        if not all(c in "0123456789abcdefABCDEF" for c in cleaned):
            return {"error": f"'{hex_str}' is not hex bytes"}

        # Ensure even length for byte conversion
        if len(cleaned) % 2 != 0:
            return {"error": f"'{hex_str}' has an odd number of hex digits"}

        return bytes.fromhex(cleaned)

    except ValueError:
        return {"error": f"'{hex_str}' is not hex bytes"}


def format_hex_string(data: bytes) -> str:
    """Format bytes as a single ``0x``-prefixed hex string.

    Examples: ``b"\\x22"`` → ``"0x22"``, ``b"\\x12\\x34"`` → ``"0x1234"``,
    ``b""`` → ``""``. The ``0x`` prefix makes it unambiguous the value
    is hex; no spaces keeps multi-byte payloads compact.

    Input parsing (``parse_hex_string``) is liberal and still accepts
    space-separated and per-byte-prefixed forms — only the output is
    canonicalized.
    """
    if not data:
        return ""
    return "0x" + data.hex().upper()


def validate_hex_id(hex_id: str | int) -> int | dict[str, Any]:
    """Validate and parse a hex ID string or integer.

    :param hex_id: Hex ID string (e.g., "0x1234", "1234") or integer
    :return: Integer ID if valid, error dict if invalid
    """
    # Handle integer input directly
    if isinstance(hex_id, int):
        if hex_id < 0:
            return {"error": f"ID cannot be negative: {hex_id}"}
        return hex_id

    # Handle string input
    if not hex_id:
        return {"error": "Empty ID provided"}

    try:
        # Remove 0x prefix if present
        cleaned = str(hex_id).strip().lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]

        # Parse as hex
        id_value = int(cleaned, 16)

        # Validate non-negative
        if id_value < 0:
            return {"error": f"ID cannot be negative: {hex_id}"}

        return id_value

    except ValueError:
        return {"error": f"'{hex_id}' is not a hex number, e.g. 0x1234"}


def format_hex_id(id_value: int, width: int = 4) -> str:
    """Format an integer ID as a hex string with 0x prefix.

    :param id_value: Integer ID value
    :param width: Width of hex string (default: 4 for 16-bit IDs)
    :return: Formatted hex ID (e.g., "0x1234")
    """
    return f"0x{id_value:0{width}X}"


def parse_typed_payload(
    value: str, payload_type: str, endianness: str = ENDIANNESS_BIG
) -> bytes | dict[str, Any]:
    """Parse a payload string into bytes based on the selected type.

    "hex" delegates to ``parse_hex_string`` (free-form hex like
    "01 02 03 04" or "0x1234"); endianness is ignored for hex (positional).
    Numeric types parse the input as a number and pack with the given
    endianness into the register width for the type:

    - int8/uint8: 1 byte (endianness no-op)
    - int16/uint16: 2 bytes
    - int32/uint32: 4 bytes
    - int64/uint64: 8 bytes
    - float: 4 bytes
    - double: 8 bytes

    Integer inputs accept any base via Python's ``int(s, 0)`` so "1234",
    "0x4D2", "0b10011010010", and "-1" all work. Float inputs accept
    standard decimal/scientific notation ("3.14", "1e-3").

    :param value: Input string from the action UI
    :param payload_type: One of ``PAYLOAD_TYPE_CHOICES`` (case-insensitive)
    :param endianness: One of ``ENDIANNESS_CHOICES`` (case-insensitive,
        defaults to Big-Endian)
    :return: Bytes if successful, error dict if invalid
    """
    payload_type = payload_type.lower()
    endianness = endianness.lower()
    if payload_type == PAYLOAD_TYPE_HEX:
        return parse_hex_string(value)

    fmt_char = _PAYLOAD_FORMATS.get(payload_type)
    if fmt_char is None:
        return {"error": f"Unknown payload type: {payload_type}"}

    cleaned = value.strip()
    if not cleaned:
        return {"error": f"Empty value for type {payload_type}"}

    try:
        num: int | float = (
            float(cleaned) if payload_type in ("float", "double") else int(cleaned, 0)
        )
    except ValueError:
        return {"error": f"Invalid {payload_type} value '{value}': not a number"}

    endian_prefix = "<" if endianness == ENDIANNESS_LITTLE else ">"
    try:
        return struct.pack(endian_prefix + fmt_char, num)
    except struct.error:
        return {"error": f"{payload_type} value out of range '{value}'"}


_READ_REPRESENTATIONS: dict[int, list[tuple[str, str]]] = {
    1: [("uint8", "B"), ("int8", "b")],
    2: [("uint16", "H"), ("int16", "h")],
    4: [("uint32", "I"), ("int32", "i"), ("float", "f")],
    8: [("uint64", "Q"), ("int64", "q"), ("double", "d")],
}


def format_typed_representations(data: bytes) -> dict[str, Any]:
    """Decode a response payload into all natural numeric representations.

    Emits keys like ``uint16_be`` / ``uint16_le`` / ``int16_be`` /
    ``int16_le`` for 2-byte payloads, plus ``float_be`` / ``float_le`` for
    4-byte and ``double_be`` / ``double_le`` for 8-byte. 1-byte payloads
    emit ``uint8`` / ``int8`` (no endianness). Returns an empty dict for
    payload sizes that don't map to a natural scalar (0, 3, 5+ excluding
    8 etc.) so callers can omit the field cleanly.

    :param data: Response bytes from the ECU
    :return: Mapping of representation label -> decoded value
    """
    size = len(data)
    specs = _READ_REPRESENTATIONS.get(size)
    if specs is None:
        return {}

    out: dict[str, Any] = {}
    for label, fmt_char in specs:
        if size == 1:
            out[label] = struct.unpack(fmt_char, data)[0]
        else:
            out[f"{label}_be"] = struct.unpack(">" + fmt_char, data)[0]
            out[f"{label}_le"] = struct.unpack("<" + fmt_char, data)[0]
    return out
