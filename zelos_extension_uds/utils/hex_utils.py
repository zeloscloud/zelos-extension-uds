"""Hex string conversion and validation utilities for UDS operations."""

import logging
from typing import Any

logger = logging.getLogger(__name__)


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
            return {"error": f"Invalid hex characters in: {hex_str}"}

        # Ensure even length for byte conversion
        if len(cleaned) % 2 != 0:
            return {"error": f"Hex string must have even length, got: {len(cleaned)}"}

        return bytes.fromhex(cleaned)

    except ValueError as e:
        return {"error": f"Failed to parse hex string '{hex_str}': {e}"}


def format_hex_string(data: bytes, separator: str = " ", prefix: str = "") -> str:
    """Format bytes as a hex string with optional separator and prefix.

    :param data: Bytes to format
    :param separator: Separator between bytes (default: space)
    :param prefix: Prefix for each byte (e.g., "0x")
    :return: Formatted hex string
    """
    if not data:
        return ""

    hex_bytes = [f"{prefix}{byte:02X}" for byte in data]
    return separator.join(hex_bytes)


def validate_hex_id(hex_id_str: str, max_value: int = 0xFFFF) -> int | dict[str, Any]:
    """Validate and parse a hex ID string.

    :param hex_id_str: Hex ID string (e.g., "0x1234", "1234")
    :param max_value: Maximum allowed value (default: 0xFFFF for 16-bit IDs)
    :return: Integer ID if valid, error dict if invalid
    """
    if not hex_id_str:
        return {"error": "Empty ID provided"}

    try:
        # Remove 0x prefix if present
        cleaned = hex_id_str.strip().lower()
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]

        # Parse as hex
        id_value = int(cleaned, 16)

        # Validate range
        if id_value < 0:
            return {"error": f"ID cannot be negative: {hex_id_str}"}

        if id_value > max_value:
            return {"error": f"ID {hex_id_str} exceeds maximum 0x{max_value:X}"}

        return id_value

    except ValueError as e:
        return {"error": f"Invalid hex ID '{hex_id_str}': {e}"}


def format_hex_id(id_value: int, width: int = 4) -> str:
    """Format an integer ID as a hex string with 0x prefix.

    :param id_value: Integer ID value
    :param width: Width of hex string (default: 4 for 16-bit IDs)
    :return: Formatted hex ID (e.g., "0x1234")
    """
    return f"0x{id_value:0{width}X}"


def validate_data_length(
    data: bytes, expected_length: int | None = None, max_length: int | None = None
) -> dict[str, Any] | None:
    """Validate data length constraints.

    :param data: Data bytes to validate
    :param expected_length: Expected exact length (optional)
    :param max_length: Maximum allowed length (optional)
    :return: Error dict if validation fails, None if valid
    """
    data_len = len(data)

    if expected_length is not None and data_len != expected_length:
        return {"error": f"Expected {expected_length} bytes, got {data_len}"}

    if max_length is not None and data_len > max_length:
        return {"error": f"Data exceeds maximum length of {max_length} bytes (got {data_len})"}

    return None
