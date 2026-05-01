"""Write data by identifier CLI command."""

import logging
import sys

import rich_click as click

from ..utils import (
    ENDIANNESS_BIG,
    ENDIANNESS_CHOICES,
    PAYLOAD_TYPE_CHOICES,
    PAYLOAD_TYPE_HEX,
    parse_typed_payload,
    validate_hex_id,
)
from .operations import write_data_by_identifier

logger = logging.getLogger(__name__)


@click.command()
@click.option(
    "--txid",
    required=True,
    type=str,
    help="Transmit CAN ID in hex (e.g., 7E0, 0x7E0)",
)
@click.option(
    "--rxid",
    required=True,
    type=str,
    help="Receive CAN ID in hex (e.g., 7E8, 0x7E8)",
)
@click.option(
    "--id",
    "did",
    required=True,
    type=str,
    help="Data Identifier in hex (e.g., 1234, 0x1234)",
)
@click.option(
    "--data",
    required=True,
    type=str,
    help="Data to write. Interpretation depends on --type.",
)
@click.option(
    "--type",
    "data_type",
    type=click.Choice(PAYLOAD_TYPE_CHOICES, case_sensitive=False),
    default=PAYLOAD_TYPE_HEX,
    show_default=True,
    help="How to interpret --data. 'hex' = raw hex bytes; numeric types pack to register width.",
)
@click.option(
    "--endian",
    "endianness",
    type=click.Choice(ENDIANNESS_CHOICES, case_sensitive=False),
    default=ENDIANNESS_BIG,
    show_default=True,
    help="Byte order for numeric --type values. Ignored for 'hex' and 1-byte types.",
)
@click.option(
    "--interface",
    default="socketcan",
    help="CAN interface type (default: socketcan)",
)
@click.option(
    "--channel",
    default="can0",
    help="CAN channel/device (default: can0)",
)
@click.option(
    "--bitrate",
    type=int,
    help="CAN bitrate in bps (e.g., 500000)",
)
def write(
    txid: str,
    rxid: str,
    did: str,
    data: str,
    data_type: str,
    endianness: str,
    interface: str,
    channel: str,
    bitrate: int | None,
) -> None:
    """Write data to ECU by Data Identifier (DID).

    Examples:

      # Write raw hex bytes to DID 0x1234

      zelos-extension-uds write --txid 7E0 --rxid 7E8 --id 1234 --data "01 02 03 04"

      # Write a uint16 (big-endian, 2 bytes)

      zelos-extension-uds write --txid 7E0 --rxid 7E8 --id 1234 --data 4660 --type uint16

      # Write a float (4 bytes, little-endian)

      zelos-extension-uds write --txid 7E0 --rxid 7E8 --id 1234 \\
          --data 3.14 --type float --endian little
    """
    # Parse hex IDs
    tx_id = validate_hex_id(txid)
    if isinstance(tx_id, dict):
        logger.error(f"Invalid TX ID: {tx_id['error']}")
        sys.exit(1)

    rx_id = validate_hex_id(rxid)
    if isinstance(rx_id, dict):
        logger.error(f"Invalid RX ID: {rx_id['error']}")
        sys.exit(1)

    did_value = validate_hex_id(did)
    if isinstance(did_value, dict):
        logger.error(f"Invalid DID: {did_value['error']}")
        sys.exit(1)

    data_bytes = parse_typed_payload(data, data_type.lower(), endianness.lower())
    if isinstance(data_bytes, dict):
        logger.error(f"Invalid data: {data_bytes['error']}")
        sys.exit(1)

    # Perform write operation
    result = write_data_by_identifier(
        tx_id=tx_id,
        rx_id=rx_id,
        did=did_value,
        data=data_bytes,
        interface=interface,
        channel=channel,
        bitrate=bitrate,
    )

    # Exit with error code if operation failed
    if result["status"] == "error":
        sys.exit(1)
