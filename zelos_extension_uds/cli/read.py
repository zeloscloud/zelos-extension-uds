"""Read data by identifier CLI command."""

import logging
import sys

import rich_click as click

from ..utils import validate_hex_id
from .operations import read_data_by_identifier

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
    help="Data Identifier in hex (e.g., F190, 0xF190)",
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
def read(
    txid: str,
    rxid: str,
    did: str,
    interface: str,
    channel: str,
    bitrate: int | None,
) -> None:
    """Read data from ECU by Data Identifier (DID).

    Examples:

      # Read VIN (DID 0xF190)

      zelos-extension-uds read --txid 7E0 --rxid 7E8 --id F190

      # Read with custom interface

      zelos-extension-uds read --txid 7E0 --rxid 7E8 --id 1234 --interface pcan --channel PCAN_USBBUS1 --bitrate 500000
    """
    # Parse hex IDs
    tx_id = validate_hex_id(txid, max_value=0x7FF)
    if isinstance(tx_id, dict):
        logger.error(f"Invalid TX ID: {tx_id['error']}")
        sys.exit(1)

    rx_id = validate_hex_id(rxid, max_value=0x7FF)
    if isinstance(rx_id, dict):
        logger.error(f"Invalid RX ID: {rx_id['error']}")
        sys.exit(1)

    did_value = validate_hex_id(did, max_value=0xFFFF)
    if isinstance(did_value, dict):
        logger.error(f"Invalid DID: {did_value['error']}")
        sys.exit(1)

    # Perform read operation
    result = read_data_by_identifier(
        tx_id=tx_id,
        rx_id=rx_id,
        did=did_value,
        interface=interface,
        channel=channel,
        bitrate=bitrate,
    )

    # Exit with error code if operation failed
    if result["status"] == "error":
        sys.exit(1)
