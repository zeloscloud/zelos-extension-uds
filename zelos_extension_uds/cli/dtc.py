"""Read DTC information CLI command."""

import logging
import sys

import rich_click as click

from ..utils import validate_hex_id
from .operations import read_dtc_information

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
    "--mask",
    type=str,
    default="FF",
    help="Status mask in hex (default: FF = all DTCs)",
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
def dtc(
    txid: str,
    rxid: str,
    mask: str,
    interface: str,
    channel: str,
    bitrate: int | None,
) -> None:
    """Read diagnostic trouble codes (DTCs).

    Examples:

      # Read all DTCs

      zelos-extension-uds dtc --txid 7E0 --rxid 7E8

      # Read only confirmed DTCs (status mask 0x08)

      zelos-extension-uds dtc --txid 7E0 --rxid 7E8 --mask 08

      # Read pending DTCs (status mask 0x04)

      zelos-extension-uds dtc --txid 7E0 --rxid 7E8 --mask 04
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

    # Parse status mask
    mask_value = validate_hex_id(mask)
    if isinstance(mask_value, dict):
        logger.error(f"Invalid status mask: {mask_value['error']}")
        sys.exit(1)

    # Perform DTC read operation
    result = read_dtc_information(
        tx_id=tx_id,
        rx_id=rx_id,
        status_mask=mask_value,
        interface=interface,
        channel=channel,
        bitrate=bitrate,
    )

    # Exit with error code if operation failed
    if result["status"] == "error":
        sys.exit(1)
