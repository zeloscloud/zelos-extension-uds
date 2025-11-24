"""Tester present CLI command."""

import logging
import sys

import rich_click as click

from ..utils import validate_hex_id
from .operations import tester_present

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
    type=str,
    help="Receive CAN ID in hex (e.g., 7E8, 0x7E8). Omit to suppress response.",
)
@click.option(
    "--suppress-response",
    is_flag=True,
    help="Suppress positive response from ECU",
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
def tp(
    txid: str,
    rxid: str | None,
    suppress_response: bool,
    interface: str,
    channel: str,
    bitrate: int | None,
) -> None:
    """Send tester present message to keep diagnostic session alive.

    Examples:

      # Send tester present with response

      zelos-extension-uds tp --txid 7E0 --rxid 7E8

      # Send tester present without response

      zelos-extension-uds tp --txid 7E0 --suppress-response
    """
    # Parse TX ID
    tx_id = validate_hex_id(txid, max_value=0x7FF)
    if isinstance(tx_id, dict):
        logger.error(f"Invalid TX ID: {tx_id['error']}")
        sys.exit(1)

    # Parse RX ID if provided
    rx_id = None
    if rxid:
        rx_id = validate_hex_id(rxid, max_value=0x7FF)
        if isinstance(rx_id, dict):
            logger.error(f"Invalid RX ID: {rx_id['error']}")
            sys.exit(1)

    # Perform tester present operation
    result = tester_present(
        tx_id=tx_id,
        rx_id=rx_id,
        suppress_response=suppress_response,
        interface=interface,
        channel=channel,
        bitrate=bitrate,
    )

    # Exit with error code if operation failed
    if result["status"] == "error":
        sys.exit(1)
