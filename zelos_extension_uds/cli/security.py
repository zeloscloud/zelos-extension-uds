"""Security access CLI command."""

import logging
import sys

import rich_click as click

from ..utils import parse_hex_string, validate_hex_id
from .operations import security_access_request_seed, security_access_send_key

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
    "--level",
    type=int,
    default=1,
    help="Security access level (default: 1)",
)
@click.option(
    "--seed",
    is_flag=True,
    help="Request seed (default action)",
)
@click.option(
    "--key",
    type=str,
    help="Send key in hex (e.g., 01020304)",
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
def security(
    txid: str,
    rxid: str,
    level: int,
    seed: bool,
    key: str | None,
    interface: str,
    channel: str,
    bitrate: int | None,
) -> None:
    """Request security access (seed/key exchange).

    Examples:

      # Request seed for level 1

      zelos-extension-uds security --txid 7E0 --rxid 7E8 --level 1 --seed

      # Send key for level 1 (level+1=2)

      zelos-extension-uds security --txid 7E0 --rxid 7E8 --level 1 --key 01020304
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

    if key:
        # Send key operation (use even sub-function: level + 1)
        key_bytes = parse_hex_string(key)
        if isinstance(key_bytes, dict):
            logger.error(f"Invalid key: {key_bytes['error']}")
            sys.exit(1)

        result = security_access_send_key(
            tx_id=tx_id,
            rx_id=rx_id,
            level=level + 1,  # Send key uses even sub-function
            key=key_bytes,
            interface=interface,
            channel=channel,
            bitrate=bitrate,
        )
    else:
        # Request seed operation (use odd sub-function: level)
        result = security_access_request_seed(
            tx_id=tx_id,
            rx_id=rx_id,
            level=level,  # Request seed uses odd sub-function
            interface=interface,
            channel=channel,
            bitrate=bitrate,
        )

    # Exit with error code if operation failed
    if result["status"] == "error":
        sys.exit(1)
