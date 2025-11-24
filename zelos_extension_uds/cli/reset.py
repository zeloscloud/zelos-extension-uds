"""ECU reset CLI command."""

import logging
import sys

import rich_click as click
from udsoncan.services import ECUReset

from ..utils import validate_hex_id
from .operations import ecu_reset

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
    help="Receive CAN ID in hex (e.g., 7E8, 0x7E8). Omit for no response.",
)
@click.option(
    "--response-required",
    is_flag=True,
    help="Require response from ECU (must also specify --rxid)",
)
@click.option(
    "--type",
    "reset_type",
    type=click.Choice(["hard", "soft", "keyoffon"], case_sensitive=False),
    default="soft",
    help="Reset type (default: soft)",
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
def reset(
    txid: str,
    rxid: str | None,
    response_required: bool,
    reset_type: str,
    interface: str,
    channel: str,
    bitrate: int | None,
) -> None:
    """Perform ECU reset.

    Examples:

      # Soft reset without response

      zelos-extension-uds reset --txid 7E0

      # Hard reset with response required

      zelos-extension-uds reset --txid 7E0 --rxid 7E8 --response-required --type hard

      # Key off/on reset

      zelos-extension-uds reset --txid 7E0 --rxid 7E8 --type keyoffon
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

    # Validate response-required flag
    if response_required and not rxid:
        logger.error("--response-required requires --rxid")
        sys.exit(1)

    # Map reset type string to value
    reset_type_map = {
        "hard": ECUReset.ResetType.hardReset,
        "soft": ECUReset.ResetType.softReset,
        "keyoffon": ECUReset.ResetType.keyOffOnReset,
    }

    reset_type_value = reset_type_map[reset_type.lower()]

    # Perform reset operation
    result = ecu_reset(
        tx_id=tx_id,
        rx_id=rx_id if response_required else None,
        reset_type=reset_type_value,
        interface=interface,
        channel=channel,
        bitrate=bitrate,
    )

    # Exit with error code if operation failed
    if result["status"] == "error":
        sys.exit(1)
