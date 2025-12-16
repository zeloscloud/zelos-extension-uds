"""Diagnostic session control CLI command."""

import logging
import sys

import rich_click as click
from udsoncan.services import DiagnosticSessionControl

from ..utils import validate_hex_id
from .operations import diagnostic_session_control

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
    "--type",
    "session_type",
    type=click.Choice(["default", "programming", "extended", "safety"], case_sensitive=False),
    default="extended",
    help="Session type (default: extended)",
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
def session(
    txid: str,
    rxid: str,
    session_type: str,
    interface: str,
    channel: str,
    bitrate: int | None,
) -> None:
    """Change diagnostic session.

    Examples:

      # Switch to extended diagnostic session

      zelos-extension-uds session --txid 7E0 --rxid 7E8 --type extended

      # Switch to programming session

      zelos-extension-uds session --txid 7E0 --rxid 7E8 --type programming
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

    # Map session type string to value
    session_type_map = {
        "default": DiagnosticSessionControl.Session.defaultSession,
        "programming": DiagnosticSessionControl.Session.programmingSession,
        "extended": DiagnosticSessionControl.Session.extendedDiagnosticSession,
        "safety": DiagnosticSessionControl.Session.safetySystemDiagnosticSession,
    }

    session_value = session_type_map[session_type.lower()]

    # Perform session control operation
    result = diagnostic_session_control(
        tx_id=tx_id,
        rx_id=rx_id,
        session_type=session_value,
        interface=interface,
        channel=channel,
        bitrate=bitrate,
    )

    # Exit with error code if operation failed
    if result["status"] == "error":
        sys.exit(1)
