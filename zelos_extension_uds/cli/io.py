"""Input/output control CLI command."""

import logging
import sys

import rich_click as click
from udsoncan.services import InputOutputControlByIdentifier

from ..utils import parse_hex_string, validate_hex_id
from .operations import input_output_control

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
    "--control",
    type=click.Choice(["return", "reset", "freeze", "adjust"], case_sensitive=False),
    default="return",
    help="Control parameter (default: return)",
)
@click.option(
    "--option",
    type=str,
    help="Optional control option data in hex (e.g., '01 02', '0102')",
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
def io(
    txid: str,
    rxid: str,
    did: str,
    control: str,
    option: str | None,
    interface: str,
    channel: str,
    bitrate: int | None,
) -> None:
    """Control input/output signals by Data Identifier (DID).

    Examples:

      # Return control to ECU

      zelos-extension-uds io --txid 7E0 --rxid 7E8 --id 1234 --control return

      # Freeze current state

      zelos-extension-uds io --txid 7E0 --rxid 7E8 --id 1234 --control freeze

      # Short term adjustment with control option

      zelos-extension-uds io --txid 7E0 --rxid 7E8 --id 1234 --control adjust --option "FF"
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

    # Parse optional control option data
    option_bytes = None
    if option:
        option_bytes = parse_hex_string(option)
        if isinstance(option_bytes, dict):
            logger.error(f"Invalid option data: {option_bytes['error']}")
            sys.exit(1)

    # Map control parameter string to value
    control_param_map = {
        "return": InputOutputControlByIdentifier.ControlParam.returnControlToECU,
        "reset": InputOutputControlByIdentifier.ControlParam.resetToDefault,
        "freeze": InputOutputControlByIdentifier.ControlParam.freezeCurrentState,
        "adjust": InputOutputControlByIdentifier.ControlParam.shortTermAdjustment,
    }

    control_param_value = control_param_map[control.lower()]

    # Perform I/O control operation
    result = input_output_control(
        tx_id=tx_id,
        rx_id=rx_id,
        did=did_value,
        control_param=control_param_value,
        control_option=option_bytes,
        interface=interface,
        channel=channel,
        bitrate=bitrate,
    )

    # Exit with error code if operation failed
    if result["status"] == "error":
        sys.exit(1)
