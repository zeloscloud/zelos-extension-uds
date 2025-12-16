"""Routine control CLI command."""

import logging
import sys

import rich_click as click
from udsoncan.services import RoutineControl

from ..utils import parse_hex_string, validate_hex_id
from .operations import routine_control

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
    "routine_id",
    required=True,
    type=str,
    help="Routine Identifier in hex (e.g., 0203, 0x0203)",
)
@click.option(
    "--control",
    type=click.Choice(["start", "stop", "results"], case_sensitive=False),
    default="start",
    help="Control type (default: start)",
)
@click.option(
    "--data",
    type=str,
    help="Optional routine data in hex (e.g., '01 02', '0102')",
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
def routine(
    txid: str,
    rxid: str,
    routine_id: str,
    control: str,
    data: str | None,
    interface: str,
    channel: str,
    bitrate: int | None,
) -> None:
    """Control diagnostic routines.

    Examples:

      # Start routine 0x0203

      zelos-extension-uds routine --txid 7E0 --rxid 7E8 --id 0203 --control start

      # Start routine with data

      zelos-extension-uds routine --txid 7E0 --rxid 7E8 --id 0203 --control start --data "01 02"

      # Request routine results

      zelos-extension-uds routine --txid 7E0 --rxid 7E8 --id 0203 --control results
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

    routine_id_value = validate_hex_id(routine_id)
    if isinstance(routine_id_value, dict):
        logger.error(f"Invalid routine ID: {routine_id_value['error']}")
        sys.exit(1)

    # Parse optional data
    data_bytes = None
    if data:
        data_bytes = parse_hex_string(data)
        if isinstance(data_bytes, dict):
            logger.error(f"Invalid data: {data_bytes['error']}")
            sys.exit(1)

    # Map control type string to value
    control_type_map = {
        "start": RoutineControl.ControlType.startRoutine,
        "stop": RoutineControl.ControlType.stopRoutine,
        "results": RoutineControl.ControlType.requestRoutineResults,
    }

    control_type_value = control_type_map[control.lower()]

    # Perform routine control operation
    result = routine_control(
        tx_id=tx_id,
        rx_id=rx_id,
        control_type=control_type_value,
        routine_id=routine_id_value,
        data=data_bytes,
        interface=interface,
        channel=channel,
        bitrate=bitrate,
    )

    # Exit with error code if operation failed
    if result["status"] == "error":
        sys.exit(1)
