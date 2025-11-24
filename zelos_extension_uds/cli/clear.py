"""Clear diagnostic information CLI command."""

import logging

import rich_click as click

from ..utils import parse_hex_string
from . import operations

logger = logging.getLogger(__name__)


@click.command()
@click.option("--txid", required=True, type=str, help="Transmit CAN ID in hex (e.g., 7E0)")
@click.option("--rxid", required=True, type=str, help="Receive CAN ID in hex (e.g., 7E8)")
@click.option(
    "--group",
    type=str,
    default="FFFFFF",
    help="DTC group mask in hex (3 bytes, FFFFFF = all DTCs)",
)
@click.option("--interface", type=str, default="socketcan", help="CAN interface type")
@click.option("--channel", type=str, default="can0", help="CAN channel/device")
@click.option("--bitrate", type=int, default=None, help="CAN bitrate (optional)")
def clear(
    txid: str,
    rxid: str,
    group: str,
    interface: str,
    channel: str,
    bitrate: int | None,
) -> None:
    """Clear diagnostic trouble codes (DTCs).

    Examples:

        # Clear all DTCs
        $ zelos-extension-uds clear --txid 7E0 --rxid 7E8

        # Clear specific DTC group
        $ zelos-extension-uds clear --txid 7E0 --rxid 7E8 --group 123456
    """
    # Parse hex IDs
    tx_id = int(txid.replace("0x", ""), 16)
    rx_id = int(rxid.replace("0x", ""), 16)

    # Parse group mask
    group_bytes = parse_hex_string(group)
    if isinstance(group_bytes, dict):
        click.echo(f"Error: Invalid group format: {group_bytes['error']}", err=True)
        raise click.Abort()

    if len(group_bytes) != 3:
        click.echo(f"Error: Group must be 3 bytes, got {len(group_bytes)}", err=True)
        raise click.Abort()

    group_int = int.from_bytes(group_bytes, byteorder="big")

    # Execute operation
    result = operations.clear_diagnostic_information(
        tx_id, rx_id, group_int, interface, channel, bitrate
    )

    # Display result
    if result["status"] == "success":
        click.echo(f"DTCs cleared for group: {result['group']}")
    else:
        click.echo(f"Error: {result['error']}", err=True)
        raise click.Abort()
