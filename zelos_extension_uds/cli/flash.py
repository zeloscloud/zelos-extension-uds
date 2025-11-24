"""Flash firmware CLI command."""

import logging
from pathlib import Path

import rich_click as click

from ..utils import parse_hex_string
from . import operations

logger = logging.getLogger(__name__)


@click.command()
@click.option("--txid", required=True, type=str, help="Transmit CAN ID in hex (e.g., 7E0)")
@click.option("--rxid", required=True, type=str, help="Receive CAN ID in hex (e.g., 7E8)")
@click.option(
    "--file",
    "firmware_file",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Firmware file path (bin/hex/elf)",
)
@click.option(
    "--address", required=True, type=str, help="Base memory address in hex (e.g., 08000000)"
)
@click.option(
    "--block-size",
    type=int,
    default=None,
    help="Block size for transfer (auto-negotiated if not specified)",
)
@click.option("--enable-tp", is_flag=True, help="Send tester present every 32 blocks")
@click.option("--enable-security", is_flag=True, help="Perform security access before flashing")
@click.option("--security-level", type=int, default=1, help="Security access level (default: 1)")
@click.option("--security-key", type=str, default=None, help="Security key in hex")
@click.option(
    "--session",
    type=click.Choice(["default", "programming", "extended"]),
    default="programming",
    help="Diagnostic session type",
)
@click.option("--interface", type=str, default="socketcan", help="CAN interface type")
@click.option("--channel", type=str, default="can0", help="CAN channel/device")
@click.option("--bitrate", type=int, default=None, help="CAN bitrate (optional)")
def flash(
    txid: str,
    rxid: str,
    firmware_file: Path,
    address: str,
    block_size: int | None,
    enable_tp: bool,
    enable_security: bool,
    security_level: int,
    security_key: str | None,
    session: str,
    interface: str,
    channel: str,
    bitrate: int | None,
) -> None:
    """Flash firmware to ECU using UDS download services.

    This command orchestrates the complete flash sequence using a persistent
    UDS client connection to maintain session state:

    1. Change to programming session (optional)
    2. Perform security access (optional)
    3. Request download (0x34)
    4. Transfer data blocks (0x36)
    5. Request transfer exit (0x37)

    Examples:

        # Basic flash
        $ zelos-extension-uds flash --txid 7E0 --rxid 7E8 --file firmware.bin --address 08000000

        # Flash with security access
        $ zelos-extension-uds flash --txid 7E0 --rxid 7E8 --file firmware.bin --address 08000000 \\
          --enable-security --security-key AABBCCDD

        # Flash with tester present
        $ zelos-extension-uds flash --txid 7E0 --rxid 7E8 --file firmware.bin --address 08000000 \\
          --enable-tp --session programming
    """
    # Parse hex IDs and address
    tx_id = int(txid.replace("0x", ""), 16)
    rx_id = int(rxid.replace("0x", ""), 16)
    base_address = int(address.replace("0x", ""), 16)

    # Validate security options
    if enable_security and not security_key:
        click.echo("Error: --security-key required when --enable-security is set", err=True)
        raise click.Abort()

    # Parse security key if provided
    key_bytes = None
    if security_key:
        key_bytes = parse_hex_string(security_key)
        if isinstance(key_bytes, dict):
            click.echo(f"Error: Invalid key format: {key_bytes['error']}", err=True)
            raise click.Abort()

    # Read firmware file
    click.echo(f"Reading firmware from {firmware_file}")
    firmware_data = firmware_file.read_bytes()
    click.echo(f"Firmware size: {len(firmware_data)} bytes")

    # Map session string to integer
    session_map = {"default": 1, "programming": 2, "extended": 3}
    session_type = session_map[session]

    # Execute flash operation
    click.echo("Starting flash sequence...")
    result = operations.flash_firmware(
        tx_id=tx_id,
        rx_id=rx_id,
        firmware_data=firmware_data,
        base_address=base_address,
        block_size=block_size,
        enable_tp=enable_tp,
        enable_security=enable_security,
        security_level=security_level,
        security_key=key_bytes,
        session_type=session_type,
        interface=interface,
        channel=channel,
        bitrate=bitrate,
    )

    # Display result
    if result["status"] == "success":
        click.echo("\nFlash completed successfully!")
        click.echo(f"  Address: {result['address']}")
        click.echo(f"  Size: {result['size']} bytes")
        click.echo(f"  Blocks: {result['blocks']}")
        click.echo(f"  Block size: {result['block_size']} bytes")
    else:
        click.echo(f"\nFlash failed: {result['error']}", err=True)
        raise click.Abort()
