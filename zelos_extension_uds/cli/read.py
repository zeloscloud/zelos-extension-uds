"""`read`: ReadDataByIdentifier (0x22)."""

import rich_click as click

from .. import services
from .utils import command


@click.command()
@click.option("--id", "did", required=True, help="Data Identifier in hex, e.g. F190")
@command
def read(ecu, did: str) -> dict:
    """Read a DID: hex, and integer/float readings of 1, 2, 4 and 8-byte values.

    \b
    Example:
        main.py read --txid 7E0 --rxid 7E8 --id F190
        main.py read --interface pcan --channel PCAN_USBBUS1 --bitrate 500000 \\
            --txid 7E0 --rxid 7E8 --id F190
    """
    return services.read_did(ecu, did)
