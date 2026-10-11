"""`write`: WriteDataByIdentifier (0x2E)."""

import rich_click as click

from .. import services
from ..utils import ENDIANNESS_BIG, ENDIANNESS_CHOICES, PAYLOAD_TYPE_CHOICES, PAYLOAD_TYPE_HEX
from .utils import command


@click.command()
@click.option("--id", "did", required=True, help="Data Identifier in hex, e.g. 0200")
@click.option("--data", required=True, help="Data to write, read as --type")
@click.option(
    "--type",
    "data_type",
    type=click.Choice(PAYLOAD_TYPE_CHOICES, case_sensitive=False),
    default=PAYLOAD_TYPE_HEX,
    show_default=True,
    help="'hex' = raw hex bytes; numeric types pack the number to the type's width",
)
@click.option(
    "--endian",
    "endianness",
    type=click.Choice(ENDIANNESS_CHOICES, case_sensitive=False),
    default=ENDIANNESS_BIG,
    show_default=True,
    help="Byte order for numeric --type. Ignored for 'hex' and 1-byte types",
)
@command
def write(ecu, did: str, data: str, data_type: str, endianness: str) -> dict:
    """Write a DID.

    \b
    Example:
        main.py write --txid 7E0 --rxid 7E8 --id 0200 --data 1300 --type uint16
    """
    return services.write_did(ecu, did, data, data_type.lower(), endianness.lower())
