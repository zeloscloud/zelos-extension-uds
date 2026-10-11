"""`io`: InputOutputControlByIdentifier (0x2F)."""

import rich_click as click

from .. import services
from ..utils import ENDIANNESS_BIG, ENDIANNESS_CHOICES, PAYLOAD_TYPE_CHOICES, PAYLOAD_TYPE_HEX
from .utils import command

CONTROLS = {
    "return": "Return Control To ECU",
    "reset": "Reset To Default",
    "freeze": "Freeze Current State",
    "adjust": "Short Term Adjustment",
}


@click.command()
@click.option("--id", "did", required=True, help="Data Identifier in hex, e.g. 0300")
@click.option(
    "--control",
    type=click.Choice(list(CONTROLS), case_sensitive=False),
    default="return",
    show_default=True,
    help="Control parameter",
)
@click.option("--option", default="", help="Optional control option record, read as --type")
@click.option(
    "--type",
    "option_type",
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
def io(ecu, did: str, control: str, option: str, option_type: str, endianness: str) -> dict:
    """Control an input or output by DID.

    \b
    Example:
        main.py io --txid 7E0 --rxid 7E8 --id 0300 --control adjust --option 4000 --type uint16
    """
    return services.io_control(
        ecu, did, CONTROLS[control.lower()], option, option_type.lower(), endianness.lower()
    )
