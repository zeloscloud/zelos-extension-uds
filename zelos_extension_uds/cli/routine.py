"""`routine`: RoutineControl (0x31)."""

import rich_click as click

from .. import services
from ..utils import ENDIANNESS_BIG, ENDIANNESS_CHOICES, PAYLOAD_TYPE_CHOICES, PAYLOAD_TYPE_HEX
from .utils import command

CONTROLS = {"start": "Start Routine", "stop": "Stop Routine", "results": "Request Results"}


@click.command()
@click.option("--id", "routine_id", required=True, help="Routine Identifier in hex, e.g. 0201")
@click.option(
    "--control",
    type=click.Choice(list(CONTROLS), case_sensitive=False),
    default="start",
    show_default=True,
    help="Control type",
)
@click.option("--data", default="", help="Optional routine data, read as --type")
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
def routine(ecu, routine_id: str, control: str, data: str, data_type: str, endianness: str) -> dict:
    """Start, stop or read the results of a routine.

    \b
    Example:
        main.py routine --txid 7E0 --rxid 7E8 --id 0201 --control start
    """
    return services.routine_control(
        ecu, routine_id, CONTROLS[control.lower()], data, data_type.lower(), endianness.lower()
    )
