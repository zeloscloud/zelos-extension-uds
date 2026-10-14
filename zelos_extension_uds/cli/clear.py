"""`clear`: ClearDiagnosticInformation (0x14)."""

import rich_click as click

from .. import services
from .utils import command


@click.command()
@click.option("--group", default="FFFFFF", show_default=True, help="DTC group, 3 bytes hex")
@command
def clear(ecu, group: str) -> dict:
    """Clear DTCs; FFFFFF clears every DTC.

    \b
    Example:
        main.py clear --txid 7E0 --rxid 7E8
    """
    return services.clear_dtc(ecu, group)
