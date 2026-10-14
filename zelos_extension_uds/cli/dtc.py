"""`dtc`: ReadDTCInformation (0x19)."""

import rich_click as click

from .. import services
from .utils import command

REPORTS = {
    "mask": "By Status Mask",
    "count": "Number By Status Mask",
    "snapshot-ids": "Snapshot Identification",
    "snapshot": "Snapshot By DTC",
    "extended": "Extended Data By DTC",
    "supported": "Supported DTCs",
}


@click.command()
@click.option(
    "--report", type=click.Choice(list(REPORTS)), default="mask", show_default=True,
    help="Sub-function",
)  # fmt: skip
@click.option("--mask", default="FF", show_default=True, help="DTC status mask in hex")
@click.option("--dtc", "dtc_id", default="", help="DTC in hex, for snapshot and extended")
@click.option("--record", default="0xFF", show_default=True, help="Record number; 0xFF: all")
@command
def dtc(ecu, report: str, mask: str, dtc_id: str, record: str) -> dict:
    """Read DTCs.

    \b
    Example:
        main.py dtc --txid 7E0 --rxid 7E8 --mask 08
        main.py dtc --txid 7E0 --rxid 7E8 --report extended --dtc 1A0098
    """
    try:
        value = int(mask, 16)
    except ValueError:
        return services.error(f"Invalid mask: '{mask}' is not hex")
    if not 0 <= value <= 0xFF:
        return services.error(f"Mask must be one byte, got {mask}")
    return services.read_dtc(ecu, value, REPORTS[report], dtc_id, record)
