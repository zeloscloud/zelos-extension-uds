"""`dtc-setting`: ControlDTCSetting (0x85)."""

import rich_click as click

from .. import services
from .utils import command


@click.command("dtc-setting")
@click.option("--setting", type=click.Choice(["on", "off"]), required=True)
@command
def dtc_setting(ecu, setting: str) -> dict:
    """Turn DTC status updates on or off.

    \b
    Example:
        main.py dtc-setting --txid 7E0 --rxid 7E8 --setting off
    """
    return services.control_dtc_setting(ecu, setting.capitalize())
