"""`comm`: CommunicationControl (0x28)."""

import rich_click as click

from .. import services
from .utils import command

CONTROLS = {
    "enable": "Enable Rx And Tx",
    "rx-only": "Enable Rx Disable Tx",
    "tx-only": "Disable Rx Enable Tx",
    "disable": "Disable Rx And Tx",
}
TYPES = {"normal": "Normal", "nm": "Network Management", "both": "Normal And Network Management"}


@click.command()
@click.option("--control", type=click.Choice(list(CONTROLS)), default="enable", show_default=True)
@click.option("--type", "kind", type=click.Choice(list(TYPES)), default="normal", show_default=True)
@command
def comm(ecu, control: str, kind: str) -> dict:
    """Enable or disable the ECU's transmission and reception.

    \b
    Example:
        main.py comm --txid 7E0 --rxid 7E8 --control rx-only
    """
    return services.communication_control(ecu, CONTROLS[control], TYPES[kind])
