"""`reset`: ECUReset (0x11)."""

import rich_click as click

from .. import services
from .utils import command

RESETS = {"hard": "Hard Reset", "soft": "Soft Reset", "keyoffon": "Key Off On Reset"}


@click.command()
@click.option(
    "--type",
    "reset_type",
    type=click.Choice(list(RESETS), case_sensitive=False),
    default="soft",
    show_default=True,
    help="Reset type",
)
@click.option(
    "--suppress-response",
    is_flag=True,
    help="suppressPosRsp: only errors are answered, so success is not confirmed",
)
@command
def reset(ecu, reset_type: str, suppress_response: bool) -> dict:
    """Reset the ECU.

    \b
    Example:
        main.py reset --txid 7E0 --rxid 7E8 --type hard
    """
    return services.ecu_reset(ecu, RESETS[reset_type.lower()], suppress_response)
