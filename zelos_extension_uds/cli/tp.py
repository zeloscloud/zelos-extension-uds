"""`tp`: TesterPresent (0x3E)."""

import rich_click as click

from .. import services
from .utils import command


@click.command()
@click.option("--suppress-response", is_flag=True, help="suppressPosRsp: only errors are answered")
@command
def tp(ecu, suppress_response: bool) -> dict:
    """Send one tester present.

    \b
    Example:
        main.py tp --txid 7E0 --rxid 7E8 --suppress-response
    """
    return services.tester_present(ecu, suppress_response)
