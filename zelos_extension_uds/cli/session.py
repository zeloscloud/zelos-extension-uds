"""`session`: DiagnosticSessionControl (0x10)."""

import rich_click as click

from .. import services
from .utils import command

SESSIONS = {
    "default": "Default Session",
    "programming": "Programming Session",
    "extended": "Extended Diagnostic Session",
    "safety": "Safety System Diagnostic Session",
}


@click.command()
@click.option(
    "--type",
    "session_type",
    type=click.Choice(list(SESSIONS), case_sensitive=False),
    default="extended",
    show_default=True,
    help="Session type",
)
@command
def session(ecu, session_type: str) -> dict:
    """Change the diagnostic session.

    \b
    Example:
        main.py session --txid 7E0 --rxid 7E8 --type extended
    """
    return services.session_control(ecu, SESSIONS[session_type.lower()])
