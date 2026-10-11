"""`security`: SecurityAccess (0x27)."""

import rich_click as click

from .. import services
from ..keys import load_key_file
from .utils import command


@click.command()
@click.option("--level", default="1", show_default=True, help="Seed sub-function (odd)")
@click.option("--seed", is_flag=True, help="Request the seed (the default without --key)")
@click.option("--key", default="", help="Send this key in hex (sub-function level + 1)")
@click.option("--key-file", default="", help="Seed/key file: request the seed and answer it")
@command
def security(ecu, level: str, seed: bool, key: str, key_file: str) -> dict:
    """Request a seed, send a key, or both with a key file.

    Each invocation opens its own session: a key sent here answers no seed the
    ECU still holds unless the ECU keeps it across connections.

    \b
    Example:
        main.py security --txid 7E0 --rxid 7E8 --level 1 --seed
        main.py security --txid 7E0 --rxid 7E8 --level 0x11 --key-file key.py
    """
    if key_file:
        try:
            ecu.key_fn = load_key_file(key_file)
        except ValueError as e:
            return services.error(str(e))
    return services.security_access(ecu, level, "" if seed else key)
