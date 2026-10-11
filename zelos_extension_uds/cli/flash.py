"""`flash`: the production download sequence."""

from pathlib import Path

import rich_click as click

from .. import services
from ..keys import load_key_file
from .utils import command


@click.command()
@click.option(
    "--file",
    "firmware_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Firmware image, raw binary",
)
@click.option("--address", required=True, help="Base memory address in hex, e.g. 08000000")
@click.option(
    "--block-size", type=int, default=0, help="Data bytes per TransferData; 0: the ECU's maximum"
)
@click.option("--enable-tp", is_flag=True, help="Tester present every 32 blocks")
@click.option(
    "--session",
    type=click.Choice(["programming", "none"]),
    default="programming",
    show_default=True,
    help="programming: extended, then programming session first",
)
@click.option("--security-level", default="0x11", show_default=True, help="Seed sub-function")
@click.option("--security-key", default="", help="Security key in hex")
@click.option("--key-file", default="", help="Seed/key file: key(level, seed) -> bytes")
@click.option("--erase-routine", default="", help="Erase routine id, e.g. FF00; none by default")
@click.option("--check-routine", default="", help="Check routine id, e.g. FF01; none by default")
@click.option(
    "--reset", type=click.Choice(["none", "hard", "soft"]), default="none", show_default=True
)
@command
def flash(
    ecu,
    firmware_file: Path,
    address: str,
    block_size: int,
    enable_tp: bool,
    session: str,
    security_level: str,
    security_key: str,
    key_file: str,
    erase_routine: str,
    check_routine: str,
    reset: str,
) -> dict:
    """Download a firmware image: sessions, security (skipped without a key or key file),
    optional erase, download, optional check, optional reset.

    \b
    Example:
        main.py flash --txid 7E0 --rxid 7E8 --file fw.bin --address 08000000 --key-file key.py
    """
    if key_file:
        try:
            ecu.key_fn = load_key_file(key_file)
        except ValueError as e:
            return services.error(str(e))
    plan = services.flash_plan(address, security_level, security_key, erase_routine, check_routine)
    if "error" in plan:
        return plan
    sessions = ("Extended Diagnostic Session", "Programming Session") if session != "none" else ()
    resets = {"hard": "Hard Reset", "soft": "Soft Reset"}
    return services.flash_firmware(
        ecu, plan["address"], firmware_file.read_bytes(), block_size, sessions,
        plan["security_level"], plan["key"], plan["erase_routine"], True, plan["check_routine"],
        resets.get(reset), 32 if enable_tp else 0,
    )  # fmt: skip
