#!/usr/bin/env python3
"""Zelos UDS extension - Unified Diagnostic Services over CAN."""

import logging
import time
from pathlib import Path

import rich_click as click

from zelos_extension_uds import ACTION_PREFIX as _ACTION_PREFIX
from zelos_extension_uds import cli as cli_commands

#: Re-exported so the at-rest inventory dump, which reads this entry module,
#: sees the same namespace the live registration uses. See the definition in
#: `zelos_extension_uds/__init__.py`.
ACTION_PREFIX = _ACTION_PREFIX

# Configure rich-click
click.rich_click.USE_RICH_MARKUP = True
click.rich_click.USE_MARKDOWN = True
click.rich_click.SHOW_ARGUMENTS = True
click.rich_click.GROUP_ARGUMENTS_OPTIONS = True
click.rich_click.STYLE_ERRORS_SUGGESTION = "yellow italic"

# UTC ISO 8601 with ms, matching the SDK's Rust tracing lines in the same log stream
logging.Formatter.converter = time.gmtime
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03dZ %(levelname)5s %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)


@click.group(invoke_without_command=True)
@click.option("--demo", is_flag=True, help="Add a demo ECU to the configured ones")
@click.option(
    "--file",
    type=click.Path(path_type=Path),
    default=None,
    is_flag=False,
    flag_value=".",
    help="Record trace to .trz file (defaults to UTC.trz if no filename specified)",
)
@click.pass_context
def cli(ctx: click.Context, demo: bool, file: Path | None) -> None:
    """UDS (ISO 14229) diagnostics over CAN with ISO-TP.

    Without a subcommand: app mode, configured via Zelos extension settings, or
    --demo for testing. With one: a single request (or flash) from the shell.

    \b
    Examples:
        main.py --demo
        main.py read --txid 7E0 --rxid 7E8 --id F190
        main.py read --interface demo --txid 7E0 --rxid 7E8 --id F190
    """
    # A subcommand runs on its own
    if ctx.invoked_subcommand is not None:
        return

    cli_commands.run_app_mode(demo, file)


for command in cli_commands.COMMANDS:
    cli.add_command(command)

if __name__ == "__main__":
    cli()
