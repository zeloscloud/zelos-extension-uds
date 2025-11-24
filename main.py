#!/usr/bin/env python3
"""Zelos UDS extension - Unified Diagnostic Services over CAN."""

import logging
from pathlib import Path

import rich_click as click
from zelos_sdk.hooks.logging import TraceLoggingHandler

from zelos_extension_uds import cli as cli_commands

# Configure rich-click for better CLI UX
click.rich_click.USE_RICH_MARKUP = True
click.rich_click.USE_MARKDOWN = True
click.rich_click.SHOW_ARGUMENTS = True
click.rich_click.GROUP_ARGUMENTS_OPTIONS = True
click.rich_click.STYLE_ERRORS_SUGGESTION = "yellow italic"

# Configure logging - INFO level prevents debug logs from being sent to backend
logging.basicConfig(level=logging.INFO)

# Add the built-in handler to capture logs at INFO level and above
handler = TraceLoggingHandler("uds_log")
handler.setLevel(logging.INFO)
logging.getLogger().addHandler(handler)


@click.group(invoke_without_command=True)
@click.option(
    "--file",
    type=click.Path(path_type=Path),
    default=None,
    is_flag=False,
    flag_value=".",
    help="Record trace to .trz file (defaults to UTC.trz if no filename specified)",
)
@click.pass_context
def cli(ctx: click.Context, file: Path | None) -> None:
    """UDS diagnostic client over CAN.

    Provides UDS (ISO 14229) diagnostic services over CAN with ISO-TP transport.

    **App Mode (no subcommand):**

    Configure via Zelos extension settings and use interactive actions in Zelos App.

    **CLI Mode (with subcommands):**

    Execute individual UDS operations directly from the command line.

    Available subcommands:

    - **session** - Change diagnostic session
    - **read** - Read data by identifier (DID)
    - **write** - Write data by identifier (DID)
    - **reset** - Perform ECU reset
    - **routine** - Control diagnostic routines
    - **io** - Control input/output signals
    - **tp** - Send tester present
    - **dtc** - Read diagnostic trouble codes
    - **clear** - Clear diagnostic trouble codes
    - **security** - Request security access (seed/key)
    - **flash** - Flash firmware to ECU

    Examples:

        # Run in app mode with Zelos App configuration

        $ zelos-extension-uds

        # Read VIN (DID 0xF190)

        $ zelos-extension-uds read --txid 7E0 --rxid 7E8 --id F190

        # Perform soft reset without waiting for response

        $ zelos-extension-uds reset --txid 7E0

        # Perform hard reset with response required

        $ zelos-extension-uds reset --txid 7E0 --rxid 7E8 --response-required --type hard
    """
    # If a subcommand was invoked, don't run the app mode
    if ctx.invoked_subcommand is not None:
        return

    # Run app-based configuration mode
    cli_commands.run_app_mode(file)


# Register subcommands
cli.add_command(cli_commands.session)
cli.add_command(cli_commands.read)
cli.add_command(cli_commands.write)
cli.add_command(cli_commands.reset)
cli.add_command(cli_commands.routine)
cli.add_command(cli_commands.io)
cli.add_command(cli_commands.tp)
cli.add_command(cli_commands.dtc)
cli.add_command(cli_commands.clear)
cli.add_command(cli_commands.security)
cli.add_command(cli_commands.flash)


if __name__ == "__main__":
    cli()
