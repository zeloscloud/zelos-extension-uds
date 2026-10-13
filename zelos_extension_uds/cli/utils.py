"""Start, stop and the CLI's one-ECU session."""

from __future__ import annotations

import contextlib
import functools
import json
import logging
import signal
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any

import rich_click as click

from ..client import STOP_BOUND, DoipLink, SharedBus, State, UdsEcu
from ..constants import CLI_INTERFACES, INTERFACES, Interface

logger = logging.getLogger(__name__)

#: CLI: how long to wait for the bus to open before giving up.
CLI_OPEN_TIMEOUT = 10.0


def start_all(ecus: list[UdsEcu], buses: list[SharedBus], tester_present_s: float | None) -> None:
    """Demo ECUs first, then the buses; periodic TP from the start when configured."""
    for ecu in ecus:
        ecu.start_demo()
    for bus in buses:
        bus.start()
    if tester_present_s:
        for ecu in ecus:
            ecu.set_tester_present(float(tester_present_s))


def stop_all(ecus: list[UdsEcu], buses: list[SharedBus]) -> None:
    """One owner, one shared bound. Signal everything first (periodic TP, then each bus,
    which closes its ISO-TP stacks, notifier and bus in that order), then wait: a request
    in flight cannot hold up a bus. Demo ECUs last."""
    deadline = time.monotonic() + STOP_BOUND
    for ecu in ecus:
        ecu.stop_tester_present()
    for bus in buses:
        bus.stop()
    for bus in buses:
        if not bus.join(max(0.0, deadline - time.monotonic())):
            logger.error("[%s] bus did not close within %gs", bus.name, STOP_BOUND)
    for ecu in ecus:
        if not ecu.join_tester_present(max(0.0, deadline - time.monotonic())):
            logger.error("[%s] periodic tester present did not stop in time", ecu.name)
    for ecu in ecus:
        ecu.stop_demo()


def run_until_stopped(ecus: list[UdsEcu], buses: list[SharedBus]) -> None:
    """Block until SIGTERM or SIGINT, then stop everything from this thread."""
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    while not stop.wait(0.5):
        pass
    logger.info("Shutting down UDS extension...")
    stop_all(ecus, buses)


# ─── CLI ────────────────────────────────────────────────────────────────────


def _label(ctx: click.Context, param: click.Parameter, value: str) -> str:
    """A settings label or short name as its label; any other name passes to python-can."""
    if value in INTERFACES:
        return value
    return CLI_INTERFACES.get(value.lower(), value)


def ecu_options(func: Callable[..., Any]) -> Callable[..., Any]:
    """The ECU a subcommand talks to: interface, channel, bitrate, FD and CAN ids, or DoIP
    host and logical addresses."""
    options = [
        click.option(
            "--interface",
            default="socketcan",
            show_default=True,
            callback=_label,
            help="Interface: a label from the settings form, or socketcan (zelos-socketcan), "
            "zelos-ssh-socketcan, pcan, kvaser, vector, slcan, other, demo, doip; any other "
            "name is a python-can interface (ixxat, gs_usb, virtual, ...)",
        ),
        click.option("--channel", default="can0", show_default=True, help="CAN channel/device"),
        click.option("--remote-host", default=None, help="zelos-ssh-socketcan: SSH host"),
        click.option("--ssh-user", default=None, help="zelos-ssh-socketcan: SSH user"),
        click.option("--ssh-port", type=int, default=None, help="zelos-ssh-socketcan: SSH port"),
        click.option("--config-json", default=None, help="other: python-can bus config, JSON"),
        click.option("--bitrate", type=int, default=None, help="CAN bitrate in bit/s"),
        click.option("--fd", is_flag=True, help="CAN FD: ISO-TP frames up to 64 bytes"),
        click.option("--data-bitrate", type=int, default=None, help="CAN FD data bitrate"),
        click.option("--txid", help="Request CAN ID, hex (tester to ECU): 7E0. Not for doip"),
        click.option("--rxid", help="Response CAN ID, hex (ECU to tester): 7E8. Not for doip"),
        click.option("--extended", is_flag=True, help="29-bit CAN ids"),
        click.option("--host", default="", help="doip: the DoIP entity's IP or hostname"),
        click.option("--port", type=int, default=13400, show_default=True, help="doip: TCP port"),
        click.option(
            "--tester-address",
            default="0E80",
            show_default=True,
            help="doip: our logical address, hex",
        ),
        click.option("--ecu-address", default="", help="doip: the ECU's logical address, hex"),
        click.option(
            "--activation-type",
            default="00",
            show_default=True,
            help="doip: routing activation type, hex",
        ),
        click.option(
            "--discover",
            is_flag=True,
            help="doip: vehicle identification first (broadcast without --host); "
            "the ECU address defaults to the entity's",
        ),
    ]
    for option in reversed(options):
        func = option(func)
    return func


@contextlib.contextmanager
def cli_ecu(
    interface: str,
    channel: str,
    bitrate: int | None,
    fd: bool,
    data_bitrate: int | None,
    txid: str | None,
    rxid: str | None,
    extended: bool,
    remote_host: str | None = None,
    ssh_user: str | None = None,
    ssh_port: int | None = None,
    config_json: str | None = None,
    doip: dict[str, Any] | None = None,
) -> Iterator[UdsEcu]:
    """One ECU on its own bus or DoIP connection, open for the block, stopped after it."""
    from .app import ADVANCED_DEFAULTS, set_library_logging

    set_library_logging(False)
    if INTERFACES.get(interface) == Interface.DOIP:
        link: dict[str, Any] = {"doip": doip or {}}
    else:
        for name, value in (("txid", txid), ("rxid", rxid)):
            if not value:
                raise click.UsageError(f"Missing option '--{name}'.")
        link = {"channel": channel, "tx_id": txid, "rx_id": rxid}
        link.update(extended_ids=extended, fd_mode=fd)
        if bitrate:
            link["bitrate"] = bitrate
        if data_bitrate:
            link["data_bitrate"] = data_bitrate
        if interface not in INTERFACES:  # a python-can name, as 0.1.x passed it
            config_json = json.dumps({"interface": interface, "channel": channel})
            interface = "Other (python-can)"
        if config_json:
            link["config_json"] = config_json
        if INTERFACES[interface] == Interface.ZELOS_SSH_SOCKETCAN:
            if not remote_host:
                raise click.UsageError("--interface zelos-ssh-socketcan needs --remote-host")
            link.update(remote_host=remote_host, remote_channel=channel)
            link.update({k: v for k, v in (("ssh_user", ssh_user), ("ssh_port", ssh_port)) if v})
    try:
        ecu = UdsEcu("cli", INTERFACES[interface], link, dict(ADVANCED_DEFAULTS))
    except ValueError as e:
        raise click.ClickException(str(e)) from e
    if ecu.doip is not None:
        bus = DoipLink(ecu)
    else:
        bus = SharedBus(ecu.bus_link, ecu.endpoint)
        bus.add(ecu)
    start_all([ecu], [bus], None)
    try:
        deadline = time.monotonic() + CLI_OPEN_TIMEOUT
        while ecu.state not in (State.CONNECTED, State.ERROR) and time.monotonic() < deadline:
            time.sleep(0.01)
        if ecu.state != State.CONNECTED:
            raise click.ClickException(ecu.last_error or f"bus not open after {CLI_OPEN_TIMEOUT}s")
        yield ecu
    finally:
        stop_all([ecu], [bus])


def emit(result: dict[str, Any]) -> None:
    """Print the result as JSON; exit 1 on error."""
    click.echo(json.dumps(result, indent=2))
    if result.get("status") == "error":
        raise SystemExit(1)


def command(func: Callable[..., dict[str, Any]]) -> Callable[..., None]:
    """A subcommand body `func(ecu, **its own options)` run on the CLI ECU."""

    @functools.wraps(func)
    def run(**kwargs: Any) -> None:
        keys = ("interface", "channel", "bitrate", "fd", "data_bitrate", "txid", "rxid")
        extra = ("remote_host", "ssh_user", "ssh_port", "config_json")
        bus_args = {k: kwargs.pop(k) for k in (*keys, "extended", *extra)}
        doip = ("host", "port", "tester_address", "ecu_address", "activation_type", "discover")
        bus_args["doip"] = {k: kwargs.pop(k) for k in doip}
        with cli_ecu(**bus_args) as ecu:
            result = func(ecu, **kwargs)
        emit(result)

    return ecu_options(run)
