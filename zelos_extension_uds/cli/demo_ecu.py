"""`demo-ecu`: run the demo UDS ECU standalone."""

import logging
import signal
import threading

import rich_click as click

from ..demo import DemoEcu
from ..demo.ecu import REQUEST_ID, RESPONSE_ID

logger = logging.getLogger(__name__)


def _can_id(ctx: click.Context, param: click.Parameter, value: str) -> int:
    try:
        return int(value, 16)
    except ValueError as e:
        raise click.BadParameter(f"{value!r} is not a hex id, e.g. 7E0") from e


@click.command("demo-ecu")
@click.option(
    "--interface",
    default=None,
    help="python-can interface (socketcan, pcan, ...). Default: the zelos-can virtual bus",
)
@click.option("--channel", default="uds-demo", show_default=True, help="CAN channel")
@click.option("--bitrate", type=int, default=None, help="CAN bitrate, for --interface")
@click.option("--fd", is_flag=True, help="CAN FD: ISO-TP frames up to 64 bytes")
@click.option(
    "--rx-id",
    default=f"{REQUEST_ID:X}",
    show_default=True,
    callback=_can_id,
    help="Id the ECU receives requests on (tester to ECU)",
)
@click.option(
    "--tx-id",
    default=f"{RESPONSE_ID:X}",
    show_default=True,
    callback=_can_id,
    help="Id the ECU answers on (ECU to tester)",
)
@click.option("--extended", is_flag=True, help="29-bit ids")
@click.option(
    "--stmin", type=int, default=0, show_default=True, help="STmin (ms) in its flow control"
)
def demo_ecu(
    interface: str | None,
    channel: str,
    bitrate: int | None,
    fd: bool,
    rx_id: int,
    tx_id: int,
    extended: bool,
    stmin: int,
) -> None:
    """Run the demo ECU: a small DC/DC converter answering UDS.

    Point any UDS tester at it. Stop with Ctrl-C.

    \b
    Example:
        uv run main.py demo-ecu --interface socketcan --channel vcan0
    """
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    try:
        ecu = DemoEcu(channel, interface, bitrate, fd, rx_id, tx_id, extended, stmin).start()
    except Exception as e:  # python-can raises its own errors for a missing adapter
        raise click.ClickException(f"cannot open CAN {interface} {channel}: {e}") from e
    if interface is None:
        logger.warning("The zelos-can virtual bus is in-process: other programs cannot reach it")
    try:
        while not stop.wait(0.5):
            pass
    finally:
        ecu.stop()
