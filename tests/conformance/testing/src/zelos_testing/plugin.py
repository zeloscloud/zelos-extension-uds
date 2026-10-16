"""pytest plugin: which bus the nodes are on, and fixtures for it.

A SocketCAN channel by default. Any other python-can bus with --interface, e.g.
`--interface zelos-virtual --channel uds-demo` for a server in the test process,
which then overrides the `uds_server` fixture to start it.

The hardware bench's own options and fixtures are zelos_testing.bench_plugin.
"""

import json
import os
import subprocess

import can
import pytest

from zelos_testing import frames

# Counters that stay flat on a healthy bus. Arbitration loss is normal traffic.
ERROR_COUNTERS = ("restarts", "bus_error", "error_warning", "error_passive", "bus_off")


def pytest_addoption(parser):
    parser.addoption(
        "--interface",
        default=os.environ.get("ZELOS_TEST_INTERFACE", "socketcan"),
        help="python-can interface of the bus: socketcan, or any other such as zelos-virtual "
        "(default: $ZELOS_TEST_INTERFACE, else socketcan)",
    )
    parser.addoption(
        "--channel",
        default=os.environ.get("ZELOS_TEST_CHANNEL", "vcan0"),
        help="Channel the nodes are on: vcan0 on a Renode bench, or a physical adapter "
        "such as can0 (default: $ZELOS_TEST_CHANNEL, else vcan0)",
    )
    parser.addoption(
        "--time-scale",
        type=float,
        help="Host seconds a wait may take per second of the node's time. Waits end "
        "on the node's frames; this only bounds them (default: 1 on a physical "
        "channel, 5 on vcan, for a host that runs the bench slower than real time)",
    )


def socketcan(config) -> bool:
    return config.getoption("interface") == "socketcan"


def pytest_configure(config):
    """Whether the nodes are simulated, and how long a wait may take, decided once."""
    frames.SIMULATED = socketcan(config) and _link(config.getoption("channel"))["info_kind"] == "vcan"
    scale = config.getoption("time_scale")
    frames.TIME_SCALE = scale if scale is not None else 5.0 if frames.SIMULATED else 1.0


@pytest.fixture(scope="session")
def uds_server():
    """A UDS server the suite starts itself. None here: it is already on the bus.

    Override in a conftest.py to start one in the test process, e.g. a demo
    ECU on --interface zelos-virtual.
    """
    return


@pytest.fixture
def bus(pytestconfig, uds_server):
    """The channel under test. Our own frames come back once transmitted."""
    with can.Bus(interface=pytestconfig.getoption("interface"), channel=pytestconfig.getoption("channel"), receive_own_messages=True) as b:
        yield b


def _link(channel: str) -> dict:
    out = subprocess.run(
        ["ip", "-json", "-details", "-statistics", "link", "show", channel],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return json.loads(out)[0]["linkinfo"]


@pytest.fixture
def bus_health(pytestconfig):
    """The controller stays error-active and counts no new errors across the test.

    A virtual channel has no controller, so there this checks nothing.
    """
    if frames.SIMULATED or not socketcan(pytestconfig):
        yield
        return

    channel = pytestconfig.getoption("channel")
    before = _link(channel)
    assert before["info_data"]["state"] == "ERROR-ACTIVE", f"{channel} before: {before['info_data']}"
    yield
    after = _link(channel)
    assert after["info_data"]["state"] == "ERROR-ACTIVE", f"{channel} after: {after['info_data']}"
    grew = {
        k: after["info_xstats"][k] - before["info_xstats"][k]
        for k in ERROR_COUNTERS
        if after["info_xstats"][k] != before["info_xstats"][k]
    }
    assert not grew, f"{channel} error counters grew: {grew}"
