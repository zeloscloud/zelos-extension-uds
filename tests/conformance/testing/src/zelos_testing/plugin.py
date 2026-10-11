"""pytest plugin: which bus the nodes are on, and fixtures for it.

A SocketCAN channel by default. Any other python-can bus with --interface, e.g.
`--interface zelos-virtual --channel uds-demo` for a server in the test process,
which then overrides the `uds_server` fixture to start it.
"""

import json
import os
import subprocess
from pathlib import Path

import can
import pytest

from zelos_testing import bench, frames

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
    # A PLC managing the bench's CANopen node: how to pause it (see zelos_testing.bench).
    group = parser.getgroup("bench_quiet", "pausing a foreign CANopen manager for tests that drive the node")
    group.addoption("--quiet-agent", default=os.environ.get("ZELOS_BENCH_QUIET_AGENT"), help="Zelos agent URL running the Modbus extension that reaches the PLC ($ZELOS_BENCH_QUIET_AGENT)")
    group.addoption("--quiet-device", default=os.environ.get("ZELOS_BENCH_QUIET_DEVICE"), help="the Modbus extension's device for the PLC, e.g. codesys/plc ($ZELOS_BENCH_QUIET_DEVICE)")
    group.addoption("--quiet-register", default=os.environ.get("ZELOS_BENCH_QUIET_REGISTER", "setpoints/bench_quiet"), help="bench_quiet's name in the device map ($ZELOS_BENCH_QUIET_REGISTER)")
    group.addoption("--quiet-mask", type=lambda v: int(v, 0), default=os.environ.get("ZELOS_BENCH_QUIET_MASK", "0b10"), help="its bits that pause the CANopen manager ($ZELOS_BENCH_QUIET_MASK)")
    parser.addoption(
        "--soak-s",
        type=float,
        help="Host seconds the coexistence suite runs every protocol at once "
        "(default: 120 on vcan, 600 on a physical channel)",
    )
    parser.addoption(
        "--a2l",
        type=Path,
        help="A2L generated beside an XCP node's ELF, e.g. build/full.a2l "
        "(default: the one *.a2l in /elf, where a bench's tester mounts its ELFs)",
    )


def socketcan(config) -> bool:
    return config.getoption("interface") == "socketcan"


def pytest_configure(config):
    """Whether the nodes are simulated, and how long a wait may take, decided once."""
    config.addinivalue_line("markers", "node: needs the DC-DC node itself, not just a UDS server")
    frames.SIMULATED = socketcan(config) and _link(config.getoption("channel"))["info_kind"] == "vcan"
    scale = config.getoption("time_scale")
    frames.TIME_SCALE = scale if scale is not None else 5.0 if frames.SIMULATED else 1.0


def find_a2l(config) -> Path | None:
    """--a2l, or the one *.a2l in /elf, where a bench's tester mounts its ELFs."""
    path = config.getoption("a2l")
    if path is None:
        found = sorted(Path("/elf").glob("*.a2l"))
        path = found[0] if len(found) == 1 else None
    return path


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


def quiet_config(config) -> bench.QuietConfig | None:
    agent, device = config.getoption("quiet_agent"), config.getoption("quiet_device")
    if not agent or not device:
        return None
    return bench.QuietConfig(agent=agent, device=device, register=config.getoption("quiet_register"), mask=config.getoption("quiet_mask"))


@pytest.fixture(scope="session", autouse=True)
def foreign_canopen(pytestconfig) -> bench.ForeignCanopen:
    """A CANopen manager or SYNC producer other than this process, found once before any test sends."""
    if not socketcan(pytestconfig):
        return bench.ForeignCanopen(manager=False, sync=False, node_operational=False)
    with can.Bus(interface="socketcan", channel=pytestconfig.getoption("channel")) as b:
        return bench.foreign_canopen(b)


@pytest.fixture(scope="module")
def canopen_takeover(pytestconfig, foreign_canopen):
    """The CANopen node is this module's: a foreign manager is paused for it, or the module skips."""
    if not foreign_canopen.present:
        yield
        return
    cfg = quiet_config(pytestconfig)
    if cfg is None:
        pytest.skip("a foreign CANopen manager is on the bus and bench_quiet is not configured (--quiet-agent, --quiet-device)")
    import zelos_sdk

    with bench.BenchQuiet(cfg, zelos_sdk.Agent(cfg.agent).actions):
        yield


@pytest.fixture(scope="module")
def foreign_managed(pytestconfig, foreign_canopen) -> bool:
    """Whether a foreign manager runs the PDU; if so, waits until it does again after an earlier module's takeover."""
    if foreign_canopen.present:
        # A bus of its own: frames from before a takeover must not count.
        with can.Bus(interface="socketcan", channel=pytestconfig.getoption("channel")) as b:
            assert bench.wait_managed(b, bench.PDU_HEARTBEAT, frames.bound(15.0)), "the foreign manager did not bring the PDU operational"
    return foreign_canopen.present
