"""The vendored conformance suite against the demo ECU, in this process.

`uds_server` (the suite's plugin leaves it empty) starts the demo on the
suite's in-process --interface (virtual, zelos-virtual) and --channel. The
fixture is the DemoEcu: its `bms` and `force` hooks are there for DTC tests.
"""

import pytest

from zelos_extension_uds.demo import DemoEcu


@pytest.fixture(scope="session")
def uds_server(pytestconfig):
    interface = pytestconfig.getoption("interface")
    if interface not in ("virtual", "zelos-virtual"):
        yield None  # a server on a real bus: the suite's own default
        return
    demo = DemoEcu(pytestconfig.getoption("channel"), interface=interface).start()
    yield demo
    demo.stop()
