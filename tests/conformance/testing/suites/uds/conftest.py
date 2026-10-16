"""The tester both UDS suites drive the ECU with."""

import contextlib

import pytest

from zelos_testing.frames import bound
from zelos_testing.uds import DEFAULT, SECURITY_DELAY_S, UdsEcu


@pytest.fixture
def ecu(pytestconfig, uds_server):
    interface = pytestconfig.getoption("interface")
    # zelos-can's SocketCAN, as the Zelos agent opens it.
    interface = "zelos-socketcan" if interface == "socketcan" else interface
    with UdsEcu(interface, pytestconfig.getoption("channel"), timeout_s=bound(2.0), delay_s=bound(SECURITY_DELAY_S + 1)) as ecu:
        yield ecu
        # As found: default session, which also locks security, returns the
        # output, ends a transfer, and enables communication and DTC setting.
        with contextlib.suppress(Exception):
            ecu.client.change_session(DEFAULT)
