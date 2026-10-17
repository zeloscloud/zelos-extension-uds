"""The vendored conformance suite against the demo ECU, in this process, once per transport.

`uds_server` (the suite's plugin leaves it empty) starts the demo:

- `can`: on the suite's in-process --interface (virtual, zelos-virtual) and --channel.
  The fixture is the DemoEcu: its `bms` and `force` hooks are there for DTC tests.
- `doip`: behind the DoIP entity simulator. The suite's tester (`zelos_testing.uds.UdsEcu`)
  talks to it over the extension's DoIP connection: physical requests to the ECU's
  logical address, functional ones to the functional group's. Tests that read CAN frames
  (the `bus` fixture) skip: there are none.
"""

import contextlib

import pytest
from doip_entity import ECU, FUNCTIONAL, TESTER, DoipEntity
from udsoncan.client import Client
from udsoncan.configs import default_client_config
from zelos_can import doip
from zelos_testing import uds

from zelos_extension_uds.demo import DemoEcu


@pytest.fixture(scope="session", params=["can", "doip"])
def uds_server(request, pytestconfig):
    if request.param == "doip":
        entity = DoipEntity(port=0, udp_port=None).start()
        with pytest.MonkeyPatch.context() as patch:
            _tester_over_doip(patch, entity)
            yield entity
        entity.stop()
        return
    interface = pytestconfig.getoption("interface")
    if interface not in ("virtual", "zelos-virtual"):
        yield None  # a server on a real bus: the suite's own default
        return
    demo = DemoEcu(pytestconfig.getoption("channel"), interface=interface).start()
    yield demo
    demo.stop()


@pytest.fixture
def bus(bus, uds_server):
    """The plugin's bus; over DoIP the test skips."""
    if isinstance(uds_server, DoipEntity):
        pytest.skip("reads CAN frames: none over DoIP")
    return bus


class _Tester(doip.Connection):
    """After the entity closed the connection (an ECU reset reboots the node), the next
    request reconnects and activates routing again, as a tester does. A request that
    met the closing connection (reset by the entity: not taken) is sent again once."""

    def empty_rxqueue(self) -> None:
        try:
            super().empty_rxqueue()
        except doip.Lost:
            self.client.reconnect(close_delay=0)

    def specific_send(self, payload: bytes) -> None:
        try:
            super().specific_send(payload)
        except doip.Lost:
            self.client.reconnect(close_delay=0)
            super().specific_send(payload)


def _tester_over_doip(patch: pytest.MonkeyPatch, entity: DoipEntity) -> None:
    """The suite's UdsEcu on a DoIP client instead of a CAN bus; the rest of it as is."""

    def enter(self):
        self.doip = doip.Client(
            entity.host,
            ECU,
            tcp_port=entity.port,
            client_logical_address=TESTER,
            activation_type=0,  # also on reconnect
            connect_timeout=2.0,
        )
        self.client = self._client(uds.PHYSICAL)
        return self

    def exit_(self, *exc):
        with contextlib.suppress(Exception):
            self.client.close()
        self.doip.close()

    def client(self, txid):
        # The suite's tester settings, as its UdsEcu._client has them.
        config = dict(default_client_config)
        config.update(
            request_timeout=None,
            p2_timeout=self.timeout_s,
            p2_star_timeout=max(5.0, self.timeout_s),
            use_server_timing=False,
            security_algo=uds.key,
            data_identifiers=uds.DIDS,
            input_output=uds.IOS,
        )
        target = ECU if txid == uds.PHYSICAL else FUNCTIONAL
        tester = Client(_Tester(self.doip, TESTER, target, ack_timeout=2.0), config=config)
        tester.open()
        return tester

    patch.setattr(uds.UdsEcu, "__enter__", enter)
    patch.setattr(uds.UdsEcu, "__exit__", exit_)
    patch.setattr(uds.UdsEcu, "_client", client)
