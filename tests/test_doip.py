"""DoIP, end to end against the DoIP entity simulator (tests/doip_entity.py), in-process.

The conformance suite runs over DoIP too (tests/conformance); these cover what is
DoIP's own: discovery, a refused routing activation, a message ISO-TP cannot carry.
"""

import contextlib

import pytest
from doip_entity import EID, PORT, DoipEntity
from helpers import wait_until
from udsoncan import Request
from udsoncan.services import ReadDataByIdentifier

from zelos_extension_uds import actions
from zelos_extension_uds.cli.app import ADVANCED_DEFAULTS, create_ecus, share_buses
from zelos_extension_uds.cli.utils import start_all, stop_all
from zelos_extension_uds.client import State


@pytest.fixture
def entity():
    """The simulator on loopback: TCP on a free port, vehicle identification on UDP 13400."""
    entity = DoipEntity(port=0, udp_port=PORT).start()
    yield entity
    entity.stop()


@contextlib.contextmanager
def dcdc(entity: DoipEntity, **doip):
    """One DoIP ECU `dcdc`, started and stopped as the app does."""
    config = {"host": "127.0.0.1", "port": entity.port, **doip}
    ecus = create_ecus({"ecus": [{"interface": "DoIP", "name": "dcdc", "doip": config}]},
                       dict(ADVANCED_DEFAULTS))  # fmt: skip
    links = share_buses(ecus)
    actions.UDS_ECUS["dcdc"] = ecus[0]
    start_all(ecus, links, None)
    try:
        yield ecus[0]
    finally:
        actions.UDS_ECUS.clear()
        stop_all(ecus, links)


def test_discovery_takes_the_entity_address(entity):
    with dcdc(entity, discover=True) as ecu:  # no ECU address configured
        assert wait_until(lambda: ecu.state == State.CONNECTED)
        status = actions.get_status("dcdc")
        assert status["ecu_address"] == "0x1001"
        vehicle = status["vehicle"]
        assert vehicle["ip"] == "127.0.0.1" and vehicle["logical_address"] == "0x1001"
        assert vehicle["eid"] == vehicle["gid"] == EID.hex(":")
        vin = actions.read_did("dcdc", "F190")  # the identified VIN is DID F190's
        assert bytes.fromhex(vin["data"][2:]).decode() == vehicle["vin"]


def test_refused_routing_activation_is_the_action_error(entity):
    with dcdc(entity, ecu_address="0x1001", tester_address="0x0E81") as ecu:
        assert wait_until(lambda: not ecu.shared._thread.is_alive())  # not retried
        assert ecu.state == State.ERROR
        result = actions.read_did("dcdc", "F190")
        assert result["status"] == "error"
        assert "routing activation refused: 0x00 unknown source address" in result["error"]
        assert actions.get_status("dcdc")["reopens"] == 0


def test_a_message_over_isotp_size_is_one_diagnostic_message(entity):
    """241 VINs read at once: a 4580-byte response, past ISO-TP's 4095, comes in one
    diagnostic message, as the request goes in one."""
    request = Request(ReadDataByIdentifier, data=b"\xf1\x90" * 241)
    with dcdc(entity, ecu_address="0x1001") as ecu:
        assert wait_until(lambda: ecu.state == State.CONNECTED)
        entity.diagnostics.clear()
        response, _ = ecu.request(0x22, 0xF190, lambda client: client.send_request(request))
        assert len(response.get_payload()) == 1 + 241 * (2 + 17) == 4580
        assert entity.diagnostics == [("in", 1 + 241 * 2), ("out", 4580)]
