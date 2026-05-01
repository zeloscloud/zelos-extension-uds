"""Unit tests for UDS transactions over virtual CAN bus.

Tests essential UDS transactions end-to-end with a demo UDS server.
"""

import logging

import pytest

from zelos_extension_uds.demo_server import DemoUDSServer
from zelos_extension_uds.extension import UDSClient

# Enable debug logging for troubleshooting
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


@pytest.fixture
def virtual_channel() -> str:
    """Provide a unique virtual CAN channel name for each test."""
    return f"test_vcan_{id(object())}"


@pytest.fixture
def uds_server(virtual_channel: str) -> DemoUDSServer:
    """Create and start a demo UDS server on virtual CAN bus."""
    server = DemoUDSServer(
        channel=virtual_channel,
        tx_id=0x7E8,  # Server TX (ECU response)
        rx_id=0x7E0,  # Server RX (tester request)
    )
    server.start()
    yield server
    server.stop()


@pytest.fixture
def uds_client(virtual_channel: str) -> UDSClient:
    """Create a UDS client configured for virtual CAN bus."""
    config = {
        "interface": "virtual",
        "channel": virtual_channel,
        "tx_id": "0x7E0",  # Client TX (tester request)
        "rx_id": "0x7E8",  # Client RX (ECU response)
    }
    client = UDSClient(config)
    client.start()
    yield client
    client.stop()


def test_read_data_by_identifier_on_demand(
    check, uds_server: DemoUDSServer, uds_client: UDSClient
) -> None:
    """Test ReadDataByIdentifier creates on-demand connection and cleans up."""
    result = uds_client.read_data_by_identifier(did="0xF190")  # VIN

    check.that(result, "is instance of", dict)
    check.that(result.get("status"), "==", "success")
    check.that(result.get("data"), "is instance of", str)
    check.that(result["data"], "==", "0x" + b"DEMOVIN123456789".hex().upper())


def test_write_data_by_identifier_on_demand(
    check, uds_server: DemoUDSServer, uds_client: UDSClient
) -> None:
    """Test WriteDataByIdentifier creates on-demand connection and cleans up."""
    test_data = b"\x12\x34\x56\x78"

    result = uds_client.write_data_by_identifier(did="0x0100", data=test_data.hex())

    check.that(result, "is instance of", dict)
    check.that(result.get("status"), "==", "success")

    # Verify data was written by reading it back
    read_result = uds_client.read_data_by_identifier(did="0x0100")

    check.that(read_result.get("status"), "==", "success")
    check.that(read_result["data"], "==", "0x12345678")


def test_diagnostic_session_control(
    check, uds_server: DemoUDSServer, uds_client: UDSClient
) -> None:
    """Test DiagnosticSessionControl transaction."""
    result = uds_client.diagnostic_session_control(session_type="Extended Diagnostic Session")

    check.that(result, "is instance of", dict)
    check.that(result.get("status"), "==", "success")


def test_tester_present(check, uds_server: DemoUDSServer, uds_client: UDSClient) -> None:
    """Test one-shot TesterPresent transaction."""
    result = uds_client.send_tester_present()

    check.that(result, "is instance of", dict)
    check.that(result.get("status"), "==", "success")


def test_ecu_reset(check, uds_server: DemoUDSServer, uds_client: UDSClient) -> None:
    """Test ECUReset transaction."""
    result = uds_client.ecu_reset(reset_type="Hard Reset")

    check.that(result, "is instance of", dict)
    check.that(result.get("status"), "==", "success")


def test_multiple_sequential_transactions(
    check, uds_server: DemoUDSServer, uds_client: UDSClient
) -> None:
    """Test multiple transactions in sequence, each with on-demand connection."""
    # First transaction: Read VIN
    result1 = uds_client.read_data_by_identifier(did="0xF190")
    check.that(result1.get("status"), "==", "success")
    check.that(result1["data"], "==", "0x" + b"DEMOVIN123456789".hex().upper())

    # Second transaction: Read part number
    result2 = uds_client.read_data_by_identifier(did="0xF191")
    check.that(result2.get("status"), "==", "success")
    check.that(result2["data"], "==", "0x" + b"DEMOPART12345".hex().upper())

    # Third transaction: Write data
    result3 = uds_client.write_data_by_identifier(did="0x0100", data="AABBCCDD")
    check.that(result3.get("status"), "==", "success")

    # Fourth transaction: Read back written data
    result4 = uds_client.read_data_by_identifier(did="0x0100")
    check.that(result4.get("status"), "==", "success")
    check.that(result4["data"], "==", "0xAABBCCDD")


def test_connection_cleanup_on_invalid_did(
    check, uds_server: DemoUDSServer, uds_client: UDSClient
) -> None:
    """Test that connection cleanup happens even on negative responses."""
    # Request unknown DID that server will reject
    result = uds_client.read_data_by_identifier(did="0xFFFF")

    # Should get an error response but not crash
    check.that(result, "is instance of", dict)
    check.that(result.get("error"), "is instance of", str)

    # Subsequent valid transaction should still work
    result2 = uds_client.read_data_by_identifier(did="0xF190")
    check.that(result2.get("status"), "==", "success")


def test_routine_control(check, uds_server: DemoUDSServer, uds_client: UDSClient) -> None:
    """Test RoutineControl transaction."""
    result = uds_client.routine_control(
        routine_id="0x0203",
        control_type="Start Routine",
    )

    check.that(result, "is instance of", dict)
    check.that(result.get("status"), "==", "success")
    check.that(result.get("routine_id"), "==", "0x0203")


def test_io_control(check, uds_server: DemoUDSServer, uds_client: UDSClient) -> None:
    """Test InputOutputControlByIdentifier transaction."""
    result = uds_client.input_output_control(
        did="0x0100",
        control_parameter="Return Control To ECU",
    )

    check.that(result, "is instance of", dict)
    check.that(result.get("status"), "==", "success")
    check.that(result.get("did"), "==", "0x0100")
