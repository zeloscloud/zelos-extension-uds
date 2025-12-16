"""Unit tests for UDS transactions over virtual CAN bus.

Tests essential UDS transactions end-to-end with a mock UDS server.
"""

import contextlib
import logging
import threading
import time

import can
import isotp
import pytest
from udsoncan.connections import PythonIsoTpConnection

from zelos_extension_uds.extension import UDSClient

# Enable debug logging for troubleshooting
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class MockUDSServer:
    """Mock UDS server that responds to requests on a virtual CAN bus.

    Implements a simple UDS server that handles common diagnostic services
    by manually parsing and responding to UDS protocol messages.
    """

    def __init__(self, channel: str, tx_id: int, rx_id: int):
        """Initialize mock UDS server.

        Args:
            channel: Virtual CAN channel name
            tx_id: Server's TX address (client's RX)
            rx_id: Server's RX address (client's TX)
        """
        self.channel = channel
        self.tx_id = tx_id
        self.rx_id = rx_id
        self.bus: can.Bus | None = None
        self.notifier: can.Notifier | None = None
        self.isotp_stack: isotp.NotifierBasedCanStack | None = None
        self.connection: PythonIsoTpConnection | None = None
        self.server_thread: threading.Thread | None = None
        self.running = False
        self.data_store: dict[int, bytes] = {
            0xF190: b"MOCKVIN123456789",  # VIN
            0xF191: b"MOCKPART12345",  # Part number
            0x0100: b"\x00\x00\x00\x00",  # Test data
        }

    def start(self) -> None:
        """Start the mock UDS server."""
        logger.info(
            f"Mock server starting on channel={self.channel}, "
            f"TX=0x{self.tx_id:03X}, RX=0x{self.rx_id:03X}"
        )

        self.bus = can.Bus(interface="virtual", channel=self.channel)
        logger.debug(f"Mock server created CAN bus: {self.bus}")

        tp_addr = isotp.Address(
            isotp.AddressingMode.Normal_11bits, txid=self.tx_id, rxid=self.rx_id
        )
        logger.debug(f"Mock server ISO-TP address: TX=0x{self.tx_id:03X}, RX=0x{self.rx_id:03X}")

        self.notifier = can.Notifier(self.bus, [])
        self.isotp_stack = isotp.NotifierBasedCanStack(
            bus=self.bus,
            notifier=self.notifier,
            address=tp_addr,
        )
        logger.debug("Mock server created ISO-TP stack")

        self.connection = PythonIsoTpConnection(self.isotp_stack)
        self.connection.open()  # IMPORTANT: Must open the connection!
        logger.debug("Mock server opened ISO-TP connection")

        self.running = True
        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()
        logger.info("Mock server thread started")

        time.sleep(0.2)  # Give server time to initialize

    def stop(self) -> None:
        """Stop the mock UDS server."""
        self.running = False

        if self.server_thread:
            self.server_thread.join(timeout=1.0)

        if self.connection:
            with contextlib.suppress(AttributeError):
                self.connection.close()

        if self.isotp_stack:
            with contextlib.suppress(AttributeError):
                self.isotp_stack.stop()

        if self.notifier:
            self.notifier.stop()

        if self.bus:
            self.bus.shutdown()

    def _run_server(self) -> None:
        """Server thread main loop - manually handle UDS requests."""
        logger.info("Mock server loop started, waiting for requests...")
        request_count = 0

        while self.running:
            try:
                request_data = self.connection.wait_frame(timeout=0.1)
                if request_data:
                    request_count += 1
                    logger.info(
                        f"Mock server received request #{request_count}: {request_data.hex()}"
                    )
                    response_data = self._process_request(request_data)
                    if response_data:
                        logger.info(f"Mock server sending response: {response_data.hex()}")
                        self.connection.send(response_data)
                    else:
                        logger.warning("Mock server generated no response")
            except TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Mock server error: {e}", exc_info=True)
                continue

        logger.info(f"Mock server loop exiting (processed {request_count} requests)")

    def _process_request(self, request: bytes) -> bytes | None:
        """Process UDS request and return response."""
        if len(request) == 0:
            logger.warning("Received empty request")
            return None

        service_id = request[0]
        logger.debug(f"Processing service 0x{service_id:02X}")

        # ReadDataByIdentifier (0x22)
        if service_id == 0x22:
            logger.debug("Handling ReadDataByIdentifier")
            return self._handle_read_did(request)

        # WriteDataByIdentifier (0x2E)
        elif service_id == 0x2E:
            logger.debug("Handling WriteDataByIdentifier")
            return self._handle_write_did(request)

        # DiagnosticSessionControl (0x10)
        elif service_id == 0x10:
            logger.debug("Handling DiagnosticSessionControl")
            return self._handle_session_control(request)

        # TesterPresent (0x3E)
        elif service_id == 0x3E:
            logger.debug("Handling TesterPresent")
            return self._handle_tester_present(request)

        # ECUReset (0x11)
        elif service_id == 0x11:
            logger.debug("Handling ECUReset")
            return self._handle_ecu_reset(request)

        # RoutineControl (0x31)
        elif service_id == 0x31:
            logger.debug("Handling RoutineControl")
            return self._handle_routine_control(request)

        # InputOutputControlByIdentifier (0x2F)
        elif service_id == 0x2F:
            logger.debug("Handling InputOutputControlByIdentifier")
            return self._handle_io_control(request)

        # Unsupported service - negative response
        logger.warning(f"Unsupported service: 0x{service_id:02X}")
        return bytes([0x7F, service_id, 0x11])  # serviceNotSupported

    def _handle_read_did(self, request: bytes) -> bytes:
        """Handle ReadDataByIdentifier request."""
        if len(request) < 3:
            logger.warning(f"ReadDID request too short: {len(request)} bytes")
            return bytes([0x7F, 0x22, 0x13])  # incorrectMessageLengthOrInvalidFormat

        did = (request[1] << 8) | request[2]
        logger.info(f"ReadDID request for DID=0x{did:04X}")

        if did in self.data_store:
            # Positive response: 0x62 (0x22 + 0x40) + DID + data
            response = bytes([0x62, request[1], request[2]]) + self.data_store[did]
            logger.info(f"ReadDID success, returning {len(self.data_store[did])} bytes")
            return response
        else:
            # Negative response: requestOutOfRange
            logger.warning(f"ReadDID: DID 0x{did:04X} not in data store")
            return bytes([0x7F, 0x22, 0x31])

    def _handle_write_did(self, request: bytes) -> bytes:
        """Handle WriteDataByIdentifier request."""
        if len(request) < 4:
            return bytes([0x7F, 0x2E, 0x13])  # incorrectMessageLengthOrInvalidFormat

        did = (request[1] << 8) | request[2]
        data = request[3:]

        self.data_store[did] = data

        # Positive response: 0x6E (0x2E + 0x40) + DID
        return bytes([0x6E, request[1], request[2]])

    def _handle_session_control(self, request: bytes) -> bytes:
        """Handle DiagnosticSessionControl request."""
        if len(request) < 2:
            return bytes([0x7F, 0x10, 0x13])  # incorrectMessageLengthOrInvalidFormat

        session_type = request[1]

        # Positive response: 0x50 (0x10 + 0x40) + session type + timing parameters
        return bytes([0x50, session_type, 0x00, 0x32, 0x01, 0xF4])

    def _handle_tester_present(self, request: bytes) -> bytes:
        """Handle TesterPresent request."""
        # Positive response: 0x7E (0x3E + 0x40) + suppress positive response bit
        suppress_response = len(request) > 1 and (request[1] & 0x80)
        if suppress_response:
            return b""  # No response when suppression bit set
        return bytes([0x7E, 0x00])

    def _handle_ecu_reset(self, request: bytes) -> bytes:
        """Handle ECUReset request."""
        if len(request) < 2:
            return bytes([0x7F, 0x11, 0x13])  # incorrectMessageLengthOrInvalidFormat

        reset_type = request[1]

        # Positive response: 0x51 (0x11 + 0x40) + reset type
        return bytes([0x51, reset_type])

    def _handle_routine_control(self, request: bytes) -> bytes:
        """Handle RoutineControl request."""
        if len(request) < 4:
            return bytes([0x7F, 0x31, 0x13])  # incorrectMessageLengthOrInvalidFormat

        control_type = request[1]
        routine_id = (request[2] << 8) | request[3]
        logger.info(f"RoutineControl: type=0x{control_type:02X}, routine_id=0x{routine_id:04X}")

        # Positive response: 0x71 (0x31 + 0x40) + control_type + routine_id
        return bytes([0x71, control_type, request[2], request[3]])

    def _handle_io_control(self, request: bytes) -> bytes:
        """Handle InputOutputControlByIdentifier request."""
        if len(request) < 4:
            return bytes([0x7F, 0x2F, 0x13])  # incorrectMessageLengthOrInvalidFormat

        did = (request[1] << 8) | request[2]
        control_param = request[3]
        logger.info(f"IOControl: DID=0x{did:04X}, param=0x{control_param:02X}")

        # Positive response: 0x6F (0x2F + 0x40) + DID + control_param
        return bytes([0x6F, request[1], request[2], control_param])


@pytest.fixture
def virtual_channel() -> str:
    """Provide a unique virtual CAN channel name for each test."""
    return f"test_vcan_{id(object())}"


@pytest.fixture
def uds_server(virtual_channel: str) -> MockUDSServer:
    """Create and start a mock UDS server on virtual CAN bus."""
    server = MockUDSServer(
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
    check, uds_server: MockUDSServer, uds_client: UDSClient
) -> None:
    """Test ReadDataByIdentifier creates on-demand connection and cleans up."""
    result = uds_client.read_data_by_identifier(did="0xF190")  # VIN

    check.that(result, "is instance of", dict)
    check.that(result.get("status"), "==", "success")
    check.that(result.get("data"), "is instance of", str)
    check.that(
        result["data"], "==", "4D 4F 43 4B 56 49 4E 31 32 33 34 35 36 37 38 39"
    )  # HEX for MOCKVIN123456789


def test_write_data_by_identifier_on_demand(
    check, uds_server: MockUDSServer, uds_client: UDSClient
) -> None:
    """Test WriteDataByIdentifier creates on-demand connection and cleans up."""
    test_data = b"\x12\x34\x56\x78"

    result = uds_client.write_data_by_identifier(did="0x0100", data=test_data.hex())

    check.that(result, "is instance of", dict)
    check.that(result.get("status"), "==", "success")

    # Verify data was written by reading it back
    read_result = uds_client.read_data_by_identifier(did="0x0100")

    check.that(read_result.get("status"), "==", "success")
    check.that(read_result["data"], "==", "12 34 56 78")


def test_diagnostic_session_control(
    check, uds_server: MockUDSServer, uds_client: UDSClient
) -> None:
    """Test DiagnosticSessionControl transaction."""
    result = uds_client.diagnostic_session_control(session_type="Extended Diagnostic Session")

    check.that(result, "is instance of", dict)
    check.that(result.get("status"), "==", "success")


def test_tester_present(check, uds_server: MockUDSServer, uds_client: UDSClient) -> None:
    """Test one-shot TesterPresent transaction."""
    result = uds_client.send_tester_present()

    check.that(result, "is instance of", dict)
    check.that(result.get("status"), "==", "success")


def test_ecu_reset(check, uds_server: MockUDSServer, uds_client: UDSClient) -> None:
    """Test ECUReset transaction."""
    result = uds_client.ecu_reset(reset_type="Hard Reset")

    check.that(result, "is instance of", dict)
    check.that(result.get("status"), "==", "success")


def test_multiple_sequential_transactions(
    check, uds_server: MockUDSServer, uds_client: UDSClient
) -> None:
    """Test multiple transactions in sequence, each with on-demand connection."""
    # First transaction: Read VIN
    result1 = uds_client.read_data_by_identifier(did="0xF190")
    check.that(result1.get("status"), "==", "success")
    check.that(result1["data"], "==", "4D 4F 43 4B 56 49 4E 31 32 33 34 35 36 37 38 39")

    # Second transaction: Read part number
    result2 = uds_client.read_data_by_identifier(did="0xF191")
    check.that(result2.get("status"), "==", "success")
    check.that(result2["data"], "==", "4D 4F 43 4B 50 41 52 54 31 32 33 34 35")

    # Third transaction: Write data
    result3 = uds_client.write_data_by_identifier(did="0x0100", data="AABBCCDD")
    check.that(result3.get("status"), "==", "success")

    # Fourth transaction: Read back written data
    result4 = uds_client.read_data_by_identifier(did="0x0100")
    check.that(result4.get("status"), "==", "success")
    check.that(result4["data"], "==", "AA BB CC DD")


def test_connection_cleanup_on_invalid_did(
    check, uds_server: MockUDSServer, uds_client: UDSClient
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


def test_routine_control(check, uds_server: MockUDSServer, uds_client: UDSClient) -> None:
    """Test RoutineControl transaction."""
    result = uds_client.routine_control(
        routine_id="0x0203",
        control_type="Start Routine",
    )

    check.that(result, "is instance of", dict)
    check.that(result.get("status"), "==", "success")
    check.that(result.get("routine_id"), "==", "0x0203")


def test_io_control(check, uds_server: MockUDSServer, uds_client: UDSClient) -> None:
    """Test InputOutputControlByIdentifier transaction."""
    result = uds_client.input_output_control(
        did="0x0100",
        control_parameter="Return Control To ECU",
    )

    check.that(result, "is instance of", dict)
    check.that(result.get("status"), "==", "success")
    check.that(result.get("did"), "==", "0x0100")
