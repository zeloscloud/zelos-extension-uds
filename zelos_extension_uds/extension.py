"""UDS (Unified Diagnostic Services) over CAN implementation for Zelos."""

import asyncio
import binascii
import logging
import math
import struct
import time
from dataclasses import dataclass
from typing import Any

import can
import isotp
import udsoncan
import zelos_sdk
from udsoncan import DidCodec
from udsoncan.client import Client
from udsoncan.connections import PythonIsoTpConnection
from udsoncan.exceptions import NegativeResponseException, TimeoutException
from udsoncan.services import (
    DiagnosticSessionControl,
    ECUReset,
    InputOutputControlByIdentifier,
    RoutineControl,
)
from zelos_sdk.actions import action

from .utils import format_hex_id, format_hex_string, parse_hex_string, validate_hex_id

logger = logging.getLogger(__name__)


class HexDidCodec(DidCodec):
    """Codec to perform simple binary Data Identifier read/writes.

    This codec handles raw bytes without requiring pre-defined DID structures.
    Adapted from zeloscloud.codecs.uds.codec.HexDidCodec for diagnostic use.

    For diagnostic tools, we preserve byte order (no endianness conversion).
    """

    def __init__(self):
        super().__init__()

    @staticmethod
    def to_bytes(data):
        """Convert data to bytes.

        Handles multiple data types:
        - bytes: pass through unchanged
        - str: hex string '0x1234' -> bytes b'\\x12\\x34' (preserves order)
        - list: recursively convert each element
        - float: pack as big-endian float
        - int: convert to big-endian bytes (network byte order)
        """
        logger.debug(f"Converting data={data} ({type(data)}) to bytes")
        data_bytes = b""

        if isinstance(data, bytes):
            data_bytes = data
        elif isinstance(data, str):
            # '0x1234' -> b'\x12\x34' (preserve byte order)
            try:
                data_bytes = bytes(binascii.unhexlify(data.removeprefix("0x")))
            except binascii.Error:
                logger.warning(f"Data={data} is not a hex string, encoding as ascii")
                data_bytes = data.encode("ascii")
        elif isinstance(data, list):
            for val in data:
                data_bytes += HexDidCodec.to_bytes(val)
        elif isinstance(data, float):
            data_bytes = struct.pack(">f", data)  # Big-endian float
        else:
            # Integer - convert to big-endian bytes (network byte order)
            min_bytes = int(math.ceil(data.bit_length() / 8))
            data_bytes = data.to_bytes(length=min_bytes, byteorder="big")

        return data_bytes

    def encode(self, data: Any) -> bytes:
        """Encode data to bytes for writing to ECU."""
        return self.to_bytes(data)

    def decode(self, did_payload: bytes) -> bytes:
        """Decode DID payload from ECU response.

        Returns bytes as-is (preserves order for diagnostic symmetry).
        """
        logger.debug(f"Decoding data = {did_payload} ({type(did_payload)})")
        # Return bytes unchanged
        return did_payload

    def __len__(self):
        """Tell udsoncan to read all remaining data after DID."""
        raise DidCodec.ReadAllRemainingData


@dataclass(slots=True)
class Metrics:
    """Performance metrics for UDS operations."""

    requests_sent: int = 0
    responses_received: int = 0
    timeouts: int = 0
    errors: int = 0


class UDSClient:
    """UDS diagnostic client over CAN with ISO-TP transport.

    Provides actions for common UDS diagnostic operations:
    - Read/Write Data By Identifier
    - ECU Reset
    - Routine Control
    - Input/Output Control
    - Tester Present
    """

    # UDS service ID constants
    SID_DIAGNOSTIC_SESSION_CONTROL = 0x10
    SID_ECU_RESET = 0x11
    SID_CLEAR_DIAGNOSTIC_INFORMATION = 0x14
    SID_READ_DTC_INFORMATION = 0x19
    SID_READ_DATA_BY_IDENTIFIER = 0x22
    SID_READ_MEMORY_BY_ADDRESS = 0x23
    SID_READ_SCALING_DATA_BY_IDENTIFIER = 0x24
    SID_SECURITY_ACCESS = 0x27
    SID_COMMUNICATION_CONTROL = 0x28
    SID_WRITE_DATA_BY_IDENTIFIER = 0x2E
    SID_INPUT_OUTPUT_CONTROL_BY_IDENTIFIER = 0x2F
    SID_ROUTINE_CONTROL = 0x31
    SID_REQUEST_DOWNLOAD = 0x34
    SID_REQUEST_UPLOAD = 0x35
    SID_TRANSFER_DATA = 0x36
    SID_REQUEST_TRANSFER_EXIT = 0x37
    SID_TESTER_PRESENT = 0x3E
    SID_CONTROL_DTC_SETTING = 0x85

    # UDS service IDs for trace logging
    SERVICE_NAMES = {
        SID_DIAGNOSTIC_SESSION_CONTROL: "DiagnosticSessionControl",
        SID_ECU_RESET: "ECUReset",
        SID_CLEAR_DIAGNOSTIC_INFORMATION: "ClearDiagnosticInformation",
        SID_READ_DTC_INFORMATION: "ReadDTCInformation",
        SID_READ_DATA_BY_IDENTIFIER: "ReadDataByIdentifier",
        SID_READ_MEMORY_BY_ADDRESS: "ReadMemoryByAddress",
        SID_READ_SCALING_DATA_BY_IDENTIFIER: "ReadScalingDataByIdentifier",
        SID_SECURITY_ACCESS: "SecurityAccess",
        SID_COMMUNICATION_CONTROL: "CommunicationControl",
        SID_WRITE_DATA_BY_IDENTIFIER: "WriteDataByIdentifier",
        SID_INPUT_OUTPUT_CONTROL_BY_IDENTIFIER: "InputOutputControlByIdentifier",
        SID_ROUTINE_CONTROL: "RoutineControl",
        SID_REQUEST_DOWNLOAD: "RequestDownload",
        SID_REQUEST_UPLOAD: "RequestUpload",
        SID_TRANSFER_DATA: "TransferData",
        SID_REQUEST_TRANSFER_EXIT: "RequestTransferExit",
        SID_TESTER_PRESENT: "TesterPresent",
        SID_CONTROL_DTC_SETTING: "ControlDTCSetting",
    }

    def __init__(
        self, config: dict[str, Any], namespace: zelos_sdk.TraceNamespace | None = None
    ) -> None:
        """Initialize UDS client.

        :param config: Configuration dictionary with CAN interface, addressing, timeouts
        :param namespace: Optional isolated TraceNamespace for the TraceSource
        """
        self.config = config
        self.namespace = namespace
        self.running = False
        self.client: Client | None = None
        self.bus: can.Bus | None = None
        self.notifier: can.Notifier | None = None
        self.isotp_stack: isotp.NotifierBasedCanStack | None = None
        self.connection: PythonIsoTpConnection | None = None

        # Metrics tracking
        self.metrics = Metrics()

        # Periodic tester present task (controlled by action, not config)
        self.tester_present_task: asyncio.Task | None = None
        self.tester_present_interval: float = 0  # Disabled by default
        self.current_tx_id: int | None = None  # Track current TX ID
        self.current_rx_id: int | None = None  # Track current RX ID

        # Create trace source (in isolated namespace if provided)
        if self.namespace:
            self.source = zelos_sdk.TraceSource("uds_client", namespace=self.namespace)
        else:
            self.source = zelos_sdk.TraceSource("uds_client")

        self._define_schema()

    def start(self) -> None:
        """Start UDS client and connect to CAN bus."""
        logger.info("Starting UDS client")

        try:
            # Create CAN bus interface
            interface = self.config.get("interface", "socketcan")
            channel = self.config.get("channel", "vcan0")
            bitrate = self.config.get("bitrate")

            logger.info(f"Connecting to CAN bus: interface={interface}, channel={channel}")

            bus_kwargs: dict[str, Any] = {"interface": interface, "channel": channel}
            if bitrate:
                bus_kwargs["bitrate"] = bitrate

            self.bus = can.Bus(**bus_kwargs)

            # TX/RX IDs are optional in config - will be specified per-action or use global defaults
            # Connection will be created on first action
            self.running = True
            logger.info("UDS client started (connection will be created on first action)")

        except Exception as e:
            logger.error(f"Failed to start UDS client: {e}")
            self.stop()
            raise

    def stop(self) -> None:
        """Stop UDS client and clean up resources."""
        logger.info("Stopping UDS client")
        self.running = False

        # Cancel periodic tester present
        if self.tester_present_task:
            self.tester_present_task.cancel()
            self.tester_present_task = None

        # Close UDS client
        if self.connection:
            try:
                self.connection.close()
            except Exception as e:
                logger.warning(f"Error closing ISO-TP connection: {e}")
            self.connection = None

        # Stop ISO-TP stack
        if self.isotp_stack:
            try:
                self.isotp_stack.stop()
            except Exception as e:
                logger.warning(f"Error stopping ISO-TP stack: {e}")
            self.isotp_stack = None

        # Stop notifier
        if self.notifier:
            try:
                self.notifier.stop()
            except Exception as e:
                logger.warning(f"Error stopping notifier: {e}")
            self.notifier = None

        # Close CAN bus
        if self.bus:
            try:
                self.bus.shutdown()
            except Exception as e:
                logger.warning(f"Error shutting down CAN bus: {e}")
            self.bus = None

        self.client = None
        logger.info("UDS client stopped")

    def run(self) -> None:
        """Main event loop with optional periodic tester present."""
        asyncio.run(self._run_async())

    async def _run_async(self) -> None:
        """Async event loop for UDS operations."""
        try:
            # Start periodic tester present if configured
            if self.tester_present_interval > 0:
                logger.info(f"Starting periodic tester present: {self.tester_present_interval}s")
                self.tester_present_task = asyncio.create_task(self._periodic_tester_present())

            # Main loop - just keep alive
            while self.running:
                await asyncio.sleep(1.0)

        except asyncio.CancelledError:
            logger.info("UDS client loop cancelled")
        finally:
            if self.tester_present_task:
                self.tester_present_task.cancel()

    async def _periodic_tester_present(self) -> None:
        """Send periodic tester present messages on the stored TX/RX IDs."""
        # Ensure connection is set to the stored IDs
        if self.current_tx_id is not None and self.current_rx_id is not None:
            self._setup_connection_with_ids(self.current_tx_id, self.current_rx_id)

        while self.running:
            try:
                await asyncio.sleep(self.tester_present_interval)

                if not self.running or not self.client:
                    break

                # Verify we're still using the correct IDs
                if self.current_tx_id is not None and self.current_rx_id is not None:
                    self._setup_connection_with_ids(self.current_tx_id, self.current_rx_id)

                # Send tester present (suppress positive response)
                response = self.client.tester_present(suppress_positive_response=True)

                if response:
                    logger.debug("Tester present sent")

            except asyncio.CancelledError:
                logger.info("Periodic tester present cancelled")
                break
            except Exception as e:
                logger.warning(f"Periodic tester present error: {e}")

    # ========== HELPERS ==========

    def _resolve_tx_rx_ids(
        self, tx_id: str | None = None, rx_id: str | None = None
    ) -> tuple[int, int] | dict[str, str]:
        """Resolve TX/RX IDs from action parameters or global config.

        :param tx_id: Optional action-specific TX ID (hex string)
        :param rx_id: Optional action-specific RX ID (hex string)
        :return: Tuple of (tx_id_int, rx_id_int) or error dict
        """
        # Try action-specific TX ID first
        if tx_id:
            tx_id_int = validate_hex_id(tx_id, max_value=0x7FF)
            if isinstance(tx_id_int, dict):
                return {"error": f"Invalid TX ID: {tx_id_int['error']}"}
        else:
            # Fall back to global config
            tx_id_int = self.config.get("tx_id")
            if tx_id_int is None:
                return {"error": "No TX ID specified (provide in action or global config)"}

        # Try action-specific RX ID first
        if rx_id:
            rx_id_int = validate_hex_id(rx_id, max_value=0x7FF)
            if isinstance(rx_id_int, dict):
                return {"error": f"Invalid RX ID: {rx_id_int['error']}"}
        else:
            # Fall back to global config
            rx_id_int = self.config.get("rx_id")
            if rx_id_int is None:
                return {"error": "No RX ID specified (provide in action or global config)"}

        return (tx_id_int, rx_id_int)

    def _setup_connection_with_ids(self, tx_id: int, rx_id: int) -> None:
        """Setup or reconfigure ISO-TP connection with specific TX/RX IDs.

        :param tx_id: Transmit CAN ID (tester→ECU)
        :param rx_id: Receive CAN ID (ECU→tester)
        """
        # Check if IDs match current connection
        if self.isotp_stack and hasattr(self.isotp_stack, "address"):
            current_addr = self.isotp_stack.address
            if (
                hasattr(current_addr, "txid")
                and current_addr.txid == tx_id
                and hasattr(current_addr, "rxid")
                and current_addr.rxid == rx_id
            ):
                # Already configured correctly
                return

            # IDs changed - update the address
            logger.debug(f"Updating connection IDs: TX=0x{tx_id:03X}, RX=0x{rx_id:03X}")
            new_addr = isotp.Address(isotp.AddressingMode.Normal_11bits, txid=tx_id, rxid=rx_id)
            self.isotp_stack.address = new_addr
            return

        # First time setup
        logger.debug(f"Setting up connection: TX=0x{tx_id:03X}, RX=0x{rx_id:03X}")

        # Create new ISO-TP addressing
        tp_addr = isotp.Address(isotp.AddressingMode.Normal_11bits, txid=tx_id, rxid=rx_id)

        # Configure ISO-TP parameters
        isotp_params = {}
        if "isotp_stmin" in self.config:
            isotp_params["stmin"] = self.config["isotp_stmin"]
        if "isotp_blocksize" in self.config:
            isotp_params["blocksize"] = self.config["isotp_blocksize"]
        if "isotp_tx_padding" in self.config or "isotp_rx_padding" in self.config:
            isotp_params["tx_data_length"] = 8
            if "isotp_tx_padding" in self.config:
                isotp_params["tx_padding"] = self.config["isotp_tx_padding"]
            if "isotp_padding_value" in self.config:
                isotp_params["tx_padding_byte"] = self.config["isotp_padding_value"]

        # Create notifier if it doesn't exist yet (first connection)
        if not self.notifier:
            self.notifier = can.Notifier(self.bus, [])

        # Create ISO-TP stack
        self.isotp_stack = isotp.NotifierBasedCanStack(
            bus=self.bus, notifier=self.notifier, address=tp_addr, params=isotp_params
        )

        # Create connection
        self.connection = PythonIsoTpConnection(self.isotp_stack)

        # Create or update client
        if not self.client:
            # First time - create client with configuration
            config = udsoncan.configs.default_client_config.copy()
            config["data_identifiers"] = {"default": HexDidCodec}
            config["input_output"] = {}

            if "request_timeout" in self.config:
                config["request_timeout"] = self.config["request_timeout"]
            if "p2_timeout" in self.config:
                config["p2_timeout"] = self.config["p2_timeout"]
            if "p2_star_timeout" in self.config:
                config["p2_star_timeout"] = self.config["p2_star_timeout"]
            if "use_external_sniffer" in self.config:
                config["use_external_sniffer"] = self.config["use_external_sniffer"]

            self.client = Client(self.connection, config=config)
            self.client.open()
        else:
            # Update existing client connection
            self.client.set_connection(self.connection)
            self.client.open()

    # ========== ACTIONS ==========

    @action("Get Status", "View UDS client status and metrics")
    def get_status(self) -> dict[str, Any]:
        """Get current UDS client status.

        :return: Status dictionary with connection state and metrics
        """
        return {
            "running": self.running,
            "connected": self.client is not None and self.bus is not None,
            "interface": self.config.get("interface", "unknown"),
            "channel": self.config.get("channel", "unknown"),
            "tx_id": format_hex_id(self.config.get("tx_id", 0), width=3),
            "rx_id": format_hex_id(self.config.get("rx_id", 0), width=3),
            "tester_present_active": self.tester_present_interval > 0,
            "tester_present_interval": self.tester_present_interval,
            "metrics": {
                "requests_sent": self.metrics.requests_sent,
                "responses_received": self.metrics.responses_received,
                "timeouts": self.metrics.timeouts,
                "errors": self.metrics.errors,
            },
        }

    @action("Diagnostic Session Control", "Change diagnostic session")
    @action.select(
        "session_type",
        title="Session Type",
        description="Type of diagnostic session",
        choices=[
            "Default Session",
            "Programming Session",
            "Extended Diagnostic Session",
            "Safety System Diagnostic Session",
        ],
        default="Extended Diagnostic Session",
    )
    @action.text(
        "tx_id",
        title="TX ID (hex, optional)",
        description="CAN TX ID (overrides global, e.g., 0x7E0)",
        placeholder="",
        default="",
    )
    @action.text(
        "rx_id",
        title="RX ID (hex, optional)",
        description="CAN RX ID (overrides global, e.g., 0x7E8)",
        placeholder="",
        default="",
    )
    def diagnostic_session_control(
        self, session_type: str, tx_id: str = "", rx_id: str = ""
    ) -> dict[str, Any]:
        """Change diagnostic session using DiagnosticSessionControl service.

        :param session_type: Type of session to activate
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with status or error
        """
        if not self.client:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Setup connection with resolved IDs
        self._setup_connection_with_ids(resolved_tx_id, resolved_rx_id)

        # Map session type to UDS session value
        session_type_map = {
            "Default Session": DiagnosticSessionControl.Session.defaultSession,
            "Programming Session": (DiagnosticSessionControl.Session.programmingSession),
            "Extended Diagnostic Session": (
                DiagnosticSessionControl.Session.extendedDiagnosticSession
            ),
            "Safety System Diagnostic Session": (
                DiagnosticSessionControl.Session.safetySystemDiagnosticSession
            ),
        }

        session_value = session_type_map.get(session_type)
        if session_value is None:
            return {"error": f"Unknown session type: {session_type}"}

        try:
            start_time = time.time()

            logger.info(f"Changing diagnostic session to: {session_type}")
            self.client.change_session(session_value)

            elapsed_ms = (time.time() - start_time) * 1000

            logger.info(f"Session changed successfully in {elapsed_ms:.1f}ms")

            return {
                "status": "success",
                "session_type": session_type,
                "elapsed_ms": round(elapsed_ms, 2),
            }

        except NegativeResponseException as e:
            nrc_name = e.response.code_name if hasattr(e.response, "code_name") else "Unknown"
            logger.error(f"Session control NRC: {nrc_name} (0x{e.response.code:02X})")
            return {"error": f"NRC: {nrc_name} (0x{e.response.code:02X})"}
        except TimeoutException:
            logger.error("Session control timeout")
            return {"error": "Timeout waiting for response"}
        except Exception as e:
            logger.error(f"Session control error: {e}")
            return {"error": str(e)}

    @action("Read Data By Identifier", "Read data from ECU by DID")
    @action.text(
        "did",
        title="Data Identifier (hex)",
        description="DID to read (e.g., 0x1234, 1234)",
        placeholder="0x1234",
        default="0x1234",
    )
    @action.text(
        "tx_id",
        title="TX ID (hex, optional)",
        description="CAN TX ID (overrides global, e.g., 0x7E0)",
        placeholder="",
        default="",
    )
    @action.text(
        "rx_id",
        title="RX ID (hex, optional)",
        description="CAN RX ID (overrides global, e.g., 0x7E8)",
        placeholder="",
        default="",
    )
    def read_data_by_identifier(self, did: str, tx_id: str = "", rx_id: str = "") -> dict[str, Any]:
        """Read data from ECU using ReadDataByIdentifier service.

        Uses udsoncan's codec architecture with HexDidCodec for dynamic DID reads.

        :param did: Data Identifier as hex string
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with data or error
        """
        if not self.client:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Setup connection with resolved IDs
        self._setup_connection_with_ids(resolved_tx_id, resolved_rx_id)

        # Validate and parse DID
        did_int = validate_hex_id(did, max_value=0xFFFF)
        if isinstance(did_int, dict):
            return did_int

        try:
            start_time = time.time()

            # Log TX event
            self._log_uds_tx(self.SID_READ_DATA_BY_IDENTIFIER, did_int, None)

            # Use udsoncan's standard read_data_by_identifier API
            # HexDidCodec is registered as default codec in client config
            response = self.client.read_data_by_identifier([did_int])

            elapsed = time.time() - start_time

            # Extract decoded data from response using codec
            # udsoncan returns decoded values in service_data.values dict
            if did_int in response.service_data.values:
                data = response.service_data.values[did_int]
            else:
                data = b""

            data_hex = format_hex_string(data)

            # Log RX event
            self._log_uds_rx(self.SID_READ_DATA_BY_IDENTIFIER, did_int, data, True, elapsed)

            return {
                "status": "success",
                "did": format_hex_id(did_int, width=4),
                "data": data_hex,
                "length": len(data),
                "elapsed_ms": round(elapsed * 1000, 2),
            }

        except NegativeResponseException as e:
            nrc_name = e.response.code_name if hasattr(e.response, "code_name") else "Unknown"
            logger.error(f"Read DID NRC: {nrc_name} (0x{e.response.code:02X})")
            return {"error": f"NRC: {nrc_name} (0x{e.response.code:02X})"}
        except TimeoutException:
            logger.error("Read DID timeout")
            return {"error": "Timeout waiting for response"}
        except Exception as e:
            logger.error(f"Read DID 0x{did_int:04X} error: {e}")
            return {"error": str(e)}

    @action("Write Data By Identifier", "Write data to ECU by DID")
    @action.text(
        "did",
        title="Data Identifier (hex)",
        description="DID to write (e.g., 0x1234)",
        placeholder="0x1234",
        default="0x1234",
    )
    @action.text(
        "data",
        title="Data (hex bytes)",
        description="Data to write (e.g., 01 02 03)",
        placeholder="01 02 03 04",
        default="00",
    )
    @action.text(
        "tx_id",
        title="TX ID (hex, optional)",
        description="CAN TX ID (overrides global, e.g., 0x7E0)",
        placeholder="",
        default="",
    )
    @action.text(
        "rx_id",
        title="RX ID (hex, optional)",
        description="CAN RX ID (overrides global, e.g., 0x7E8)",
        placeholder="",
        default="",
    )
    def write_data_by_identifier(
        self, did: str, data: str, tx_id: str = "", rx_id: str = ""
    ) -> dict[str, Any]:
        """Write data to ECU using WriteDataByIdentifier service.

        Uses udsoncan's codec architecture with HexDidCodec for dynamic DID writes.

        :param did: Data Identifier as hex string
        :param data: Data to write as hex string
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with status or error
        """
        if not self.client:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Setup connection with resolved IDs
        self._setup_connection_with_ids(resolved_tx_id, resolved_rx_id)

        # Validate and parse DID
        did_int = validate_hex_id(did, max_value=0xFFFF)
        if isinstance(did_int, dict):
            return did_int

        # Parse data - can be hex string or raw bytes
        data_bytes = parse_hex_string(data)
        if isinstance(data_bytes, dict):
            return data_bytes

        try:
            start_time = time.time()

            # Log TX event
            self._log_uds_tx(self.SID_WRITE_DATA_BY_IDENTIFIER, did_int, data_bytes)

            # Use udsoncan's standard write_data_by_identifier API
            # HexDidCodec is registered as default codec and accepts bytes directly
            response = self.client.write_data_by_identifier(did_int, data_bytes)

            elapsed = time.time() - start_time

            # Check for positive response
            if not response.positive:
                # Log RX event with failure
                self._log_uds_rx(self.SID_WRITE_DATA_BY_IDENTIFIER, did_int, None, False, elapsed)
                return {
                    "error": f"Negative response: {response.code_name}",
                    "nrc": response.code,
                }

            # Log RX event with success
            self._log_uds_rx(self.SID_WRITE_DATA_BY_IDENTIFIER, did_int, None, True, elapsed)

            return {
                "status": "success",
                "did": format_hex_id(did_int, width=4),
                "data_written": format_hex_string(data_bytes),
                "elapsed_ms": round(elapsed * 1000, 2),
            }

        except NegativeResponseException as e:
            nrc_name = e.response.code_name if hasattr(e.response, "code_name") else "Unknown"
            logger.error(f"Write DID NRC: {nrc_name} (0x{e.response.code:02X})")
            return {"error": f"NRC: {nrc_name} (0x{e.response.code:02X})"}
        except TimeoutException:
            logger.error("Write DID timeout")
            return {"error": "Timeout waiting for response"}
        except Exception as e:
            logger.error(f"Write DID 0x{did_int:04X} error: {e}")
            return {"error": str(e)}

    @action("ECU Reset", "Reset the ECU")
    @action.select(
        "reset_type",
        title="Reset Type",
        description="Type of reset to perform",
        choices=["Hard Reset", "Soft Reset", "Key Off On Reset"],
        default="Soft Reset",
    )
    @action.text(
        "tx_id",
        title="TX ID (hex, optional)",
        description="CAN TX ID (overrides global, e.g., 0x7E0)",
        placeholder="",
        default="",
    )
    @action.text(
        "rx_id",
        title="RX ID (hex, optional)",
        description="CAN RX ID (overrides global, e.g., 0x7E8)",
        placeholder="",
        default="",
    )
    def ecu_reset(self, reset_type: str, tx_id: str = "", rx_id: str = "") -> dict[str, Any]:
        """Perform ECU reset using ECUReset service.

        :param reset_type: Type of reset ("Hard Reset", "Soft Reset", "Key Off On Reset")
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with status or error
        """
        if not self.client:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Setup connection with resolved IDs
        self._setup_connection_with_ids(resolved_tx_id, resolved_rx_id)

        # Map reset type to UDS reset type value
        reset_type_map = {
            "Hard Reset": ECUReset.ResetType.hardReset,
            "Soft Reset": ECUReset.ResetType.softReset,
            "Key Off On Reset": ECUReset.ResetType.keyOffOnReset,
        }

        if reset_type not in reset_type_map:
            return {"error": f"Invalid reset type: {reset_type}"}

        try:
            start_time = time.time()

            # Log TX event
            self._log_uds_tx(self.SID_ECU_RESET, reset_type_map[reset_type], None)

            # Send UDS request
            response = self.client.ecu_reset(reset_type_map[reset_type])

            elapsed = time.time() - start_time

            # Check for positive response
            if not response.positive:
                # Log RX event with failure
                self._log_uds_rx(
                    self.SID_ECU_RESET, reset_type_map[reset_type], None, False, elapsed
                )
                return {
                    "error": f"Negative response: {response.code_name}",
                    "nrc": response.code,
                }

            # Log RX event with success
            self._log_uds_rx(self.SID_ECU_RESET, reset_type_map[reset_type], None, True, elapsed)

            # ECU may respond with power down time
            power_down_time = getattr(response.service_data, "power_down_time", None)

            result = {
                "status": "success",
                "reset_type": reset_type,
                "elapsed_ms": round(elapsed * 1000, 2),
            }

            if power_down_time is not None:
                result["power_down_time_ms"] = power_down_time

            return result

        except Exception as e:
            logger.error(f"ECU reset error: {e}")
            return {"error": str(e)}

    @action("Routine Control", "Control diagnostic routines")
    @action.select(
        "control_type",
        title="Control Type",
        description="Routine control operation",
        choices=["Start Routine", "Stop Routine", "Request Results"],
        default="Start Routine",
    )
    @action.text(
        "routine_id",
        title="Routine ID (hex)",
        description="Routine identifier (e.g., 0x0203)",
        placeholder="0x0203",
        default="0x0203",
    )
    @action.text(
        "data",
        title="Data (hex bytes, optional)",
        description="Optional data for routine (e.g., 01 02)",
        placeholder="01 02",
        default="",
    )
    @action.text(
        "tx_id",
        title="TX ID (hex, optional)",
        description="CAN TX ID (overrides global, e.g., 0x7E0)",
        placeholder="",
        default="",
    )
    @action.text(
        "rx_id",
        title="RX ID (hex, optional)",
        description="CAN RX ID (overrides global, e.g., 0x7E8)",
        placeholder="",
        default="",
    )
    def routine_control(
        self, control_type: str, routine_id: str, data: str = "", tx_id: str = "", rx_id: str = ""
    ) -> dict[str, Any]:
        """Control diagnostic routine using RoutineControl service.

        :param control_type: Control operation type
        :param routine_id: Routine identifier as hex string
        :param data: Optional data as hex string
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with routine results or error
        """
        if not self.client:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Setup connection with resolved IDs
        self._setup_connection_with_ids(resolved_tx_id, resolved_rx_id)

        # Map control type to UDS control type value
        control_type_map = {
            "Start Routine": RoutineControl.ControlType.startRoutine,
            "Stop Routine": RoutineControl.ControlType.stopRoutine,
            "Request Results": RoutineControl.ControlType.requestRoutineResults,
        }

        if control_type not in control_type_map:
            return {"error": f"Invalid control type: {control_type}"}

        # Validate and parse routine ID
        routine_id_int = validate_hex_id(routine_id, max_value=0xFFFF)
        if isinstance(routine_id_int, dict):
            return routine_id_int

        # Parse optional data
        data_bytes = b""
        if data.strip():
            data_bytes = parse_hex_string(data)
            if isinstance(data_bytes, dict):
                return data_bytes

        try:
            start_time = time.time()

            # Send UDS request
            response = self.client.routine_control(
                control_type_map[control_type], routine_id_int, data=data_bytes
            )

            elapsed = time.time() - start_time

            # Check for positive response
            if not response.positive:
                return {
                    "error": f"Negative response: {response.code_name}",
                    "nrc": response.code,
                }

            # Extract routine results if present
            result = {
                "status": "success",
                "control_type": control_type,
                "routine_id": format_hex_id(routine_id_int, width=4),
                "elapsed_ms": round(elapsed * 1000, 2),
            }

            # Add response data if present
            if hasattr(response.service_data, "routine_status_record"):
                routine_data = response.service_data.routine_status_record
                if routine_data:
                    result["response_data"] = format_hex_string(routine_data)

            return result

        except Exception as e:
            logger.error(f"Routine control error: {e}")
            return {"error": str(e)}

    @action("Input Output Control", "Control input/output signals")
    @action.text(
        "did",
        title="Data Identifier (hex)",
        description="DID to control (e.g., 0x1234)",
        placeholder="0x1234",
        default="0x1234",
    )
    @action.select(
        "control_parameter",
        title="Control Parameter",
        description="Type of control to apply",
        choices=[
            "Return Control To ECU",
            "Reset To Default",
            "Freeze Current State",
            "Short Term Adjustment",
        ],
        default="Return Control To ECU",
    )
    @action.text(
        "control_option",
        title="Control Option Record (hex, optional)",
        description="Optional control data (e.g., 01 02)",
        placeholder="01 02",
        default="",
    )
    @action.text(
        "tx_id",
        title="TX ID (hex, optional)",
        description="CAN TX ID (overrides global, e.g., 0x7E0)",
        placeholder="",
        default="",
    )
    @action.text(
        "rx_id",
        title="RX ID (hex, optional)",
        description="CAN RX ID (overrides global, e.g., 0x7E8)",
        placeholder="",
        default="",
    )
    def input_output_control(
        self,
        did: str,
        control_parameter: str,
        control_option: str = "",
        tx_id: str = "",
        rx_id: str = "",
    ) -> dict[str, Any]:
        """Control input/output using InputOutputControlByIdentifier service.

        :param did: Data Identifier as hex string
        :param control_parameter: Control parameter type
        :param control_option: Optional control option record as hex string
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with status or error
        """
        if not self.client:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Setup connection with resolved IDs
        self._setup_connection_with_ids(resolved_tx_id, resolved_rx_id)

        # Map control parameter to UDS control parameter value
        control_param_map = {
            "Return Control To ECU": (
                InputOutputControlByIdentifier.ControlParam.returnControlToECU
            ),
            "Reset To Default": (InputOutputControlByIdentifier.ControlParam.resetToDefault),
            "Freeze Current State": (
                InputOutputControlByIdentifier.ControlParam.freezeCurrentState
            ),
            "Short Term Adjustment": (
                InputOutputControlByIdentifier.ControlParam.shortTermAdjustment
            ),
        }

        if control_parameter not in control_param_map:
            return {"error": f"Invalid control parameter: {control_parameter}"}

        # Validate and parse DID
        did_int = validate_hex_id(did, max_value=0xFFFF)
        if isinstance(did_int, dict):
            return did_int

        # Parse optional control option
        control_option_bytes = b""
        if control_option.strip():
            control_option_bytes = parse_hex_string(control_option)
            if isinstance(control_option_bytes, dict):
                return control_option_bytes

        try:
            start_time = time.time()

            # Send UDS request
            response = self.client.io_control(
                did_int,
                control_param_map[control_parameter],
                values=list(control_option_bytes) if control_option_bytes else None,
            )

            elapsed = time.time() - start_time

            # Check for positive response
            if not response.positive:
                return {
                    "error": f"Negative response: {response.code_name}",
                    "nrc": response.code,
                }

            return {
                "status": "success",
                "did": format_hex_id(did_int, width=4),
                "control_parameter": control_parameter,
                "elapsed_ms": round(elapsed * 1000, 2),
            }

        except Exception as e:
            logger.error(f"IO control error: {e}")
            return {"error": str(e)}

    @action("Tester Present", "Send tester present message")
    @action.boolean(
        "suppress_response",
        title="Suppress Positive Response",
        description="Suppress positive response from ECU",
        default=False,
        widget="toggle",
    )
    @action.text(
        "tx_id",
        title="TX ID (hex, optional)",
        description="CAN TX ID (overrides global, e.g., 0x7E0)",
        placeholder="",
        default="",
    )
    @action.text(
        "rx_id",
        title="RX ID (hex, optional)",
        description="CAN RX ID (overrides global, e.g., 0x7E8)",
        placeholder="",
        default="",
    )
    def send_tester_present(
        self, suppress_response: bool = False, tx_id: str = "", rx_id: str = ""
    ) -> dict[str, Any]:
        """Send tester present message using TesterPresent service.

        :param suppress_response: Whether to suppress positive response
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with status or error
        """
        if not self.client:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Setup connection with resolved IDs
        self._setup_connection_with_ids(resolved_tx_id, resolved_rx_id)

        try:
            start_time = time.time()

            # Log TX event
            self._log_uds_tx(self.SID_TESTER_PRESENT, 0, None)

            # Send UDS request
            response = self.client.tester_present(suppress_positive_response=suppress_response)

            elapsed = time.time() - start_time

            if response and not response.positive:
                # Log RX event with failure
                self._log_uds_rx(self.SID_TESTER_PRESENT, 0, None, False, elapsed)
                return {
                    "error": f"Negative response: {response.code_name}",
                    "nrc": response.code,
                }

            # Log RX event with success
            self._log_uds_rx(self.SID_TESTER_PRESENT, 0, None, True, elapsed)

            return {
                "status": "success",
                "suppress_response": suppress_response,
                "elapsed_ms": round(elapsed * 1000, 2),
            }

        except Exception as e:
            logger.error(f"Tester present error: {e}")
            return {"error": str(e)}

    @action("Periodic Tester Present", "Start/stop periodic tester present")
    @action.boolean(
        "enabled",
        title="Enable",
        description="Start or stop periodic tester present",
        default=False,
        widget="toggle",
    )
    @action.number(
        "interval",
        minimum=0.5,
        maximum=10.0,
        multiple_of=0.1,
        default=2.0,
        title="Interval (seconds)",
        description="Send tester present every N seconds",
        widget="range",
    )
    @action.text(
        "tx_id",
        title="TX ID (hex, optional)",
        description="CAN TX ID (overrides global, e.g., 0x7E0)",
        placeholder="",
        default="",
    )
    @action.text(
        "rx_id",
        title="RX ID (hex, optional)",
        description="CAN RX ID (overrides global, e.g., 0x7E8)",
        placeholder="",
        default="",
    )
    def periodic_tester_present(
        self, enabled: bool, interval: float, tx_id: str = "", rx_id: str = ""
    ) -> dict[str, Any]:
        """Start or stop periodic tester present messages.

        When started, tester present will run on the specified TX/RX IDs.
        Starting a new session will cancel any existing session.

        :param enabled: True to start, False to stop
        :param interval: Interval in seconds between messages
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Status dictionary
        """
        if not self.client:
            return {"error": "UDS client not started"}

        # Stop requested
        if not enabled:
            if self.tester_present_interval == 0:
                return {"message": "Periodic tester present not active"}

            if self.tester_present_task:
                self.tester_present_task.cancel()
                self.tester_present_task = None

            self.tester_present_interval = 0
            self.current_tx_id = None
            self.current_rx_id = None
            logger.info("Stopped periodic tester present")

            return {
                "status": "stopped",
                "message": "Periodic tester present disabled",
            }

        # Start requested - resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Setup connection with resolved IDs
        self._setup_connection_with_ids(resolved_tx_id, resolved_rx_id)

        # Cancel existing task if running
        if self.tester_present_task and not self.tester_present_task.done():
            logger.info("Cancelling existing periodic tester present")
            self.tester_present_task.cancel()
            self.tester_present_task = None

        # Store TX/RX IDs for this tester present session
        self.current_tx_id = resolved_tx_id
        self.current_rx_id = resolved_rx_id
        self.tester_present_interval = interval

        logger.info(
            f"Starting periodic tester present: {interval}s on "
            f"TX=0x{resolved_tx_id:03X}, RX=0x{resolved_rx_id:03X}"
        )

        # Create background task
        self.tester_present_task = asyncio.create_task(self._periodic_tester_present())

        return {
            "status": "started",
            "interval": interval,
            "tx_id": format_hex_id(resolved_tx_id, width=3),
            "rx_id": format_hex_id(resolved_rx_id, width=3),
            "message": f"Sending tester present every {interval}s",
        }

    @action("Read DTC Information", "Read diagnostic trouble codes")
    @action.select(
        "status_mask",
        title="DTC Status Mask",
        description="Type of DTCs to read",
        choices=[
            "All DTCs",
            "Test Failed",
            "Test Failed This Operation Cycle",
            "Pending DTC",
            "Confirmed DTC",
            "Test Not Completed Since Last Clear",
            "Test Failed Since Last Clear",
            "Test Not Completed This Operation Cycle",
            "Warning Indicator Requested",
        ],
        default="All DTCs",
    )
    @action.text(
        "tx_id",
        title="TX ID (hex, optional)",
        description="CAN TX ID (overrides global, e.g., 0x7E0)",
        placeholder="",
        default="",
    )
    @action.text(
        "rx_id",
        title="RX ID (hex, optional)",
        description="CAN RX ID (overrides global, e.g., 0x7E8)",
        placeholder="",
        default="",
    )
    def read_dtc_information(
        self, status_mask: str, tx_id: str = "", rx_id: str = ""
    ) -> dict[str, Any]:
        """Read diagnostic trouble codes using ReadDTCInformation service.

        :param status_mask: Type of DTCs to read
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with DTCs or error
        """
        if not self.client:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Setup connection with resolved IDs
        self._setup_connection_with_ids(resolved_tx_id, resolved_rx_id)

        # Map status mask to values
        status_mask_map = {
            "All DTCs": 0xFF,
            "Test Failed": 0x01,
            "Test Failed This Operation Cycle": 0x02,
            "Pending DTC": 0x04,
            "Confirmed DTC": 0x08,
            "Test Not Completed Since Last Clear": 0x10,
            "Test Failed Since Last Clear": 0x20,
            "Test Not Completed This Operation Cycle": 0x40,
            "Warning Indicator Requested": 0x80,
        }

        mask_value = status_mask_map.get(status_mask, 0xFF)

        try:
            start_time = time.time()

            logger.info(f"Reading DTCs with status mask: {status_mask} (0x{mask_value:02X})")

            # Use udsoncan's get_dtc_by_status_mask
            response = self.client.get_dtc_by_status_mask(mask_value)

            elapsed_ms = (time.time() - start_time) * 1000

            # Parse DTCs from response
            dtcs = []
            if hasattr(response, "dtcs") and response.dtcs:
                for dtc in response.dtcs:
                    dtcs.append(
                        {
                            "id": f"0x{dtc.id:06X}" if hasattr(dtc, "id") else "Unknown",
                            "status": f"0x{dtc.status.get_byte_as_int():02X}"
                            if hasattr(dtc, "status")
                            else "Unknown",
                            "severity": getattr(dtc, "severity", None),
                        }
                    )

            logger.info(f"Found {len(dtcs)} DTCs in {elapsed_ms:.1f}ms")

            return {
                "status": "success",
                "status_mask": status_mask,
                "dtc_count": len(dtcs),
                "dtcs": dtcs,
                "elapsed_ms": round(elapsed_ms, 2),
            }

        except NegativeResponseException as e:
            nrc_name = e.response.code_name if hasattr(e.response, "code_name") else "Unknown"
            logger.error(f"Read DTC NRC: {nrc_name} (0x{e.response.code:02X})")
            return {"error": f"NRC: {nrc_name} (0x{e.response.code:02X})"}
        except TimeoutException:
            logger.error("Read DTC timeout")
            return {"error": "Timeout waiting for response"}
        except Exception as e:
            logger.error(f"Read DTC error: {e}")
            return {"error": str(e)}

    @action("Clear Diagnostic Information", "Clear diagnostic trouble codes")
    @action.text(
        "group",
        title="DTC Group (hex, optional)",
        description="DTC group to clear (3 bytes, e.g., FFFFFF for all DTCs)",
        placeholder="FFFFFF",
        default="FFFFFF",
    )
    @action.text(
        "tx_id",
        title="TX ID (hex, optional)",
        description="CAN TX ID (overrides global, e.g., 0x7E0)",
        placeholder="",
        default="",
    )
    @action.text(
        "rx_id",
        title="RX ID (hex, optional)",
        description="CAN RX ID (overrides global, e.g., 0x7E8)",
        placeholder="",
        default="",
    )
    def clear_diagnostic_information(
        self, group: str = "FFFFFF", tx_id: str = "", rx_id: str = ""
    ) -> dict[str, Any]:
        """Clear diagnostic trouble codes using ClearDiagnosticInformation service.

        :param group: DTC group mask (3 bytes hex, FFFFFF = all DTCs)
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Success status or error
        """
        if not self.client:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Setup connection with resolved IDs
        self._setup_connection_with_ids(resolved_tx_id, resolved_rx_id)

        try:
            start_time = time.time()

            # Parse group mask
            group_bytes = parse_hex_string(group)
            if isinstance(group_bytes, dict):
                return {"error": f"Invalid group format: {group_bytes['error']}"}

            if len(group_bytes) != 3:
                return {"error": f"Group must be 3 bytes, got {len(group_bytes)}"}

            group_int = int.from_bytes(group_bytes, byteorder="big")

            logger.info(f"Clearing DTCs for group: 0x{group_int:06X}")
            self.client.clear_dtc(group_int)

            elapsed_ms = (time.time() - start_time) * 1000

            logger.info("DTCs cleared successfully")

            return {
                "status": "success",
                "group": f"0x{group_int:06X}",
                "elapsed_ms": round(elapsed_ms, 2),
            }

        except NegativeResponseException as e:
            nrc_name = e.response.code_name if hasattr(e.response, "code_name") else "Unknown"
            logger.error(f"Clear DTC NRC: {nrc_name} (0x{e.response.code:02X})")
            return {"error": f"NRC: {nrc_name} (0x{e.response.code:02X})"}
        except TimeoutException:
            logger.error("Clear DTC timeout")
            return {"error": "Timeout waiting for response"}
        except Exception as e:
            logger.error(f"Clear DTC error: {e}")
            return {"error": str(e)}

    @action("Security Access", "Request security access")
    @action.select(
        "access_level",
        title="Access Level",
        description="Security access level to request",
        choices=["Level 1", "Level 2", "Level 3", "Level 4"],
        default="Level 1",
    )
    @action.text(
        "key",
        title="Security Key (hex, optional)",
        description="Security key for seed-key exchange (leave empty for seed request)",
        placeholder="",
        default="",
    )
    @action.text(
        "tx_id",
        title="TX ID (hex, optional)",
        description="CAN TX ID (overrides global, e.g., 0x7E0)",
        placeholder="",
        default="",
    )
    @action.text(
        "rx_id",
        title="RX ID (hex, optional)",
        description="CAN RX ID (overrides global, e.g., 0x7E8)",
        placeholder="",
        default="",
    )
    def security_access(
        self, access_level: str, key: str = "", tx_id: str = "", rx_id: str = ""
    ) -> dict[str, Any]:
        """Request security access using SecurityAccess service.

        :param access_level: Security access level
        :param key: Optional security key (empty = request seed)
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with seed/status or error
        """
        if not self.client:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Setup connection with resolved IDs
        self._setup_connection_with_ids(resolved_tx_id, resolved_rx_id)

        # Map access level to request/send key sub-functions
        # Odd = request seed, Even = send key
        level_map = {
            "Level 1": 1,
            "Level 2": 3,
            "Level 3": 5,
            "Level 4": 7,
        }

        base_level = level_map.get(access_level, 1)

        try:
            start_time = time.time()

            if not key:
                # Request seed
                logger.info(f"Requesting security seed for {access_level}")
                response = self.client.request_seed(base_level)

                elapsed_ms = (time.time() - start_time) * 1000

                # Extract seed from response
                seed = (
                    format_hex_string(response.service_data.seed)
                    if hasattr(response.service_data, "seed")
                    else ""
                )

                logger.info(f"Received seed: {seed}")

                return {
                    "status": "success",
                    "operation": "request_seed",
                    "access_level": access_level,
                    "seed": seed,
                    "elapsed_ms": round(elapsed_ms, 2),
                }
            else:
                # Send key
                key_bytes = parse_hex_string(key)
                if isinstance(key_bytes, dict):
                    return {"error": f"Invalid key format: {key_bytes['error']}"}

                logger.info(f"Sending security key for {access_level}")
                response = self.client.send_key(base_level + 1, key_bytes)

                elapsed_ms = (time.time() - start_time) * 1000

                logger.info("Security access granted")

                return {
                    "status": "success",
                    "operation": "send_key",
                    "access_level": access_level,
                    "access_granted": True,
                    "elapsed_ms": round(elapsed_ms, 2),
                }

        except NegativeResponseException as e:
            nrc_name = e.response.code_name if hasattr(e.response, "code_name") else "Unknown"
            logger.error(f"Security access NRC: {nrc_name} (0x{e.response.code:02X})")
            return {"error": f"NRC: {nrc_name} (0x{e.response.code:02X})"}
        except TimeoutException:
            logger.error("Security access timeout")
            return {"error": "Timeout waiting for response"}
        except Exception as e:
            logger.error(f"Security access error: {e}")
            return {"error": str(e)}

    # ========== TRACE SCHEMA & LOGGING ==========

    def _define_schema(self) -> None:
        """Define trace schema for UDS events."""
        # TX (transmit/request) events
        self.source.add_event(
            "tx",
            [
                zelos_sdk.TraceEventFieldMetadata("service_id", zelos_sdk.DataType.UInt8),
                zelos_sdk.TraceEventFieldMetadata("service_name", zelos_sdk.DataType.String),
                zelos_sdk.TraceEventFieldMetadata("parameter", zelos_sdk.DataType.UInt32),
                zelos_sdk.TraceEventFieldMetadata("data", zelos_sdk.DataType.Binary),
            ],
        )

        # RX (receive/response) events
        self.source.add_event(
            "rx",
            [
                zelos_sdk.TraceEventFieldMetadata("service_id", zelos_sdk.DataType.UInt8),
                zelos_sdk.TraceEventFieldMetadata("service_name", zelos_sdk.DataType.String),
                zelos_sdk.TraceEventFieldMetadata("parameter", zelos_sdk.DataType.UInt32),
                zelos_sdk.TraceEventFieldMetadata("data", zelos_sdk.DataType.Binary),
                zelos_sdk.TraceEventFieldMetadata("success", zelos_sdk.DataType.Boolean),
                zelos_sdk.TraceEventFieldMetadata("elapsed_ms", zelos_sdk.DataType.Float32, "ms"),
            ],
        )

    def _log_uds_tx(
        self,
        service_id: int,
        parameter: int,
        data: bytes | None,
    ) -> None:
        """Log UDS TX (request) event to trace.

        :param service_id: UDS service ID
        :param parameter: Service parameter (DID, routine ID, etc.)
        :param data: Request data
        """
        service_name = self.SERVICE_NAMES.get(service_id, f"Unknown_0x{service_id:02X}")

        self.source.tx.log(
            service_id=service_id,
            service_name=service_name,
            parameter=parameter,
            data=data if data else b"",
        )

    def _log_uds_rx(
        self,
        service_id: int,
        parameter: int,
        data: bytes | None,
        success: bool,
        elapsed: float,
    ) -> None:
        """Log UDS RX (response) event to trace.

        :param service_id: UDS service ID
        :param parameter: Service parameter (DID, routine ID, etc.)
        :param data: Response data
        :param success: Whether request was successful
        :param elapsed: Elapsed time in seconds
        """
        service_name = self.SERVICE_NAMES.get(service_id, f"Unknown_0x{service_id:02X}")

        self.source.rx.log(
            service_id=service_id,
            service_name=service_name,
            parameter=parameter,
            data=data if data else b"",
            success=success,
            elapsed_ms=elapsed * 1000.0,
        )
