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

        # Metrics tracking
        self.metrics = Metrics()

        # Periodic tester present task (controlled by action, not config)
        self.tester_present_task: asyncio.Task | None = None
        self.tester_present_interval: float = 0  # Disabled by default
        self.tester_present_tx_id: int | None = None  # Track TP TX ID
        self.tester_present_rx_id: int | None = None  # Track TP RX ID
        self.tester_present_cleanup: dict[str, Any] | None = None  # TP resources to clean up

        # Create trace source (in isolated namespace if provided)
        if self.namespace:
            self.source = zelos_sdk.TraceSource("uds_client", namespace=self.namespace)
        else:
            self.source = zelos_sdk.TraceSource("uds_client")

        self._define_schema()

    def start(self) -> None:
        """Start UDS client - validates config without creating connections."""
        logger.info("Starting UDS client")

        try:
            # Validate config has required fields
            interface = self.config.get("interface", "socketcan")
            channel = self.config.get("channel", "vcan0")

            logger.info(f"UDS client configured: interface={interface}, channel={channel}")
            logger.info("Connections will be created on-demand for each transaction")

            self.running = True

        except Exception as e:
            logger.error(f"Failed to start UDS client: {e}")
            self.stop()
            raise

    def stop(self) -> None:
        """Stop UDS client and clean up resources."""
        logger.info("Stopping UDS client")
        self.running = False

        # Cancel periodic tester present (which will clean up its own connection)
        self.tester_present_interval = 0
        if self.tester_present_task:
            self.tester_present_task.cancel()
            self.tester_present_task = None

        self.tester_present_tx_id = None
        self.tester_present_rx_id = None

        logger.info("UDS client stopped")

    def run(self) -> None:
        """Main event loop - blocks to keep the process alive for action serving.

        UDS actions create connections on-demand. Periodic tester present
        is managed via the periodic_tester_present() action which creates
        async tasks in the event loop.
        """
        logger.info("UDS client running (on-demand mode - no persistent connections)")
        asyncio.run(self._run_async())

    async def _run_async(self) -> None:
        """Async event loop - keeps process alive and handles periodic tasks."""
        try:
            while self.running:
                # Sleep and allow async tasks (like periodic tester present) to run
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            logger.info("UDS event loop cancelled")

    async def _periodic_tester_present(self) -> None:
        """Send periodic tester present messages with dedicated CAN bus connection.

        This background task maintains its own long-lived CAN bus connection
        for the duration of the periodic TP session.
        """
        if self.tester_present_tx_id is None or self.tester_present_rx_id is None:
            logger.error("Periodic TP: TX/RX IDs not set")
            return

        # Create dedicated UDS client for periodic TP
        try:
            tp_client, self.tester_present_cleanup = self._create_uds_client(
                self.tester_present_tx_id, self.tester_present_rx_id
            )
            logger.debug(
                f"Periodic TP: Created connection TX=0x{self.tester_present_tx_id:03X}, "
                f"RX=0x{self.tester_present_rx_id:03X}"
            )
        except Exception as e:
            logger.error(f"Periodic TP: Failed to create connection: {e}")
            return

        try:
            while self.running and self.tester_present_interval > 0:
                try:
                    await asyncio.sleep(self.tester_present_interval)

                    if not self.running or self.tester_present_interval == 0:
                        break

                    # Send tester present with suppressed response (fire-and-forget)
                    # This matches the reference implementation pattern
                    with tp_client.suppress_positive_response(wait_nrc=False):
                        tp_client.tester_present()

                    logger.debug("Periodic tester present sent (suppressed response)")

                except asyncio.CancelledError:
                    logger.info("Periodic tester present cancelled")
                    break
                except Exception as e:
                    logger.warning(f"Periodic tester present error: {e}")

        finally:
            # Clean up dedicated TP connection
            if self.tester_present_cleanup:
                logger.debug("Periodic TP: Cleaning up connection")
                self._cleanup_uds_client(self.tester_present_cleanup)
                self.tester_present_cleanup = None

    # ========== HELPERS ==========

    def _create_uds_client(self, tx_id: int, rx_id: int) -> tuple[Client, dict[str, Any]]:
        """Create a UDS client on-demand for a single transaction.

        Creates: CAN bus → Notifier → ISO-TP stack → Connection → UDS Client
        Returns the client and a cleanup dictionary for resource disposal.

        :param tx_id: Transmit CAN ID (tester→ECU)
        :param rx_id: Receive CAN ID (ECU→tester)
        :return: Tuple of (UDS client, cleanup dict with resources to clean up)
        """
        # Determine if we need 29-bit addressing
        # Use 29-bit if: explicitly configured OR either ID exceeds 11-bit range
        use_extended = self.config.get("extended_id", False) or tx_id > 0x7FF or rx_id > 0x7FF
        id_bits = 29 if use_extended else 11
        logger.debug(f"Creating UDS client: TX=0x{tx_id:X}, RX=0x{rx_id:X} ({id_bits}-bit)")

        # Create CAN bus interface
        interface = self.config.get("interface", "socketcan")
        channel = self.config.get("channel", "vcan0")
        bitrate = self.config.get("bitrate")

        bus_kwargs: dict[str, Any] = {"interface": interface, "channel": channel}
        if bitrate:
            bus_kwargs["bitrate"] = bitrate

        bus = can.Bus(**bus_kwargs)

        # Create ISO-TP addressing (11-bit or 29-bit based on ID range or config)
        if use_extended:
            tp_addr = isotp.Address(isotp.AddressingMode.Normal_29bits, txid=tx_id, rxid=rx_id)
        else:
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

        # Create notifier
        notifier = can.Notifier(bus, [])

        # Create ISO-TP stack
        isotp_stack = isotp.NotifierBasedCanStack(
            bus=bus, notifier=notifier, address=tp_addr, params=isotp_params
        )

        # Create connection
        connection = PythonIsoTpConnection(isotp_stack)

        # Create client with configuration
        config = udsoncan.configs.default_client_config.copy()
        config["data_identifiers"] = {"default": HexDidCodec}
        config["input_output"] = {"default": {"codec": HexDidCodec}}

        if "request_timeout" in self.config:
            config["request_timeout"] = self.config["request_timeout"]
        if "p2_timeout" in self.config:
            config["p2_timeout"] = self.config["p2_timeout"]
        if "p2_star_timeout" in self.config:
            config["p2_star_timeout"] = self.config["p2_star_timeout"]
        if "use_external_sniffer" in self.config:
            config["use_external_sniffer"] = self.config["use_external_sniffer"]

        client = Client(connection, config=config)
        client.open()

        # Return client and cleanup resources
        cleanup = {
            "client": client,
            "connection": connection,
            "isotp_stack": isotp_stack,
            "notifier": notifier,
            "bus": bus,
        }

        return client, cleanup

    def _cleanup_uds_client(self, cleanup: dict[str, Any]) -> None:
        """Clean up resources from an on-demand UDS client.

        :param cleanup: Dictionary with resources to clean up
        """
        # Close connection
        if "connection" in cleanup and cleanup["connection"]:
            try:
                cleanup["connection"].close()
            except Exception as e:
                logger.debug(f"Error closing connection: {e}")

        # Stop ISO-TP stack
        if "isotp_stack" in cleanup and cleanup["isotp_stack"]:
            try:
                cleanup["isotp_stack"].stop()
            except Exception as e:
                logger.debug(f"Error stopping ISO-TP stack: {e}")

        # Stop notifier
        if "notifier" in cleanup and cleanup["notifier"]:
            try:
                cleanup["notifier"].stop()
            except Exception as e:
                logger.debug(f"Error stopping notifier: {e}")

        # Close CAN bus
        if "bus" in cleanup and cleanup["bus"]:
            try:
                cleanup["bus"].shutdown()
            except Exception as e:
                logger.debug(f"Error shutting down CAN bus: {e}")

    def _resolve_tx_rx_ids(
        self, tx_id: str | None = None, rx_id: str | None = None
    ) -> tuple[int, int] | dict[str, str]:
        """Resolve TX/RX IDs from action parameters or global config.

        Supports both 11-bit (0x000-0x7FF) and 29-bit (0x000-0x1FFFFFFF) CAN IDs.
        The addressing mode is automatically selected in _create_uds_client based
        on whether IDs exceed 11-bit range or extended_id config is set.

        :param tx_id: Optional action-specific TX ID (hex string)
        :param rx_id: Optional action-specific RX ID (hex string)
        :return: Tuple of (tx_id_int, rx_id_int) or error dict
        """
        # Max 29-bit CAN ID
        max_can_id = 0x1FFFFFFF

        # Try action-specific TX ID first
        if tx_id:
            tx_id_int = validate_hex_id(tx_id, max_value=max_can_id)
            if isinstance(tx_id_int, dict):
                return {"error": f"Invalid TX ID: {tx_id_int['error']}"}
        else:
            # Fall back to global config
            tx_id_str = self.config.get("tx_id")
            if tx_id_str is None:
                return {"error": "No TX ID specified (provide in action or global config)"}
            # Validate config value
            tx_id_int = validate_hex_id(tx_id_str, max_value=max_can_id)
            if isinstance(tx_id_int, dict):
                return {"error": f"Invalid TX ID in config: {tx_id_int['error']}"}

        # Try action-specific RX ID first
        if rx_id:
            rx_id_int = validate_hex_id(rx_id, max_value=max_can_id)
            if isinstance(rx_id_int, dict):
                return {"error": f"Invalid RX ID: {rx_id_int['error']}"}
        else:
            # Fall back to global config
            rx_id_str = self.config.get("rx_id")
            if rx_id_str is None:
                return {"error": "No RX ID specified (provide in action or global config)"}
            # Validate config value
            rx_id_int = validate_hex_id(rx_id_str, max_value=max_can_id)
            if isinstance(rx_id_int, dict):
                return {"error": f"Invalid RX ID in config: {rx_id_int['error']}"}

        return (tx_id_int, rx_id_int)

    # ========== ACTIONS ==========

    @action("Get Status", "View UDS client status and metrics")
    def get_status(self) -> dict[str, Any]:
        """Get current UDS client status.

        :return: Status dictionary with connection state and metrics
        """
        # Get and format TX/RX IDs from config (they're stored as strings)
        tx_id_str = self.config.get("tx_id")
        rx_id_str = self.config.get("rx_id")

        return {
            "running": self.running,
            "connection_mode": "on-demand (stateless)",
            "interface": self.config.get("interface", "socketcan"),
            "channel": self.config.get("channel", "vcan0"),
            "default_tx_id": tx_id_str if tx_id_str else "not set",
            "default_rx_id": rx_id_str if rx_id_str else "not set",
            "tester_present_active": self.tester_present_interval > 0,
            "tester_present_interval": self.tester_present_interval,
            "tester_present_tx_id": format_hex_id(self.tester_present_tx_id, width=3)
            if self.tester_present_tx_id
            else None,
            "tester_present_rx_id": format_hex_id(self.tester_present_rx_id, width=3)
            if self.tester_present_rx_id
            else None,
            "metrics": {
                "requests_sent": self.metrics.requests_sent,
                "responses_received": self.metrics.responses_received,
                "timeouts": self.metrics.timeouts,
                "errors": self.metrics.errors,
            },
        }

    @action("Diagnostic Session Control", "Change diagnostic session")
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
    def diagnostic_session_control(
        self, tx_id: str = "", rx_id: str = "", session_type: str = "Extended Diagnostic Session"
    ) -> dict[str, Any]:
        """Change diagnostic session using DiagnosticSessionControl service.

        Creates on-demand CAN bus connection for this transaction.

        :param session_type: Type of session to activate
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with status or error
        """
        if not self.running:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

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

        client, cleanup = None, None
        try:
            client, cleanup = self._create_uds_client(resolved_tx_id, resolved_rx_id)

            start_time = time.time()

            logger.info(f"Changing diagnostic session to: {session_type}")
            client.change_session(session_value)

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
        finally:
            if cleanup:
                self._cleanup_uds_client(cleanup)

    @action("Read Data By Identifier", "Read data from ECU by DID")
    @action.text(
        "tx_id",
        title="TX ID (hex, optional)",
        description="CAN TX ID (overrides global, e.g., 0x7E0)",
        placeholder="0x7E0",
        default="",
    )
    @action.text(
        "rx_id",
        title="RX ID (hex, optional)",
        description="CAN RX ID (overrides global, e.g., 0x7E8)",
        placeholder="0x7E8",
        default="",
    )
    @action.text(
        "did",
        title="Data Identifier (hex)",
        description="DID to read (e.g., 0x1234, 1234)",
        placeholder="0x1234",
        default="0x1234",
    )
    def read_data_by_identifier(
        self, tx_id: str = "", rx_id: str = "", did: str = "0x1234"
    ) -> dict[str, Any]:
        """Read data from ECU using ReadDataByIdentifier service.

        Uses udsoncan's codec architecture with HexDidCodec for dynamic DID reads.
        Creates on-demand CAN bus connection for this transaction.

        :param did: Data Identifier as hex string
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with data or error
        """
        if not self.running:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Validate and parse DID
        did_int = validate_hex_id(did, max_value=0xFFFF)
        if isinstance(did_int, dict):
            return did_int

        client, cleanup = None, None
        try:
            client, cleanup = self._create_uds_client(resolved_tx_id, resolved_rx_id)

            start_time = time.time()

            # Log TX event
            self._log_uds_tx(self.SID_READ_DATA_BY_IDENTIFIER, did_int, None)

            # Use udsoncan's standard read_data_by_identifier API
            # HexDidCodec is registered as default codec in client config
            response = client.read_data_by_identifier([did_int])

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
        finally:
            if cleanup:
                self._cleanup_uds_client(cleanup)

    @action("Write Data By Identifier", "Write data to ECU by DID")
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
    def write_data_by_identifier(
        self, tx_id: str = "", rx_id: str = "", did: str = "0x1234", data: str = "00"
    ) -> dict[str, Any]:
        """Write data to ECU using WriteDataByIdentifier service.

        Uses udsoncan's codec architecture with HexDidCodec for dynamic DID writes.
        Creates on-demand CAN bus connection for this transaction.

        :param did: Data Identifier as hex string
        :param data: Data to write as hex string
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with status or error
        """
        if not self.running:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Validate and parse DID
        did_int = validate_hex_id(did, max_value=0xFFFF)
        if isinstance(did_int, dict):
            return did_int

        # Parse data - can be hex string or raw bytes
        data_bytes = parse_hex_string(data)
        if isinstance(data_bytes, dict):
            return data_bytes

        # Create on-demand UDS client for this transaction
        client = None
        cleanup = None

        try:
            client, cleanup = self._create_uds_client(resolved_tx_id, resolved_rx_id)

            start_time = time.time()

            # Log TX event
            self._log_uds_tx(self.SID_WRITE_DATA_BY_IDENTIFIER, did_int, data_bytes)

            # Use udsoncan's standard write_data_by_identifier API
            # HexDidCodec is registered as default codec and accepts bytes directly
            response = client.write_data_by_identifier(did_int, data_bytes)

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
        finally:
            # Clean up on-demand resources
            if cleanup:
                self._cleanup_uds_client(cleanup)

    @action("ECU Reset", "Reset the ECU")
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
    @action.select(
        "reset_type",
        title="Reset Type",
        description="Type of reset to perform",
        choices=["Hard Reset", "Soft Reset", "Key Off On Reset"],
        default="Soft Reset",
    )
    def ecu_reset(
        self, tx_id: str = "", rx_id: str = "", reset_type: str = "Soft Reset"
    ) -> dict[str, Any]:
        """Perform ECU reset using ECUReset service.

        Creates on-demand CAN bus connection for this transaction.

        :param reset_type: Type of reset ("Hard Reset", "Soft Reset", "Key Off On Reset")
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with status or error
        """
        if not self.running:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Map reset type to UDS reset type value
        reset_type_map = {
            "Hard Reset": ECUReset.ResetType.hardReset,
            "Soft Reset": ECUReset.ResetType.softReset,
            "Key Off On Reset": ECUReset.ResetType.keyOffOnReset,
        }

        if reset_type not in reset_type_map:
            return {"error": f"Invalid reset type: {reset_type}"}

        # Create on-demand UDS client for this transaction
        client = None
        cleanup = None

        try:
            client, cleanup = self._create_uds_client(resolved_tx_id, resolved_rx_id)

            start_time = time.time()

            # Log TX event
            self._log_uds_tx(self.SID_ECU_RESET, reset_type_map[reset_type], None)

            # Send UDS request
            response = client.ecu_reset(reset_type_map[reset_type])

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
        finally:
            # Clean up on-demand resources
            if cleanup:
                self._cleanup_uds_client(cleanup)

    @action("Routine Control", "Control diagnostic routines")
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
    def routine_control(
        self,
        tx_id: str = "",
        rx_id: str = "",
        control_type: str = "Start Routine",
        routine_id: str = "0x0203",
        data: str = "",
    ) -> dict[str, Any]:
        """Control diagnostic routine using RoutineControl service.

        Creates on-demand CAN bus connection for this transaction.

        :param control_type: Control operation type
        :param routine_id: Routine identifier as hex string
        :param data: Optional data as hex string
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with routine results or error
        """
        if not self.running:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

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

        # Create on-demand UDS client for this transaction
        client = None
        cleanup = None

        try:
            client, cleanup = self._create_uds_client(resolved_tx_id, resolved_rx_id)

            start_time = time.time()

            # Send UDS request
            response = client.routine_control(
                routine_id_int, control_type_map[control_type], data=data_bytes
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
        finally:
            # Clean up on-demand resources
            if cleanup:
                self._cleanup_uds_client(cleanup)

    @action("Input Output Control", "Control input/output signals")
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
    def input_output_control(
        self,
        tx_id: str = "",
        rx_id: str = "",
        did: str = "0x1234",
        control_parameter: str = "Return Control To ECU",
        control_option: str = "",
    ) -> dict[str, Any]:
        """Control input/output using InputOutputControlByIdentifier service.

        :param did: Data Identifier as hex string
        :param control_parameter: Control parameter type
        :param control_option: Optional control option record as hex string
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with status or error
        """
        if not self.running:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

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

        # Create on-demand UDS client for this transaction
        client = None
        cleanup = None

        try:
            client, cleanup = self._create_uds_client(resolved_tx_id, resolved_rx_id)

            start_time = time.time()

            # Send UDS request
            response = client.io_control(
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
        finally:
            # Clean up on-demand resources
            if cleanup:
                self._cleanup_uds_client(cleanup)

    @action("Tester Present", "Send tester present message")
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
    @action.boolean(
        "suppress_response",
        title="Suppress Positive Response",
        description="Don't wait for ECU response (fire-and-forget)",
        default=False,
        widget="toggle",
    )
    def send_tester_present(
        self, tx_id: str = "", rx_id: str = "", suppress_response: bool = False
    ) -> dict[str, Any]:
        """Send tester present message using TesterPresent service.

        Creates on-demand CAN bus connection for this transaction.

        :param suppress_response: If True, suppress positive response (fire-and-forget)
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with status or error
        """
        if not self.running:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Create on-demand UDS client for this transaction
        client = None
        cleanup = None

        try:
            client, cleanup = self._create_uds_client(resolved_tx_id, resolved_rx_id)

            start_time = time.time()

            # Log TX event
            self._log_uds_tx(self.SID_TESTER_PRESENT, 0, None)

            # Send UDS request with optional suppress positive response
            if suppress_response:
                # Use context manager to suppress positive response (fire-and-forget)
                with client.suppress_positive_response(wait_nrc=False):
                    client.tester_present()
                elapsed = time.time() - start_time
                # Log RX event (no response expected)
                self._log_uds_rx(self.SID_TESTER_PRESENT, 0, None, True, elapsed)
                return {
                    "status": "success",
                    "suppress_response": True,
                    "elapsed_ms": round(elapsed * 1000, 2),
                }

            # Normal request with response expected
            response = client.tester_present()

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
                "elapsed_ms": round(elapsed * 1000, 2),
            }

        except Exception as e:
            logger.error(f"Tester present error: {e}")
            return {"error": str(e)}
        finally:
            # Clean up on-demand resources
            if cleanup:
                self._cleanup_uds_client(cleanup)

    @action("Periodic Tester Present", "Start/stop periodic tester present")
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
    def periodic_tester_present(
        self, tx_id: str = "", rx_id: str = "", enabled: bool = False, interval: float = 2.0
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
        if not self.running:
            return {"error": "UDS client not started"}

        # Stop requested
        if not enabled:
            if self.tester_present_interval == 0:
                return {"message": "Periodic tester present not active"}

            # Stop the interval (the background task will clean up its own connection)
            self.tester_present_interval = 0

            # Cancel the background task
            if self.tester_present_task:
                self.tester_present_task.cancel()
                self.tester_present_task = None

            self.tester_present_tx_id = None
            self.tester_present_rx_id = None
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

        # Cancel existing task if running (will clean up its own connection)
        if self.tester_present_task and not self.tester_present_task.done():
            logger.info("Cancelling existing periodic tester present")
            # Stop the interval first so the task exits
            self.tester_present_interval = 0
            self.tester_present_task.cancel()
            self.tester_present_task = None

        # Store TX/RX IDs for this tester present session
        self.tester_present_tx_id = resolved_tx_id
        self.tester_present_rx_id = resolved_rx_id
        self.tester_present_interval = interval

        logger.info(
            f"Starting periodic tester present: {interval}s on "
            f"TX=0x{resolved_tx_id:03X}, RX=0x{resolved_rx_id:03X}"
        )

        # Create background task (which will create its own connection)
        self.tester_present_task = asyncio.create_task(self._periodic_tester_present())

        return {
            "status": "started",
            "interval": interval,
            "tx_id": format_hex_id(resolved_tx_id, width=3),
            "rx_id": format_hex_id(resolved_rx_id, width=3),
            "message": f"Sending tester present every {interval}s",
        }

    @action("Read DTC Information", "Read diagnostic trouble codes")
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
    def read_dtc_information(
        self, tx_id: str = "", rx_id: str = "", status_mask: str = "All DTCs"
    ) -> dict[str, Any]:
        """Read diagnostic trouble codes using ReadDTCInformation service.

        :param status_mask: Type of DTCs to read
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with DTCs or error
        """
        if not self.running:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

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

        # Create on-demand UDS client for this transaction
        client = None
        cleanup = None

        try:
            client, cleanup = self._create_uds_client(resolved_tx_id, resolved_rx_id)

            start_time = time.time()

            logger.info(f"Reading DTCs with status mask: {status_mask} (0x{mask_value:02X})")

            # Use udsoncan's get_dtc_by_status_mask
            response = client.get_dtc_by_status_mask(mask_value)

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
        finally:
            # Clean up on-demand resources
            if cleanup:
                self._cleanup_uds_client(cleanup)

    @action("Clear Diagnostic Information", "Clear diagnostic trouble codes")
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
    @action.text(
        "group",
        title="DTC Group (hex, optional)",
        description="DTC group to clear (3 bytes, e.g., FFFFFF for all DTCs)",
        placeholder="FFFFFF",
        default="FFFFFF",
    )
    def clear_diagnostic_information(
        self, tx_id: str = "", rx_id: str = "", group: str = "FFFFFF"
    ) -> dict[str, Any]:
        """Clear diagnostic trouble codes using ClearDiagnosticInformation service.

        :param group: DTC group mask (3 bytes hex, FFFFFF = all DTCs)
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Success status or error
        """
        if not self.running:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Parse group mask
        group_bytes = parse_hex_string(group)
        if isinstance(group_bytes, dict):
            return {"error": f"Invalid group format: {group_bytes['error']}"}

        if len(group_bytes) != 3:
            return {"error": f"Group must be 3 bytes, got {len(group_bytes)}"}

        group_int = int.from_bytes(group_bytes, byteorder="big")

        # Create on-demand UDS client for this transaction
        client = None
        cleanup = None

        try:
            client, cleanup = self._create_uds_client(resolved_tx_id, resolved_rx_id)

            start_time = time.time()

            logger.info(f"Clearing DTCs for group: 0x{group_int:06X}")
            client.clear_dtc(group_int)

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
        finally:
            # Clean up on-demand resources
            if cleanup:
                self._cleanup_uds_client(cleanup)

    @action("Security Access", "Request security access")
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
    def security_access(
        self, tx_id: str = "", rx_id: str = "", access_level: str = "Level 1", key: str = ""
    ) -> dict[str, Any]:
        """Request security access using SecurityAccess service.

        :param access_level: Security access level
        :param key: Optional security key (empty = request seed)
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with seed/status or error
        """
        if not self.running:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Map access level to request/send key sub-functions
        # Odd = request seed, Even = send key
        level_map = {
            "Level 1": 1,
            "Level 2": 3,
            "Level 3": 5,
            "Level 4": 7,
        }

        base_level = level_map.get(access_level, 1)

        # Create on-demand UDS client for this transaction
        client = None
        cleanup = None

        try:
            client, cleanup = self._create_uds_client(resolved_tx_id, resolved_rx_id)

            start_time = time.time()

            if not key:
                # Request seed
                logger.info(f"Requesting security seed for {access_level}")
                response = client.request_seed(base_level)

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
                response = client.send_key(base_level + 1, key_bytes)

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
        finally:
            # Clean up on-demand resources
            if cleanup:
                self._cleanup_uds_client(cleanup)

    # ========== FLASH / TRANSFER ACTIONS ==========

    @action("Request Download", "Initiate firmware download to ECU")
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
    @action.text(
        "address",
        title="Memory Address (hex)",
        description="Target memory address (e.g., 0x08000000)",
        placeholder="0x08000000",
        default="0x00000000",
    )
    @action.text(
        "size",
        title="Data Size (bytes)",
        description="Size of data to be transferred",
        placeholder="1024",
        default="1024",
    )
    def request_download(
        self, tx_id: str = "", rx_id: str = "", address: str = "0x00000000", size: str = "1024"
    ) -> dict[str, Any]:
        """Initiate firmware download using RequestDownload service (0x34).

        :param address: Target memory address (hex string)
        :param size: Data size in bytes
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with max_block_size or error
        """
        if not self.running:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Parse address
        address_int = validate_hex_id(address, max_value=0xFFFFFFFF)
        if isinstance(address_int, dict):
            return {"error": f"Invalid address: {address_int['error']}"}

        # Parse size
        try:
            size_int = int(size)
            if size_int <= 0:
                return {"error": "Size must be positive"}
        except ValueError:
            return {"error": f"Invalid size: {size}"}

        client, cleanup = None, None
        try:
            client, cleanup = self._create_uds_client(resolved_tx_id, resolved_rx_id)

            start_time = time.time()

            from udsoncan.common.MemoryLocation import MemoryLocation

            location = MemoryLocation(address=address_int, memorysize=size_int, address_format=32)
            logger.info(f"Requesting download: address=0x{address_int:08X}, size={size_int}")

            response = client.request_download(location)

            elapsed_ms = (time.time() - start_time) * 1000

            max_length = (
                response.service_data.max_length
                if hasattr(response.service_data, "max_length")
                else 0
            )

            logger.info(f"Download accepted. Max block size: {max_length}")

            return {
                "status": "success",
                "address": f"0x{address_int:08X}",
                "size": size_int,
                "max_block_size": max_length,
                "elapsed_ms": round(elapsed_ms, 2),
            }

        except NegativeResponseException as e:
            nrc_name = e.response.code_name if hasattr(e.response, "code_name") else "Unknown"
            logger.error(f"Request download NRC: {nrc_name} (0x{e.response.code:02X})")
            return {"error": f"NRC: {nrc_name} (0x{e.response.code:02X})"}
        except TimeoutException:
            logger.error("Request download timeout")
            return {"error": "Timeout waiting for response"}
        except Exception as e:
            logger.error(f"Request download error: {e}")
            return {"error": str(e)}
        finally:
            if cleanup:
                self._cleanup_uds_client(cleanup)

    @action("Transfer Data", "Transfer a block of data to ECU")
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
    @action.text(
        "sequence",
        title="Sequence Number",
        description="Block sequence number (0-255)",
        placeholder="1",
        default="1",
    )
    @action.text(
        "data",
        title="Data (hex bytes)",
        description="Data block to transfer (e.g., 01 02 03 04)",
        placeholder="00 11 22 33",
        default="00",
    )
    def transfer_data(
        self, tx_id: str = "", rx_id: str = "", sequence: str = "1", data: str = "00"
    ) -> dict[str, Any]:
        """Transfer data block using TransferData service (0x36).

        :param sequence: Block sequence number (0-255)
        :param data: Data to transfer as hex string
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with status or error
        """
        if not self.running:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Parse sequence number
        try:
            seq_int = int(sequence)
            if seq_int < 0 or seq_int > 255:
                return {"error": "Sequence must be 0-255"}
        except ValueError:
            return {"error": f"Invalid sequence: {sequence}"}

        # Parse data
        data_bytes = parse_hex_string(data)
        if isinstance(data_bytes, dict):
            return data_bytes

        client, cleanup = None, None
        try:
            client, cleanup = self._create_uds_client(resolved_tx_id, resolved_rx_id)

            start_time = time.time()

            logger.info(f"Transferring block {seq_int}: {len(data_bytes)} bytes")

            client.transfer_data(seq_int, data_bytes)

            elapsed_ms = (time.time() - start_time) * 1000

            return {
                "status": "success",
                "sequence": seq_int,
                "bytes_transferred": len(data_bytes),
                "elapsed_ms": round(elapsed_ms, 2),
            }

        except NegativeResponseException as e:
            nrc_name = e.response.code_name if hasattr(e.response, "code_name") else "Unknown"
            logger.error(f"Transfer data NRC: {nrc_name} (0x{e.response.code:02X})")
            return {"error": f"NRC: {nrc_name} (0x{e.response.code:02X})"}
        except TimeoutException:
            logger.error("Transfer data timeout")
            return {"error": "Timeout waiting for response"}
        except Exception as e:
            logger.error(f"Transfer data error: {e}")
            return {"error": str(e)}
        finally:
            if cleanup:
                self._cleanup_uds_client(cleanup)

    @action("Request Transfer Exit", "Finalize firmware transfer")
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
    def request_transfer_exit(self, tx_id: str = "", rx_id: str = "") -> dict[str, Any]:
        """Finalize transfer using RequestTransferExit service (0x37).

        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with status or error
        """
        if not self.running:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        client, cleanup = None, None
        try:
            client, cleanup = self._create_uds_client(resolved_tx_id, resolved_rx_id)

            start_time = time.time()

            logger.info("Requesting transfer exit")

            client.request_transfer_exit()

            elapsed_ms = (time.time() - start_time) * 1000

            logger.info("Transfer exit successful")

            return {
                "status": "success",
                "elapsed_ms": round(elapsed_ms, 2),
            }

        except NegativeResponseException as e:
            nrc_name = e.response.code_name if hasattr(e.response, "code_name") else "Unknown"
            logger.error(f"Transfer exit NRC: {nrc_name} (0x{e.response.code:02X})")
            return {"error": f"NRC: {nrc_name} (0x{e.response.code:02X})"}
        except TimeoutException:
            logger.error("Transfer exit timeout")
            return {"error": "Timeout waiting for response"}
        except Exception as e:
            logger.error(f"Transfer exit error: {e}")
            return {"error": str(e)}
        finally:
            if cleanup:
                self._cleanup_uds_client(cleanup)

    @action("Flash Firmware", "Flash firmware file to ECU")
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
    @action.text(
        "address",
        title="Memory Address (hex)",
        description="Target memory address (e.g., 0x08000000)",
        placeholder="0x08000000",
        default="0x00000000",
    )
    @action.text(
        "data",
        title="Firmware Data (hex bytes)",
        description="Firmware data as hex string",
        placeholder="00 11 22 33 44 55",
        default="",
    )
    @action.number(
        "block_size",
        minimum=8,
        maximum=4095,
        default=256,
        title="Block Size (bytes)",
        description="Transfer block size (0 = auto-negotiate)",
        widget="number",
    )
    @action.boolean(
        "change_session",
        title="Change to Programming Session",
        description="Switch to programming session before flash",
        default=True,
        widget="toggle",
    )
    def flash_firmware(
        self,
        tx_id: str = "",
        rx_id: str = "",
        address: str = "0x00000000",
        data: str = "",
        block_size: int = 256,
        change_session: bool = True,
    ) -> dict[str, Any]:
        """Flash firmware to ECU using stateless UDS transactions.

        Executes the full flash sequence:
        1. Change to programming session (optional)
        2. Request download
        3. Transfer data blocks
        4. Request transfer exit

        Note: For long transfers, start periodic tester present before flashing
        to prevent S3 timeout.

        :param address: Target memory address (hex string)
        :param data: Firmware data as hex string
        :param block_size: Block size for transfer (0 = auto-negotiate)
        :param change_session: Whether to change to programming session first
        :param tx_id: Optional TX ID (overrides global config)
        :param rx_id: Optional RX ID (overrides global config)
        :return: Response with flash status or error
        """
        if not self.running:
            return {"error": "UDS client not started"}

        # Resolve TX/RX IDs
        ids_result = self._resolve_tx_rx_ids(tx_id if tx_id else None, rx_id if rx_id else None)
        if isinstance(ids_result, dict):
            return ids_result
        resolved_tx_id, resolved_rx_id = ids_result

        # Parse address
        address_int = validate_hex_id(address, max_value=0xFFFFFFFF)
        if isinstance(address_int, dict):
            return {"error": f"Invalid address: {address_int['error']}"}

        # Parse firmware data
        if not data.strip():
            return {"error": "No firmware data provided"}

        firmware_bytes = parse_hex_string(data)
        if isinstance(firmware_bytes, dict):
            return {"error": f"Invalid firmware data: {firmware_bytes['error']}"}

        if len(firmware_bytes) == 0:
            return {"error": "Firmware data is empty"}

        logger.info(
            f"Starting flash: address=0x{address_int:08X}, "
            f"size={len(firmware_bytes)} bytes, block_size={block_size}"
        )

        start_time = time.time()

        # Step 1: Change session (optional)
        if change_session:
            result = self.diagnostic_session_control(
                session_type="Programming Session", tx_id=tx_id, rx_id=rx_id
            )
            if "error" in result:
                return {"error": f"Session change failed: {result['error']}"}
            logger.info("Changed to programming session")

        # Step 2: Request download
        client, cleanup = None, None
        try:
            client, cleanup = self._create_uds_client(resolved_tx_id, resolved_rx_id)

            from udsoncan.common.MemoryLocation import MemoryLocation

            location = MemoryLocation(
                address=address_int, memorysize=len(firmware_bytes), address_format=32
            )
            response = client.request_download(location)

            # Use server-provided block size if auto-negotiate
            max_block_size = (
                response.service_data.max_length
                if hasattr(response.service_data, "max_length")
                else block_size
            )
            if block_size == 0 or block_size > max_block_size:
                block_size = max_block_size

            logger.info(f"Download accepted. Using block size: {block_size}")

        except NegativeResponseException as e:
            nrc_name = e.response.code_name if hasattr(e.response, "code_name") else "Unknown"
            return {"error": f"Request download failed: NRC {nrc_name} (0x{e.response.code:02X})"}
        except TimeoutException:
            return {"error": "Request download timeout"}
        except Exception as e:
            return {"error": f"Request download failed: {e}"}
        finally:
            if cleanup:
                self._cleanup_uds_client(cleanup)

        # Step 3: Transfer data blocks
        total_blocks = (len(firmware_bytes) + block_size - 1) // block_size
        logger.info(f"Transferring {len(firmware_bytes)} bytes in {total_blocks} blocks")

        sequence = 1
        offset = 0
        blocks_transferred = 0

        while offset < len(firmware_bytes):
            block = firmware_bytes[offset : offset + block_size]

            client, cleanup = None, None
            try:
                client, cleanup = self._create_uds_client(resolved_tx_id, resolved_rx_id)
                client.transfer_data(sequence, block)
                blocks_transferred += 1

                if blocks_transferred % 10 == 0:
                    logger.info(f"Transferred {blocks_transferred}/{total_blocks} blocks")

            except NegativeResponseException as e:
                nrc_name = e.response.code_name if hasattr(e.response, "code_name") else "Unknown"
                return {
                    "error": f"Transfer failed at block {sequence}: "
                    f"NRC {nrc_name} (0x{e.response.code:02X})",
                    "blocks_transferred": blocks_transferred,
                }
            except TimeoutException:
                return {
                    "error": f"Transfer timeout at block {sequence}",
                    "blocks_transferred": blocks_transferred,
                }
            except Exception as e:
                return {
                    "error": f"Transfer failed at block {sequence}: {e}",
                    "blocks_transferred": blocks_transferred,
                }
            finally:
                if cleanup:
                    self._cleanup_uds_client(cleanup)

            sequence = (sequence + 1) % 256
            offset += block_size

        logger.info(f"All {total_blocks} blocks transferred")

        # Step 4: Request transfer exit
        client, cleanup = None, None
        try:
            client, cleanup = self._create_uds_client(resolved_tx_id, resolved_rx_id)
            client.request_transfer_exit()
            logger.info("Transfer exit successful")

        except NegativeResponseException as e:
            nrc_name = e.response.code_name if hasattr(e.response, "code_name") else "Unknown"
            return {
                "error": f"Transfer exit failed: NRC {nrc_name} (0x{e.response.code:02X})",
                "blocks_transferred": blocks_transferred,
            }
        except TimeoutException:
            return {"error": "Transfer exit timeout", "blocks_transferred": blocks_transferred}
        except Exception as e:
            return {"error": f"Transfer exit failed: {e}", "blocks_transferred": blocks_transferred}
        finally:
            if cleanup:
                self._cleanup_uds_client(cleanup)

        elapsed_ms = (time.time() - start_time) * 1000

        return {
            "status": "success",
            "address": f"0x{address_int:08X}",
            "size": len(firmware_bytes),
            "blocks": total_blocks,
            "block_size": block_size,
            "elapsed_ms": round(elapsed_ms, 2),
        }

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
