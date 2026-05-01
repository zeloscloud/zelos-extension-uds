"""In-process demo UDS server for testing and the ``demo`` CAN interface.

Implements a minimal ECU on a python-can virtual bus so that the same
process can drive both the UDS client (agent actions, CLI subcommands)
and a fake server. Used by integration tests and by ``UDSClient`` when
the configured CAN interface is ``demo``.
"""

from __future__ import annotations

import contextlib
import logging
import threading
import time

import can
import isotp
from udsoncan.connections import PythonIsoTpConnection

logger = logging.getLogger(__name__)

# Default seed bytes returned for SecurityAccess request_seed.
_DEFAULT_SEED = b"\xde\xad\xbe\xef"


class DemoUDSServer:
    """Demo UDS server that responds to requests on a virtual CAN bus.

    Handles the common services exercised by the extension's actions and
    CLI commands: ReadDataByIdentifier (0x22), WriteDataByIdentifier (0x2E),
    DiagnosticSessionControl (0x10), TesterPresent (0x3E), ECUReset (0x11),
    RoutineControl (0x31), InputOutputControlByIdentifier (0x2F),
    SecurityAccess (0x27), ClearDiagnosticInformation (0x14).
    """

    def __init__(
        self,
        channel: str,
        tx_id: int,
        rx_id: int,
        interface: str = "virtual",
        data_store: dict[int, bytes] | None = None,
    ) -> None:
        """Initialize demo UDS server.

        :param channel: CAN channel name
        :param tx_id: Server TX address (client RX) — ECU response ID
        :param rx_id: Server RX address (client TX) — tester request ID
        :param interface: python-can interface (default: virtual)
        :param data_store: Initial DID -> bytes map; defaults to demo entries
        """
        self.channel = channel
        self.tx_id = tx_id
        self.rx_id = rx_id
        self.interface = interface
        self.bus: can.Bus | None = None
        self.notifier: can.Notifier | None = None
        self.isotp_stack: isotp.NotifierBasedCanStack | None = None
        self.connection: PythonIsoTpConnection | None = None
        self.server_thread: threading.Thread | None = None
        self.running = False
        self.data_store: dict[int, bytes] = (
            data_store
            if data_store is not None
            else {
                0xF190: b"DEMOVIN123456789",
                0xF191: b"DEMOPART12345",
                0x0100: b"\x00\x00\x00\x00",
            }
        )
        # Latest WriteDataByIdentifier write — useful for tests to assert
        # the bytes that hit the wire after typed-payload encoding.
        self.last_write: tuple[int, bytes] | None = None
        # Latest IO control / routine control payloads.
        self.last_routine_data: bytes | None = None
        self.last_io_payload: bytes | None = None

    def start(self) -> None:
        """Start the demo UDS server."""
        logger.info(
            "Demo UDS server starting on %s/%s (TX=0x%03X, RX=0x%03X)",
            self.interface,
            self.channel,
            self.tx_id,
            self.rx_id,
        )

        self.bus = can.Bus(interface=self.interface, channel=self.channel)
        tp_addr = isotp.Address(
            isotp.AddressingMode.Normal_11bits, txid=self.tx_id, rxid=self.rx_id
        )
        self.notifier = can.Notifier(self.bus, [])
        self.isotp_stack = isotp.NotifierBasedCanStack(
            bus=self.bus, notifier=self.notifier, address=tp_addr
        )
        self.connection = PythonIsoTpConnection(self.isotp_stack)
        self.connection.open()

        self.running = True
        self.server_thread = threading.Thread(
            target=self._run_server, name="demo-uds-server", daemon=True
        )
        self.server_thread.start()
        # Brief settle so first request after start() doesn't race.
        time.sleep(0.1)

    def stop(self) -> None:
        """Stop the demo UDS server and tear down the bus."""
        self.running = False

        if self.server_thread:
            self.server_thread.join(timeout=1.0)

        if self.connection:
            with contextlib.suppress(Exception):
                self.connection.close()
        if self.isotp_stack:
            with contextlib.suppress(Exception):
                self.isotp_stack.stop()
        if self.notifier:
            with contextlib.suppress(Exception):
                self.notifier.stop()
        if self.bus:
            with contextlib.suppress(Exception):
                self.bus.shutdown()

    def __enter__(self) -> DemoUDSServer:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    # ---- internal ----

    def _run_server(self) -> None:
        while self.running:
            try:
                request = self.connection.wait_frame(timeout=0.1) if self.connection else None
                if not request:
                    continue
                response = self._process_request(request)
                if response and self.connection:
                    self.connection.send(response)
            except TimeoutError:
                continue
            except Exception as e:
                # Brief sleep avoids a tight error loop if the connection
                # raises consistently (e.g. closed mid-stop).
                logger.warning("Demo server error: %s", e)
                time.sleep(0.01)

    def _process_request(self, request: bytes) -> bytes | None:
        if not request:
            return None
        sid = request[0]
        if sid == 0x22:
            return self._handle_read_did(request)
        if sid == 0x2E:
            return self._handle_write_did(request)
        if sid == 0x10:
            return self._handle_session_control(request)
        if sid == 0x3E:
            return self._handle_tester_present(request)
        if sid == 0x11:
            return self._handle_ecu_reset(request)
        if sid == 0x31:
            return self._handle_routine_control(request)
        if sid == 0x2F:
            return self._handle_io_control(request)
        if sid == 0x27:
            return self._handle_security_access(request)
        if sid == 0x14:
            return self._handle_clear_dtc(request)
        # serviceNotSupported
        return bytes([0x7F, sid, 0x11])

    def _handle_read_did(self, req: bytes) -> bytes:
        if len(req) < 3:
            return bytes([0x7F, 0x22, 0x13])
        did = (req[1] << 8) | req[2]
        if did in self.data_store:
            return bytes([0x62, req[1], req[2]]) + self.data_store[did]
        return bytes([0x7F, 0x22, 0x31])  # requestOutOfRange

    def _handle_write_did(self, req: bytes) -> bytes:
        if len(req) < 4:
            return bytes([0x7F, 0x2E, 0x13])
        did = (req[1] << 8) | req[2]
        data = req[3:]
        self.data_store[did] = data
        self.last_write = (did, data)
        return bytes([0x6E, req[1], req[2]])

    def _handle_session_control(self, req: bytes) -> bytes:
        if len(req) < 2:
            return bytes([0x7F, 0x10, 0x13])
        return bytes([0x50, req[1], 0x00, 0x32, 0x01, 0xF4])

    def _handle_tester_present(self, req: bytes) -> bytes:
        suppress = len(req) > 1 and (req[1] & 0x80)
        if suppress:
            return b""
        return bytes([0x7E, 0x00])

    def _handle_ecu_reset(self, req: bytes) -> bytes:
        if len(req) < 2:
            return bytes([0x7F, 0x11, 0x13])
        return bytes([0x51, req[1]])

    def _handle_routine_control(self, req: bytes) -> bytes:
        if len(req) < 4:
            return bytes([0x7F, 0x31, 0x13])
        control_type = req[1]
        # Capture optional routine data (after 2-byte routine id)
        self.last_routine_data = bytes(req[4:])
        return bytes([0x71, control_type, req[2], req[3]])

    def _handle_io_control(self, req: bytes) -> bytes:
        if len(req) < 4:
            return bytes([0x7F, 0x2F, 0x13])
        control_param = req[3]
        # Capture optional control option record (after control param byte)
        self.last_io_payload = bytes(req[4:])
        return bytes([0x6F, req[1], req[2], control_param])

    def _handle_security_access(self, req: bytes) -> bytes:
        if len(req) < 2:
            return bytes([0x7F, 0x27, 0x13])
        sub = req[1]
        # Odd = request seed, even = send key
        if sub % 2 == 1:
            return bytes([0x67, sub]) + _DEFAULT_SEED
        return bytes([0x67, sub])

    def _handle_clear_dtc(self, req: bytes) -> bytes:
        if len(req) < 4:
            return bytes([0x7F, 0x14, 0x13])
        return bytes([0x54])
