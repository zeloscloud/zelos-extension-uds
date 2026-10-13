"""DoIP entity simulator (ISO 13400-2) in front of the demo ECU, for tests and demos.

The bench DC-DC as a DoIP node, as its firmware is to be one: vehicle
identification on UDP, routing activation, alive check and diagnostic messages
on TCP, UDS into the demo ECU's server (`zelos_extension_uds.demo`). An ECU
reset closes every TCP connection, as the node's reboot does. Written from the
standard's tables, not with doipclient, so it checks the client's encoding.
Not a product feature.

    uv run python tests/doip_entity.py --host 127.0.0.1
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import math
import signal
import struct
import threading
import time

from zelos_extension_uds.demo import DemoEcu
from zelos_extension_uds.demo.ecu import CYCLE_S, PENDING_REPEAT_S

logger = logging.getLogger("doip-entity")

PORT = 13400
#: Logical addresses, as the hardware entity's: tester, the DC-DC, functional group.
TESTER, ECU, FUNCTIONAL = 0x0E80, 0x1001, 0xE400
#: EID (and GID): a fixed locally administered MAC, 02 then "ZELOS".
EID = bytes.fromhex("025a454c4f53")
#: Protocol versions taken (2010, 2012, 2019); 0xFF only in vehicle identification
#: requests. Replies carry 0x02.
VERSIONS, ANY_VERSION, VERSION = (0x01, 0x02, 0x03), 0xFF, 0x02
#: Routing activation types taken: default, central security.
ACTIVATION_TYPES = (0x00, 0xE0)
HEADER = struct.Struct("!BBHI")
#: Largest payload taken (generic header NACK 0x02 above).
MAX_PAYLOAD = 0x10000
#: T_TCP_Initial_Inactivity, T_TCP_General_Inactivity, T_TCP_Alive_Check.
INITIAL_INACTIVITY_S, GENERAL_INACTIVITY_S, ALIVE_CHECK_S = 2.0, 300.0, 0.5
TICK_S = 0.001

GENERIC_NACK = 0x0000
IDENTIFY, IDENTIFY_EID, IDENTIFY_VIN, IDENTIFICATION = 0x0001, 0x0002, 0x0003, 0x0004
ACTIVATE, ACTIVATION = 0x0005, 0x0006
ALIVE_CHECK, ALIVE_CHECK_RESPONSE = 0x0007, 0x0008
DIAGNOSTIC, DIAGNOSTIC_ACK, DIAGNOSTIC_NACK = 0x8001, 0x8002, 0x8003
#: Generic header NACK codes.
INCORRECT_PATTERN, UNKNOWN_TYPE, TOO_LARGE, INVALID_LENGTH = 0x00, 0x01, 0x02, 0x04
#: Routing activation response codes.
UNKNOWN_SOURCE, SOURCE_DIFFERS, SOURCE_ACTIVE, UNSUPPORTED_TYPE, ACTIVATED = (
    0x00, 0x02, 0x03, 0x06, 0x10,
)  # fmt: skip
#: Diagnostic message NACK codes.
INVALID_SOURCE, UNKNOWN_TARGET = 0x02, 0x03


def message(kind: int, payload: bytes) -> bytes:
    return HEADER.pack(VERSION, VERSION ^ 0xFF, kind, len(payload)) + payload


class DoipEntity:
    """A DoIP node on `host`: TCP `port` (0: a free one, read `port` after start), UDP
    `udp_port` for vehicle identification (None: none). Takes the `testers` addresses.

    `diagnostics` records ("in" or "out", user data length) per diagnostic message.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = PORT,
        udp_port: int | None = PORT,
        ecu: DemoEcu | None = None,
        testers: tuple[int, ...] = (TESTER,),
    ) -> None:
        self.host, self.port, self.udp_port = host, port, udp_port
        self.ecu = ecu or DemoEcu()
        self.testers = testers
        self.diagnostics: list[tuple[str, int]] = []
        #: Open connections and the tester address activated on each (None: not yet).
        self._sockets: dict[asyncio.StreamWriter, int | None] = {}
        self._alive: dict[asyncio.StreamWriter, asyncio.Event] = {}
        #: Who gets the ECU's own responses (pending, then the routine's result).
        self._reply_to: tuple[asyncio.StreamWriter, int] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop: asyncio.Event | None = None
        self._ready = threading.Event()
        self._error: BaseException | None = None
        self._thread: threading.Thread | None = None

    # ─── Lifecycle ─────────────────────────────────────────────────────────

    def start(self) -> DoipEntity:
        self._thread = threading.Thread(target=self._run, name="doip-entity", daemon=True)
        self._thread.start()
        self._ready.wait(5.0)
        if self._error is not None:
            raise self._error
        return self

    def stop(self) -> None:
        if self._loop is not None and self._stop is not None:
            self._loop.call_soon_threadsafe(self._stop.set)
        if self._thread is not None:
            self._thread.join(5.0)

    def _run(self) -> None:
        try:
            asyncio.run(self._main())
        except BaseException as e:
            self._error = e
            self._ready.set()

    async def _main(self) -> None:
        self._loop, self._stop = asyncio.get_running_loop(), asyncio.Event()
        server = await asyncio.start_server(self._serve, self.host, self.port)
        self.port = server.sockets[0].getsockname()[1]
        udp = None
        if self.udp_port is not None:
            udp, _ = await self._loop.create_datagram_endpoint(
                lambda: _Identification(self), local_addr=(self.host, self.udp_port)
            )
        ticker = asyncio.create_task(self._tick())
        logger.info(
            "DoIP entity on %s TCP %d UDP %s: ECU 0x%04X, tester 0x%04X, VIN %s",
            self.host, self.port, self.udp_port, ECU, self.testers[0], self.ecu.vin.decode(),
        )  # fmt: skip
        self._ready.set()
        await self._stop.wait()
        ticker.cancel()
        server.close()
        for writer in list(self._sockets):
            writer.close()
        if udp is not None:
            udp.close()

    async def _tick(self) -> None:
        """The demo ECU's clock: pending responses, S3, the model every CYCLE_S. A pending
        routine answers on time, as a real-time server does: the last tick before it spins."""
        next_cycle = time.monotonic()
        while True:
            await asyncio.sleep(TICK_S)
            due = self._due()
            if due - time.monotonic() < 2 * TICK_S:
                while time.monotonic() < due:
                    pass
            with self.ecu.lock:
                response = self.ecu.tick()
                if time.monotonic() >= next_cycle:
                    next_cycle += CYCLE_S
                    self.ecu.sample()
            if response and self._reply_to is not None:
                self._diagnostic(*self._reply_to, response)

    def _due(self) -> float:
        """When the ECU's pending routine answers next (0x78 or its result), else inf."""
        if self.ecu.pending is None:
            return math.inf
        _, done_at, sent_at = self.ecu.pending
        return min(done_at, sent_at + PENDING_REPEAT_S)

    # ─── TCP ───────────────────────────────────────────────────────────────

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._sockets[writer] = None
        try:
            while not writer.is_closing():
                activated = self._sockets.get(writer) is not None
                timeout = GENERAL_INACTIVITY_S if activated else INITIAL_INACTIVITY_S
                header = await asyncio.wait_for(reader.readexactly(HEADER.size), timeout)
                version, inverse, kind, length = HEADER.unpack(header)
                if version not in VERSIONS or version ^ inverse != 0xFF:
                    self._send(writer, GENERIC_NACK, bytes([INCORRECT_PATTERN]))
                    break
                if length > MAX_PAYLOAD:
                    self._send(writer, GENERIC_NACK, bytes([TOO_LARGE]))
                    break
                payload = await reader.readexactly(length)
                if not await self._handle(writer, kind, payload):
                    break
                await writer.drain()
        except (asyncio.IncompleteReadError, TimeoutError, ConnectionError):
            pass
        finally:
            self._sockets.pop(writer, None)
            writer.close()

    async def _handle(self, writer: asyncio.StreamWriter, kind: int, payload: bytes) -> bool:
        """One message; False closes the connection."""
        lengths = {ACTIVATE: (7, 11), ALIVE_CHECK: (0,), ALIVE_CHECK_RESPONSE: (2,)}
        if (
            kind in lengths
            and len(payload) not in lengths[kind]
            or (kind == DIAGNOSTIC and len(payload) < 5)
        ):
            self._send(writer, GENERIC_NACK, bytes([INVALID_LENGTH]))
            return False
        if kind == ACTIVATE:
            return await self._activate(writer, payload)
        if kind == ALIVE_CHECK:  # a tester checking on us
            self._send(writer, ALIVE_CHECK_RESPONSE, struct.pack("!H", ECU))
        elif kind == ALIVE_CHECK_RESPONSE:
            if writer in self._alive:
                self._alive[writer].set()
        elif kind == DIAGNOSTIC:
            return self._diagnose(writer, payload)
        else:
            self._send(writer, GENERIC_NACK, bytes([UNKNOWN_TYPE]))
        return True

    async def _activate(self, writer: asyncio.StreamWriter, payload: bytes) -> bool:
        source, kind = struct.unpack_from("!HB", payload)
        code = await self._activation(writer, source, kind)
        self._send(writer, ACTIVATION, struct.pack("!HHBI", source, ECU, code, 0))
        if code != ACTIVATED:
            logger.info("routing activation refused: tester 0x%04X code 0x%02X", source, code)
            return False
        logger.info("routing activated: tester 0x%04X type 0x%02X", source, kind)
        self._sockets[writer] = source
        return True

    async def _activation(self, writer: asyncio.StreamWriter, source: int, kind: int) -> int:
        if source not in self.testers:
            return UNKNOWN_SOURCE
        if kind not in ACTIVATION_TYPES:
            return UNSUPPORTED_TYPE
        if self._sockets.get(writer) not in (None, source):
            return SOURCE_DIFFERS
        other = next((w for w, s in self._sockets.items() if s == source and w is not writer), None)
        if other is not None:
            if await self._alive_check(other):
                return SOURCE_ACTIVE
            self._sockets.pop(other, None)  # silent: the tester is gone
            other.close()
        return ACTIVATED

    async def _alive_check(self, writer: asyncio.StreamWriter) -> bool:
        answered = self._alive[writer] = asyncio.Event()
        self._send(writer, ALIVE_CHECK, b"")
        try:
            await asyncio.wait_for(answered.wait(), ALIVE_CHECK_S)
            return True
        except TimeoutError:
            return False
        finally:
            self._alive.pop(writer, None)

    def _diagnose(self, writer: asyncio.StreamWriter, payload: bytes) -> bool:
        source, target = struct.unpack_from("!HH", payload)
        data = payload[4:]
        if self._sockets.get(writer) != source:  # not activated, or another tester
            self._send(writer, DIAGNOSTIC_NACK, struct.pack("!HHB", target, source, INVALID_SOURCE))
            return False
        if target not in (ECU, FUNCTIONAL):
            self._send(writer, DIAGNOSTIC_NACK, struct.pack("!HHB", target, source, UNKNOWN_TARGET))
            return True
        self._send(writer, DIAGNOSTIC_ACK, struct.pack("!HHB", target, source, 0x00))
        self.diagnostics.append(("in", len(data)))
        with self.ecu.lock:
            response = self.ecu.request(data, functional=target == FUNCTIONAL)
        self._reply_to = (writer, source)
        if response:
            self._diagnostic(writer, source, response)
        if data[0] == 0x11 and (response is None or response[0] == 0x51):
            logger.info("ECU reset: closing every connection, as the node's reboot does")
            for other in list(self._sockets):
                other.close()
            return False
        return True

    def _diagnostic(self, writer: asyncio.StreamWriter, tester: int, data: bytes) -> None:
        self.diagnostics.append(("out", len(data)))
        self._send(writer, DIAGNOSTIC, struct.pack("!HH", ECU, tester) + data)

    @staticmethod
    def _send(writer: asyncio.StreamWriter, kind: int, payload: bytes) -> None:
        if not writer.is_closing():
            writer.write(message(kind, payload))

    # ─── UDP ───────────────────────────────────────────────────────────────

    def identification(self, data: bytes) -> bytes | None:
        """The answer to a datagram: a vehicle identification response, a NACK or none."""
        if len(data) < HEADER.size:
            return None
        version, inverse, kind, length = HEADER.unpack_from(data)
        payload = data[HEADER.size :]
        if version not in (*VERSIONS, ANY_VERSION) or version ^ inverse != 0xFF:
            return message(GENERIC_NACK, bytes([INCORRECT_PATTERN]))
        expected = {IDENTIFY: 0, IDENTIFY_EID: 6, IDENTIFY_VIN: 17}
        if kind not in expected:
            return message(GENERIC_NACK, bytes([UNKNOWN_TYPE]))
        if length != expected[kind] or len(payload) != length:
            return message(GENERIC_NACK, bytes([INVALID_LENGTH]))
        vin = bytes(self.ecu.vin)  # DID F190, as the node's
        if kind == IDENTIFY_EID and payload != EID or kind == IDENTIFY_VIN and payload != vin:
            return None  # not us
        # GID = EID (no group), no further action, no sync status.
        return message(IDENTIFICATION, vin + struct.pack("!H", ECU) + EID + EID + b"\x00")


class _Identification(asyncio.DatagramProtocol):
    def __init__(self, entity: DoipEntity) -> None:
        self.entity = entity
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        reply = self.entity.identification(data)
        if reply is not None and self.transport is not None:
            self.transport.sendto(reply, addr)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--host", default="127.0.0.1", help="address to listen on")
    parser.add_argument("--port", type=int, default=PORT, help="TCP port")
    parser.add_argument("--udp-port", type=int, default=PORT, help="UDP port; 0: none")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    entity = DoipEntity(args.host, args.port, args.udp_port or None).start()
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    with contextlib.suppress(KeyboardInterrupt):
        while not stop.wait(0.5):
            pass
    entity.stop()


if __name__ == "__main__":
    main()
