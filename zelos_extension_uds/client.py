"""ECU lifecycle: one persistent bus per (interface, channel), one ISO-TP stack per ECU;
or one DoIP connection per ECU.

`SharedBus` owns a bus, its `can.Notifier` and one worker thread that opens
the bus, attaches every ECU's ISO-TP stack, watches for failure and reopens
with backoff. A stack hears its ECU only while a request is outstanding: an idle
ECU sends nothing, no flow control to another tester's transfer. `DoipLink` is
the same worker for one ECU's DoIP connection.
`UdsEcu` serializes requests on its address pair: udsoncan is not safe for
concurrent use of one connection.
"""

from __future__ import annotations

import binascii
import contextlib
import copy
import logging
import math
import struct
import threading
import time
from collections.abc import Callable, Iterator
from enum import StrEnum
from typing import Any

import can
import isotp
import udsoncan
import zelos_sdk
from udsoncan import DidCodec
from udsoncan.client import Client
from udsoncan.connections import PythonIsoTpConnection
from udsoncan.exceptions import NegativeResponseException, TimeoutException
from zelos_can import doip
from zelos_can import isotp as uds_link

from zelos_extension_uds.constants import INTERFACES, Interface, trace_layout
from zelos_extension_uds.trace import Trace, service_name

logger = logging.getLogger(__name__)

#: Reopen backoff: doubles per failed attempt up to the cap; a bus that stayed
#: up for HEALTHY seconds starts over.
RECONNECT_INITIAL = 3.0
RECONNECT_MAX = 60.0
HEALTHY = 10.0

#: Stopping every ECU and bus completes within this.
STOP_BOUND = 3.0

#: How often a wait on a response in reassembly checks it is still in progress.
RX_POLL = 0.05

#: Bus health check period; notifier receive timeout (bounds its stop).
HEALTH_TICK = 0.25
NOTIFIER_TIMEOUT = 0.1

SID_TESTER_PRESENT = 0x3E
SID_ECU_RESET = 0x11

#: An entity closing the connection this soon after an ECU reset is the reset, not a fault.
RESET_CLOSE_S = 5.0

#: Longest a request waits for its ECU's lock: shorter than an action's 30 s timeout, so a
#: request queued behind a long one (a flash) fails instead of being sent after its caller
#: gave up. Periodic tester present waits TP_LOCK_TIMEOUT and skips the beat.
LOCK_TIMEOUT = 20.0
TP_LOCK_TIMEOUT = 0.1


class State(StrEnum):
    STOPPED = "stopped"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


class Unavailable(Exception):
    """The ECU's bus is down; the reason is the message."""


class HexDidCodec(DidCodec):
    """Raw DID bytes, no pre-defined structure; byte order preserved."""

    @staticmethod
    def to_bytes(data: Any) -> bytes:
        if isinstance(data, bytes | bytearray):
            return bytes(data)
        if isinstance(data, str):
            try:
                return binascii.unhexlify(data.removeprefix("0x"))
            except binascii.Error:
                return data.encode("ascii")
        if isinstance(data, list):
            return b"".join(HexDidCodec.to_bytes(v) for v in data)
        if isinstance(data, float):
            return struct.pack(">f", data)
        return data.to_bytes(max(1, math.ceil(data.bit_length() / 8)), "big")

    def encode(self, data: Any) -> bytes:
        return self.to_bytes(data)

    def decode(self, did_payload: bytes) -> bytes:
        return did_payload

    def __len__(self) -> int:
        raise DidCodec.ReadAllRemainingData


def client_config(advanced: dict[str, Any]) -> dict[str, Any]:
    config = copy.deepcopy(udsoncan.configs.default_client_config)
    config.update(
        data_identifiers={"default": HexDidCodec},
        input_output={"default": {"codec": HexDidCodec}},
        request_timeout=float(advanced["request_timeout"]),
        p2_timeout=float(advanced["p2_timeout"]),
        p2_star_timeout=float(advanced["p2_star_timeout"]),
        # Server-reported P2 (often 50 ms) leaves no margin for the network:
        # the configured timeouts apply.
        use_server_timing=False,
    )
    return config


def _describe(e: BaseException) -> str:
    return f"{type(e).__name__}: {e}" if str(e) else type(e).__name__


class _Connection(PythonIsoTpConnection):
    """udsoncan's connection, with two changes.

    `on_send` gets the payload once a request is sent (blocking send: every frame
    out): arguments udsoncan refuses and failed sends never reach it.

    P2 (P2* after 0x78) bounds the start of a response, as ISO 14229-2 has it, not
    its end: udsoncan waits P2 for the whole message, so a long multi-frame
    response (an upload block over a slow link) timed out mid-reassembly. A wait
    that times out while the stack is receiving continues until the message is
    complete, bounded by can-isotp's consecutive-frame timeout (N_Cr) and by
    `request_timeout` from the send.
    """

    def __init__(
        self, stack: isotp.TransportLayer, on_send: Callable[[bytes], None], request_timeout: float
    ) -> None:
        super().__init__(stack)
        self.on_send, self.stack, self.request_timeout = on_send, stack, request_timeout
        self._sent_at = 0.0

    def send(self, data: Any, timeout: float | None = None) -> None:
        payload = bytes(data.get_payload() if hasattr(data, "get_payload") else data)
        self._sent_at = time.monotonic()
        super().send(data, timeout)
        self.on_send(payload)

    def specific_wait_frame(self, timeout: float | None = None) -> bytes | None:
        try:
            return super().specific_wait_frame(timeout)
        except TimeoutException:
            deadline = self._sent_at + self.request_timeout
            # Its first frame came within P2: the rest follows at the sender's pace.
            while self.stack.is_rx_active() and time.monotonic() < deadline:
                frame = self.stack.recv(block=True, timeout=RX_POLL)
                if frame is not None:
                    return bytes(frame)
            frame = self.stack.recv(block=False)  # completed just as the wait ended
            if frame is None:
                raise
            return bytes(frame)


class _ErrorListener(can.Listener):
    """Turns a receive error in the notifier thread into a bus failure."""

    def __init__(self, shared: SharedBus) -> None:
        self.shared = shared

    def on_message_received(self, msg: can.Message) -> None:
        pass

    def on_error(self, exc: Exception) -> None:
        self.shared.fail(f"CAN receive failed: {_describe(exc)}")


class SharedBus:
    """One bus and one notifier for every ECU on one (interface, channel)."""

    def __init__(self, link: dict[str, Any], name: str) -> None:
        self.link, self.name = link, name
        self.ecus: list[UdsEcu] = []
        self.bus: can.BusABC | None = None
        self.notifier: can.Notifier | None = None
        self.reopens = 0
        self._reason = ""
        self._stop = threading.Event()
        self._failed = threading.Event()
        self._thread: threading.Thread | None = None

    def add(self, ecu: UdsEcu) -> None:
        self.ecus.append(ecu)
        ecu.shared = self

    def start(self) -> None:
        for ecu in self.ecus:
            ecu.state = State.CONNECTING
        self._thread = threading.Thread(target=self._run, name=f"uds-bus-{self.name}", daemon=True)
        self._thread.start()

    def fail(self, reason: str) -> None:
        """Mark the bus failed; the worker closes and reopens it."""
        if not self._failed.is_set():
            self._reason = reason
            self._failed.set()

    def stop(self) -> None:
        """Ask the worker to close the bus. Returns at once; `join` waits."""
        self._stop.set()
        self._failed.set()

    def join(self, timeout: float) -> bool:
        if self._thread is not None:
            self._thread.join(timeout)
            return not self._thread.is_alive()
        return True

    def _run(self) -> None:
        backoff = RECONNECT_INITIAL
        while not self._stop.is_set():
            self._failed.clear()
            self._reason = ""
            opened = time.monotonic()
            permanent = False
            try:
                self._open()
            except Exception as e:
                reason, permanent = self._open_error(e)
                self.fail(reason)
            while not self._stop.is_set() and not self._failed.wait(HEALTH_TICK):
                reason = self._health()
                if reason:
                    self.fail(reason)
            reason = "" if self._stop.is_set() else self._reason
            self._close(reason)
            if self._stop.is_set():
                break
            if permanent:
                logger.error("[%s] not retried: %s", self.name, reason)
                break
            if time.monotonic() - opened >= HEALTHY:
                backoff = RECONNECT_INITIAL
            logger.warning("[%s] %s; reopening in %gs", self.name, reason, backoff)
            self._stop.wait(backoff)
            backoff = min(backoff * 2, RECONNECT_MAX)
            self.reopens += 1

    def _open_error(self, e: Exception) -> tuple[str, bool]:
        """Why opening failed, and whether no retry fixes it."""
        reason = f"cannot open {uds_link.bus_text(self.link)}: {_describe(e)}"
        return reason, uds_link.permanent(e, self.link)

    def _health(self) -> str | None:
        """Why the open bus is unusable, or None; every HEALTH_TICK."""
        dead = next((e for e in self.ecus if not e.stack_alive()), None)
        return None if dead is None else f"ISO-TP stack of {dead.name} stopped (CAN send failed?)"

    def _open(self) -> None:
        self.bus = uds_link.open_bus(self.link, self.name)
        self.notifier = can.Notifier(self.bus, [_ErrorListener(self)], timeout=NOTIFIER_TIMEOUT)
        for ecu in self.ecus:
            ecu._attach(self.bus, self.notifier)

    def _close(self, reason: str) -> None:
        """Explicit order: ISO-TP stacks, notifier, bus."""
        for ecu in self.ecus:
            ecu._detach(reason)
        notifier, self.notifier = self.notifier, None
        if notifier is not None:
            try:
                notifier.stop(timeout=1.0)
            except Exception as e:
                logger.debug("[%s] notifier stop: %s", self.name, e)
        bus, self.bus = self.bus, None
        if bus is not None:
            try:
                bus.shutdown()
            except Exception as e:
                logger.debug("[%s] bus shutdown: %s", self.name, e)


class DoipLink(SharedBus):
    """One ECU's DoIP connection, run like a bus: identify the entity (Discover),
    connect, activate routing; while idle, answer alive checks and watch for the entity
    closing; reconnect with the bus's backoff."""

    def __init__(self, ecu: UdsEcu) -> None:
        super().__init__({}, ecu.name)  # its endpoint is known only once identified
        self.add(ecu)
        self.ecu = ecu
        self.client: doip.Client | None = None
        self.connection: doip.Connection | None = None

    def _open(self) -> None:
        cfg = self.ecu.doip
        if cfg.discover:
            self.ecu.vehicle = None  # an answer from an earlier connection is stale
            self.ecu.vehicle = doip.identify(cfg.host)
            logger.info("[%s] DoIP entity %s", self.ecu.name, self.ecu.vehicle.as_dict())
        self.client, self.ecu.ecu_address = doip.connect(cfg, self.ecu.vehicle)
        self.connection = doip.Connection(
            self.client, cfg.tester, self.ecu.ecu_address, cfg.timeout, self.ecu._sent, self.fail
        )
        self.ecu._open_client(self.connection)

    def _open_error(self, e: Exception) -> tuple[str, bool]:
        text = str(e) if isinstance(e, doip.Refused | doip.DoipError) else _describe(e)
        permanent = isinstance(e, doip.Refused) and e.permanent
        return f"cannot connect to DoIP {self.ecu.doip.peer}: {text}", permanent

    def _health(self) -> str | None:
        connection = self.connection
        if connection is None or not self.ecu.lock.acquire(blocking=False):
            return None  # a request in progress sees a closed connection itself
        try:
            connection.empty_rxqueue()
        except doip.Lost as e:
            return str(e)
        except Exception as e:
            return f"DoIP connection lost: {_describe(e)}"
        finally:
            self.ecu.lock.release()
        return None

    def _close(self, reason: str) -> None:
        """Explicit order: udsoncan client, DoIP connection."""
        if reason == doip.CLOSED and time.monotonic() - self.ecu.reset_at < RESET_CLOSE_S:
            logger.info("[%s] the entity closed the connection after the ECU reset", self.name)
            reason = ""
        self.ecu._detach(reason)
        if not reason and not self._stop.is_set():
            self.ecu.state = State.CONNECTING
        self.connection = None
        client, self.client = self.client, None
        if client is not None:
            client.close()


class UdsEcu:
    """One ECU: an address pair on a shared bus, its udsoncan client and periodic TP."""

    def __init__(
        self, name: str, interface: Interface, link: dict[str, Any], advanced: dict[str, Any]
    ) -> None:
        self.name, self.interface = name, interface
        self.label = next(k for k, v in INTERFACES.items() if v == interface)
        #: `key(level, seed) -> key` from the ECU's key file, or None.
        self.key_fn: Callable[[int, bytes], bytes] | None = None
        link = dict(link)
        #: DoIP: the settings, the identified entity (Discover) and the ECU's logical address.
        self.doip: doip.Config | None = None
        self.vehicle: doip.Vehicle | None = None
        self.ecu_address: int | None = None
        if interface == Interface.DOIP:
            self.doip = doip.config(link)  # ValueError
            self.ecu_address = self.doip.ecu
        elif interface == Interface.DEMO:
            from zelos_extension_uds.demo.ecu import REQUEST_ID, RESPONSE_ID

            link.setdefault("tx_id", hex(REQUEST_ID))
            link.setdefault("rx_id", hex(RESPONSE_ID))
            link.update(interface="zelos-virtual", channel=f"uds-demo-{name}-{id(self):x}")
        else:
            link["interface"] = str(interface)
        self.link = link
        if self.doip is None:
            self.bus_link = uds_link.bus_link(link)
            self.tx_id, self.rx_id, self.extended = uds_link.ids(link)  # ValueError
        self.fd = bool(link.get("fd_mode"))
        self.advanced = advanced
        self.shared: SharedBus | None = None
        self.trace: Trace | None = None
        self.state = State.STOPPED
        self.last_error = ""
        #: Held around each request/response; reentrant so a sequence (flash) can hold it.
        self.lock = threading.RLock()
        self._op: str | None = None  # what holds `lock`, for the busy message
        self._sending: tuple[int, int] | None = None
        self.counts = dict.fromkeys(
            ("requests", "responses", "positive", "negative", "timeouts", "errors"), 0
        )
        self.tp_period: float | None = None
        self._tp_stop = threading.Event()
        self._tp_thread: threading.Thread | None = None
        #: Serializes start/stop of periodic TP; set once stopping, so none starts after.
        self._tp_lock = threading.Lock()
        self._tp_closed = False
        self._stack: uds_link.QuietStack | None = None
        self._client: Client | None = None
        self.demo = None
        self.reset_at = -math.inf  # last ECUReset sent and not refused

    @property
    def endpoint(self) -> str:
        if self.doip is not None:
            host = self.doip.host or (self.vehicle.ip if self.vehicle else "broadcast")
            ecu = "discover" if self.ecu_address is None else f"0x{self.ecu_address:04X}"
            return f"doip://{host}:{self.doip.port} 0x{self.doip.tester:04X}/{ecu}"
        ids = f"{uds_link.id_text(self.tx_id, self.extended)}/"
        ids += uds_link.id_text(self.rx_id, self.extended)
        if self.interface == Interface.DEMO:
            return f"demo {ids}"
        return f"{uds_link.bus_text(self.bus_link)} {ids}"

    # ─── Lifecycle ─────────────────────────────────────────────────────────

    def trace_to(self, prefix: str, source: zelos_sdk.TraceSource | None = None) -> None:
        """Declare `tx`/`rx` (see `trace_layout`); `source` is the shared one with a prefix."""
        source_name, event_prefix = trace_layout(prefix, self.name)
        self.trace = Trace(source or zelos_sdk.TraceSource(source_name), event_prefix)

    def start_demo(self) -> None:
        """Start the in-process demo ECU on this ECU's virtual channel."""
        if self.interface != Interface.DEMO:
            return
        from zelos_extension_uds.demo.ecu import DemoEcu

        self.demo = DemoEcu(
            channel=self.link["channel"],
            fd=self.fd,
            request_id=self.tx_id,
            response_id=self.rx_id,
            extended=self.extended,
        )
        self.demo.start()

    def stop_demo(self) -> None:
        demo, self.demo = self.demo, None
        if demo is not None:
            demo.stop()

    def _attach(self, bus: can.BusABC, notifier: can.Notifier) -> None:
        """Called by the bus worker once the bus is open."""
        stack = uds_link.QuietStack(
            bus=bus,
            notifier=notifier,
            address=uds_link.address(self.tx_id, self.rx_id, self.extended),
            params=uds_link.isotp_params(self.advanced, self.fd),
        )
        connection = _Connection(stack, self._sent, float(self.advanced["request_timeout"]))
        self._open_client(connection)
        self._stack = stack

    def _open_client(self, connection: Any) -> None:
        """udsoncan's client on `connection`: the ECU is connected."""
        client = Client(connection, config=client_config(self.advanced))
        client.open()
        self._client = client
        self.state, self.last_error = State.CONNECTED, ""
        logger.info("[%s] connected (%s)", self.name, self.endpoint)

    def _detach(self, reason: str) -> None:
        """Called by the bus worker before the bus closes. Does not wait for `lock`."""
        client, self._client, self._stack = self._client, None, None
        if client is not None:
            try:
                client.close()
            except Exception as e:
                logger.debug("[%s] ISO-TP stop: %s", self.name, e)
        if reason:
            self.state, self.last_error = State.ERROR, reason
            self.counts["errors"] += 1
            logger.error("[%s] %s", self.name, reason)
        else:
            self.state = State.STOPPED

    def stack_alive(self) -> bool:
        stack = self._stack
        return stack is None or (stack.main_thread is not None and stack.main_thread.is_alive())

    # ─── Requests ──────────────────────────────────────────────────────────

    @contextlib.contextmanager
    def busy(self, op: str, timeout: float | None = None) -> Iterator[None]:
        """Hold the ECU for `op`; Unavailable when another holds it longer than `timeout`
        (LOCK_TIMEOUT when None)."""
        if not self.lock.acquire(timeout=LOCK_TIMEOUT if timeout is None else timeout):
            raise Unavailable(f"busy: {self._op or 'a request'} in progress")
        outer = self._op
        self._op = outer or op
        try:
            yield
        finally:
            self._op = outer
            self.lock.release()

    def _sent(self, payload: bytes) -> None:
        """A request was sent: count it, trace it with everything after the SID."""
        sending, self._sending = self._sending, None
        if sending is not None:
            self.counts["requests"] += 1
            if self.trace:
                self.trace.tx(*sending, payload[1:])

    def request(
        self,
        sid: int,
        parameter: int,
        call: Callable[[Client], Any],
        lock_timeout: float | None = None,
    ) -> tuple[Any, float]:
        """Run `call` on the client under the lock: (response or None, elapsed s).

        Raises Unavailable while the bus is down or the ECU is busy, else what udsoncan
        raises. `tx` is traced only once the request is sent; `parameter` is the identifier
        the request addresses (see the README's trace table), traced beside the raw bytes.
        """
        with self.busy(service_name(sid), lock_timeout):
            client = self._client
            if client is None:
                raise Unavailable(self.last_error or f"ECU {self.name} is {self.state}")
            self._sending = (sid, parameter)
            stack = self._stack
            start = time.monotonic()
            try:
                with uds_link.listening([stack] if stack is not None else []):
                    response = call(client)
            except NegativeResponseException as e:
                self.counts["responses"] += 1
                self.counts["negative"] += 1
                if self.trace:
                    data = _after_sid(e.response)
                    self.trace.rx(sid, parameter, data, e.response.code, time.monotonic() - start)
                raise
            except TimeoutException:
                self.counts["timeouts"] += 1
                self._check_stack()
                raise
            except Exception:
                self.counts["errors"] += 1
                self._check_stack()
                raise
            finally:
                self._sending = None
            if sid == SID_ECU_RESET:
                self.reset_at = time.monotonic()
            elapsed = time.monotonic() - start
            if response is not None:
                self.counts["responses"] += 1
                self.counts["positive"] += 1
                if self.trace:
                    self.trace.rx(sid, parameter, _after_sid(response), 0, elapsed)
            return response, elapsed

    def _check_stack(self) -> None:
        if not self.stack_alive() and self.shared is not None:
            self.shared.fail(f"ISO-TP stack of {self.name} stopped (CAN send failed?)")

    # ─── Periodic tester present ───────────────────────────────────────────

    def set_tester_present(self, period: float | None) -> None:
        """Start (period in s) or stop (None) suppressed TesterPresent on this ECU.

        Stop, join and start run as one step: concurrent calls leave one thread at most.
        """
        with self._tp_lock:
            self._tp_stop.set()
            self.join_tester_present(STOP_BOUND)
            self.tp_period = None
            if period and not self._tp_closed:
                self.tp_period = period
                self._tp_stop = threading.Event()
                self._tp_thread = threading.Thread(
                    target=self._tester_present_loop,
                    args=(period, self._tp_stop),
                    name=f"uds-tp-{self.name}",
                    daemon=True,
                )
                self._tp_thread.start()

    def stop_tester_present(self) -> None:
        """Signal periodic TP to end for good; `join_tester_present` waits."""
        with self._tp_lock:
            self._tp_closed = True
            self.tp_period = None
            self._tp_stop.set()

    def join_tester_present(self, timeout: float) -> bool:
        thread = self._tp_thread
        if thread is None:
            return True
        thread.join(timeout)
        if thread.is_alive():
            return False
        self._tp_thread = None
        return True

    def _tester_present_loop(self, period: float, stop: threading.Event) -> None:
        while not stop.wait(period):
            try:
                self.request(SID_TESTER_PRESENT, 0x00, tester_present_suppressed, TP_LOCK_TIMEOUT)
            except Unavailable:  # bus down, or a request in progress keeps the session
                pass
            except Exception as e:
                logger.warning("[%s] periodic tester present: %s", self.name, _describe(e))

    # ─── Status ────────────────────────────────────────────────────────────

    def status(self) -> dict[str, Any]:
        if self.doip is not None:
            ids = {
                "tester_address": f"0x{self.doip.tester:04X}",
                "ecu_address": "" if self.ecu_address is None else f"0x{self.ecu_address:04X}",
                "activation_type": f"0x{self.doip.activation:02X}",
                "vehicle": self.vehicle.as_dict() if self.vehicle else None,
            }
        else:
            ids = {
                "tx_id": uds_link.id_text(self.tx_id, self.extended),
                "rx_id": uds_link.id_text(self.rx_id, self.extended),
                "extended_ids": self.extended,
                "fd_mode": self.fd,
            }
        return {
            "name": self.name,
            "state": str(self.state),
            "last_error": self.last_error,
            "interface": self.label,
            "endpoint": self.endpoint,
            **ids,
            "tester_present_active": self.tp_period is not None,
            "tester_present_interval": self.tp_period or 0,
            "reopens": self.shared.reopens if self.shared else 0,
            "metrics": dict(self.counts),
        }


def _after_sid(response: Any) -> bytes:
    """A response's bytes after its SID (0x7F for a negative one)."""
    return bytes((response.original_payload or b"")[1:])


def tester_present_suppressed(client: Client) -> None:
    with client.suppress_positive_response(wait_nrc=False):
        client.tester_present()
