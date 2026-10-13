"""UDS on DoIP (ISO 13400-2): settings, vehicle identification, the TCP connection.

doipclient carries the messages and udsoncan is the tester on its
`DoIPClientUDSConnector`, as on CAN it is on ISO-TP. One TCP connection per
ECU. No ISO-TP: a UDS message is one diagnostic message, whatever its size.

doipclient is pinned to a minor version: `Client` replaces its socket setup
and TCP read loop, and uses its private socket, parser and close flag.
"""

from __future__ import annotations

import contextlib
import logging
import socket
import struct
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from doipclient import DoIPClient
from doipclient.connectors import DoIPClientUDSConnector
from doipclient.messages import (
    AliveCheckRequest,
    AliveCheckResponse,
    DiagnosticMessage,
    DiagnosticMessageNegativeAcknowledgement,
    DiagnosticMessagePositiveAcknowledgement,
    GenericDoIPNegativeAcknowledge,
)
from udsoncan.exceptions import TimeoutException

logger = logging.getLogger(__name__)

PORT = 13400
TESTER = 0x0E80
BROADCAST = "255.255.255.255"
#: ISO 13400-2:2012, doipclient's.
PROTOCOL_VERSION = 0x02
#: A_DoIP_Ctrl: how long vehicle identification waits for answers.
IDENTIFY_S = 2.0
#: `tcp_timeout` default: the TCP connect and each request's acknowledgement.
TCP_TIMEOUT = 2.0
#: Why a connection went.
CLOSED = "DoIP connection closed by the entity"

VEHICLE_IDENTIFICATION_REQUEST, VEHICLE_IDENTIFICATION_RESPONSE = 0x0001, 0x0004
HEADER = struct.Struct("!BBHI")

ACTIVATION_CODES = {
    0x00: "unknown source address",
    0x01: "all TCP sockets in use",
    0x02: "source address differs from the one activated on this socket",
    0x03: "source address already active on another socket",
    0x04: "missing authentication",
    0x05: "confirmation rejected",
    0x06: "unsupported activation type",
    0x07: "TLS required",
    0x11: "confirmation required",
}
#: Refusals no retry fixes: the settings or the entity must change.
ACTIVATION_PERMANENT = {0x00, 0x02, 0x04, 0x06, 0x07}
DIAGNOSTIC_NACK = {
    0x02: "invalid source address",
    0x03: "unknown target address",
    0x04: "diagnostic message too large",
    0x05: "out of memory",
    0x06: "target unreachable",
    0x07: "unknown network",
    0x08: "transport protocol error",
}
HEADER_NACK = {
    0x00: "incorrect pattern format",
    0x01: "unknown payload type",
    0x02: "message too large",
    0x03: "out of memory",
    0x04: "invalid payload length",
}


class Refused(Exception):
    """The entity refused us; `permanent`: for a reason no retry fixes."""

    def __init__(self, reason: str, permanent: bool = True) -> None:
        super().__init__(reason)
        self.permanent = permanent


class Lost(ConnectionError):
    """The entity closed or reset the connection."""


class DoipError(Exception):
    """A diagnostic message the entity did not take: NACK, or no acknowledgement."""


# ─── Settings ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Config:
    """An ECU's `doip` settings. Discover: `host` may be empty (broadcast), `ecu` None
    (the entity's own address)."""

    host: str
    port: int
    tester: int
    ecu: int | None
    activation: int
    timeout: float
    discover: bool

    @property
    def peer(self) -> str:
        return f"{self.host or 'broadcast'}:{self.port}"


def _hex(value: Any, label: str, limit: int) -> int:
    try:
        number = value if isinstance(value, int) else int(str(value).strip(), 16)
    except ValueError:
        raise ValueError(f"{label} {value!r} is not hex, e.g. 0x1001") from None
    if not 0 <= number <= limit:
        raise ValueError(f"{label} {value} is out of range (0 to 0x{limit:X})")
    return number


def config(link: dict[str, Any]) -> Config:
    """The `doip` object of an ECU's settings; ValueError naming the setting."""
    doip = link.get("doip") or {}
    host = str(doip.get("host") or "").strip()
    discover = bool(doip.get("discover"))
    ecu = doip.get("ecu_address")
    ecu = (
        None if ecu is None or str(ecu).strip() == "" else _hex(ecu, "ECU Logical Address", 0xFFFF)
    )
    if not host and not discover:
        raise ValueError("no DoIP Host: set it, or turn on Discover")
    if ecu is None and not discover:
        raise ValueError("no ECU Logical Address: set it, or turn on Discover")
    port = int(doip.get("port") or PORT)
    if not 0 < port < 0x10000:
        raise ValueError(f"TCP Port {port} is out of range")
    timeout = float(doip.get("tcp_timeout") or TCP_TIMEOUT)
    if timeout <= 0:
        raise ValueError("TCP Timeout must be above 0")
    return Config(
        host=host,
        port=port,
        tester=_hex(doip.get("tester_address") or TESTER, "Tester Logical Address", 0xFFFF),
        ecu=ecu,
        activation=_hex(doip.get("activation_type") or 0, "Routing Activation Type", 0xFF),
        timeout=timeout,
        discover=discover,
    )


# ─── Vehicle identification (UDP) ───────────────────────────────────────────


@dataclass(frozen=True)
class Vehicle:
    """A vehicle identification response and where it came from."""

    ip: str
    logical_address: int
    vin: str
    eid: bytes
    gid: bytes
    further_action: int
    sync_status: int | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "logical_address": f"0x{self.logical_address:04X}",
            "vin": self.vin,
            "eid": self.eid.hex(":"),
            "gid": self.gid.hex(":"),
            "further_action": f"0x{self.further_action:02X}",
            "sync_status": None if self.sync_status is None else f"0x{self.sync_status:02X}",
        }


def _vehicle(data: bytes, ip: str) -> Vehicle | None:
    """A vehicle identification response datagram, else None."""
    if len(data) < HEADER.size:
        return None
    version, inverse, kind, length = HEADER.unpack_from(data)
    payload = data[HEADER.size : HEADER.size + length]
    if version ^ inverse != 0xFF or kind != VEHICLE_IDENTIFICATION_RESPONSE or len(payload) < 32:
        return None
    vin, address, eid, gid, action = struct.unpack_from("!17sH6s6sB", payload)
    sync = payload[32] if len(payload) > 32 else None
    # all 0x00 or 0xFF: not configured (ISO 13400-2)
    text = "" if set(vin) <= {0x00, 0xFF} else vin.decode("ascii", "replace")
    return Vehicle(ip, address, text, eid, gid, action, sync)


def identify(host: str, timeout: float = IDENTIFY_S) -> Vehicle:
    """Vehicle identification request on UDP 13400, to `host` or broadcast.

    doipclient's `get_entity` takes the first answer, which on a broadcast is a guess
    between vehicles: here a broadcast collects answers for `timeout` and exactly one
    entity must answer, else Refused. Unicast takes the first answer.
    """
    target = host or BROADCAST
    family, _, _, _, address = socket.getaddrinfo(target, PORT, type=socket.SOCK_DGRAM)[0]
    request = HEADER.pack(
        PROTOCOL_VERSION, PROTOCOL_VERSION ^ 0xFF, VEHICLE_IDENTIFICATION_REQUEST, 0
    )
    found: dict[tuple[str, int], Vehicle] = {}
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        if not host:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(request, address)
        deadline = time.monotonic() + timeout
        while (left := deadline - time.monotonic()) > 0:
            sock.settimeout(left)
            try:
                data, source = sock.recvfrom(4096)
            except TimeoutError:
                break
            vehicle = _vehicle(data, source[0])
            if vehicle is None:
                continue
            if host:
                return vehicle
            found[(vehicle.ip, vehicle.logical_address)] = vehicle
    if not found:
        raise TimeoutError(f"no DoIP entity answered vehicle identification at {target}")
    if len(found) > 1:
        seen = ", ".join(f"{v.ip} 0x{v.logical_address:04X} {v.vin}" for v in found.values())
        raise Refused(f"{len(found)} DoIP entities answered the broadcast ({seen}): set Host")
    return next(iter(found.values()))


# ─── TCP connection ─────────────────────────────────────────────────────────


class Client(DoIPClient):
    """doipclient with a bounded TCP connect, sends bounded by the same timeout, and a TCP
    read that loses nothing.

    Its own setup connects without a timeout (the OS's, over a minute to an absent host),
    and its read drops what a recv returns once the deadline has passed: that response
    is lost, and the stream can be left mid-message.
    """

    def __init__(self, *args: Any, connect_timeout: float, **kwargs: Any) -> None:
        self._connect_timeout = connect_timeout
        super().__init__(*args, **kwargs)

    def _connect(self) -> None:
        sock = socket.create_connection(
            (self._ecu_ip_address, self._tcp_port), self._connect_timeout
        )
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        self._tcp_sock, self._tcp_close_detected = sock, False
        # Unused (vehicle identification is `identify`); doipclient's close() closes it.
        self._udp_sock = socket.socket(self._address_family, socket.SOCK_DGRAM)

    def read_doip(
        self,
        timeout: float = IDENTIFY_S,
        transport: DoIPClient.TransportType = DoIPClient.TransportType.TRANSPORT_TCP,
    ) -> Any:
        """The next message within `timeout` (0: only what has arrived). Every byte read
        goes to the parser before the deadline is checked. Answers alive checks; a generic
        header NACK raises DoipError; TimeoutError once the entity has closed."""
        if transport != DoIPClient.TransportType.TRANSPORT_TCP:
            return super().read_doip(timeout, transport)
        deadline = time.monotonic() + timeout
        sock = self._tcp_sock
        try:
            while True:
                message = self._tcp_parser.read_message(b"")
                if isinstance(message, GenericDoIPNegativeAcknowledge):
                    code = message.nack_code
                    reason = HEADER_NACK.get(code, "reserved")
                    raise DoipError(f"DoIP header refused: NACK 0x{code:02X} {reason}")
                if isinstance(message, AliveCheckRequest):
                    self.send_doip_message(AliveCheckResponse(self._client_logical_address))
                    continue
                if message is not None:
                    return message
                if self._tcp_close_detected:
                    raise TimeoutError(CLOSED)
                left = deadline - time.monotonic()
                sock.settimeout(max(left, 0.0))  # 0: non-blocking, a last look
                try:
                    data = sock.recv(4096)
                except (TimeoutError, BlockingIOError):
                    if left <= 0:
                        raise TimeoutError("ECU failed to respond in time") from None
                    continue
                self._tcp_close_detected = not data
                self._tcp_parser.push_bytes(data)
        finally:
            with contextlib.suppress(OSError):  # closed meanwhile
                sock.settimeout(self._connect_timeout)

    def close(self) -> None:
        """Shut down first: wakes a read in progress on another thread."""
        with contextlib.suppress(OSError):  # not connected any more
            self._tcp_sock.shutdown(socket.SHUT_RDWR)
        super().close()


def connect(cfg: Config, vehicle: Vehicle | None) -> tuple[Client, int]:
    """TCP connect and routing activation: (client, ECU logical address).

    The host is the configured one, else the identified entity's; the ECU address the
    configured one, else the entity's. A refused activation raises Refused.
    """
    host = cfg.host or (vehicle.ip if vehicle else "")
    ecu = cfg.ecu if cfg.ecu is not None else vehicle.logical_address if vehicle else None
    if not host or ecu is None:
        raise ValueError("no DoIP host or ECU address")  # config() and Discover rule it out
    ip = socket.getaddrinfo(host, cfg.port, type=socket.SOCK_STREAM)[0][4][0]
    client = Client(
        ip,
        ecu,
        tcp_port=cfg.port,
        activation_type=None,  # activated below: the refusal code named
        client_logical_address=cfg.tester,
        connect_timeout=cfg.timeout,
    )
    try:
        response = client.request_activation(cfg.activation, disable_retry=True)
    except BaseException:
        client.close()
        raise
    code = response.pack()[4]  # raw: the enum property raises on VM-specific codes
    if code != 0x10:
        client.close()
        reason = ACTIVATION_CODES.get(code, "VM-specific" if 0xE0 <= code <= 0xFE else "reserved")
        text = (
            f"DoIP routing activation refused: 0x{code:02X} {reason} "
            f"(tester 0x{cfg.tester:04X}, type 0x{cfg.activation:02X})"
        )
        raise Refused(text, permanent=code in ACTIVATION_PERMANENT)
    return client, ecu


class Connection(DoIPClientUDSConnector):
    """udsoncan's connection to one ECU over a DoIP client.

    `on_send` gets each request once the entity acknowledged it (0x8002), as the CAN
    connection's does once the last frame is out. `on_lost` gets the reason once the
    entity closed or reset the connection; the call then raises Lost. A NACK, or no
    acknowledgement within `ack_timeout`, raises DoipError naming the code; a response
    timeout udsoncan's TimeoutException, as on CAN. Messages nobody waits for (late
    responses) are dropped before each request.
    """

    def __init__(
        self,
        client: Client,
        tester: int,
        target: int,
        ack_timeout: float,
        on_send: Callable[[bytes], None] = lambda _: None,
        on_lost: Callable[[str], None] = lambda _: None,
    ) -> None:
        super().__init__(client)
        self.client, self.tester, self.target = client, tester, target
        self.ack_timeout, self.on_send, self.on_lost = ack_timeout, on_send, on_lost

    def send(self, data: Any, timeout: float | None = None) -> None:
        payload = bytes(data.get_payload() if hasattr(data, "get_payload") else data)
        super().send(data, timeout)
        self.on_send(payload)

    def specific_send(self, payload: bytes) -> None:
        message = DiagnosticMessage(self.tester, self.target, bytearray(payload))
        deadline = time.monotonic() + self.ack_timeout
        with self._errors():
            self.client.send_doip_message(message)
            while (left := deadline - time.monotonic()) > 0:
                try:
                    reply = self.client.read_doip(timeout=left)
                except TimeoutError:
                    if self.client._tcp_close_detected:
                        raise
                    break
                acks = (
                    DiagnosticMessagePositiveAcknowledgement,
                    DiagnosticMessageNegativeAcknowledgement,
                )
                if not isinstance(reply, acks) or (reply.source_address, reply.target_address) != (
                    self.target,
                    self.tester,
                ):
                    logger.debug("DoIP: dropped %s before the acknowledgement", reply)
                    continue
                if isinstance(reply, DiagnosticMessageNegativeAcknowledgement):
                    code = reply.pack()[4]  # raw: the enum property raises on reserved codes
                    reason = DIAGNOSTIC_NACK.get(code, "reserved")
                    raise DoipError(f"DoIP diagnostic message refused: NACK 0x{code:02X} {reason}")
                return
        raise DoipError(f"DoIP: no acknowledgement within {self.ack_timeout:g} s")

    def specific_wait_frame(self, timeout: float | None = 2) -> bytes:
        with self._errors():
            # receive_diagnostic reads 0 as no timeout at all
            return bytes(self.client.receive_diagnostic(timeout=timeout or 1e-3))

    def empty_rxqueue(self) -> None:
        """Drop what arrived unasked and answer alive checks (the client's read does);
        never waits for more. Raises Lost once the entity has closed."""
        with self._errors():
            while True:
                try:
                    logger.debug("DoIP: dropped %s", self.client.read_doip(timeout=0))
                except TimeoutError:
                    break
        if self.client._tcp_close_detected:
            raise self.lost(CLOSED)

    def lost(self, reason: str) -> Lost:
        self.on_lost(reason)
        return Lost(reason)

    @contextlib.contextmanager
    def _errors(self) -> Iterator[None]:
        """doipclient's errors as ours."""
        try:
            yield
        except (DoipError, Lost):
            raise
        except OSError as e:  # TimeoutError, socket errors
            if self.client._tcp_close_detected:
                raise self.lost(CLOSED) from None
            if isinstance(e, TimeoutError):
                raise TimeoutException(str(e)) from None
            raise self.lost(f"DoIP connection lost: {e.strerror or e}") from None
