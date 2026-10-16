"""An ECU over UDS on CAN (ISO 14229 on ISO-TP), as a test drives it.

zelos-can opens the bus, can-isotp carries the messages, udsoncan is the
tester. `client` addresses the ECU physically; `functional()` addresses every
ECU on the bus at once, as a tester's keep-alive does. Any python-can bus.
"""

import contextlib
import struct
import time

import can
import isotp
from udsoncan import AsciiCodec, DidCodec, MemoryLocation
from udsoncan.client import Client
from udsoncan.configs import default_client_config
from udsoncan.connections import PythonIsoTpConnection
from udsoncan.exceptions import NegativeResponseException
from udsoncan.services import ECUReset
from zelos_can.bus import BUS_DEFAULTS, open_python_can_bus, prepare_bus_config

from zelos_testing import frames, uds_keys

__all__ = ["CAN_STATS", "FUNCTIONAL", "PHYSICAL", "RESPONSE", "NegativeResponseException", "UdsEcu", "transfer_block"]

# The node's identifiers: requests to it, to every ECU, and its responses.
PHYSICAL, FUNCTIONAL, RESPONSE = 0x7E0, 0x7DF, 0x7E8
DEFAULT, PROGRAMMING, EXTENDED = 0x01, 0x02, 0x03
LEVEL_EXTENDED, LEVEL_PROGRAMMING = 0x01, 0x11
# Security delay, also after power-up.
SECURITY_DELAY_S = 10.0


class Scaled(DidCodec):
    """A big-endian number in fixed steps, e.g. '>H' in 0.01 V, or '>f' as is."""

    def __init__(self, fmt: str, step: float = 1):
        self.fmt, self.step = fmt, step
        self.real = fmt[-1] in "fd"

    def encode(self, value: float) -> bytes:
        raw = value / self.step
        return struct.pack(self.fmt, raw if self.real else round(raw))

    def decode(self, payload: bytes) -> float:
        value = struct.unpack(self.fmt, payload)[0] * self.step
        return value if self.real else round(value, 6)

    def __len__(self) -> int:
        return struct.calcsize(self.fmt)


class Words(DidCodec):
    """n big-endian uint32, as a tuple."""

    def __init__(self, n: int):
        self.fmt = f">{n}I"

    def encode(self, value) -> bytes:
        return struct.pack(self.fmt, *value)

    def decode(self, payload: bytes) -> tuple:
        return struct.unpack(self.fmt, payload)

    def __len__(self) -> int:
        return struct.calcsize(self.fmt)


# DID 0x0110, in order: the node's CAN counters (struct zelos_can_stats).
CAN_STATS = ("sent", "overflow", "deferred", "tx_error", "peak", "rx_overrun")

# The contract; see nodes/dcdc/src/uds.c.
DIDS = {
    0xF186: Scaled(">B"),  # active session
    0xF187: AsciiCodec(13),  # spare part number
    0xF18A: AsciiCodec(5),  # system supplier
    0xF18C: AsciiCodec(10),  # serial number
    0xF190: AsciiCodec(17),  # VIN
    0xF191: AsciiCodec(13),  # hardware version
    0xF195: AsciiCodec(10),  # software version
    0x0101: Scaled(">f"),  # output voltage, V
    0x0102: Scaled(">h", 0.1),  # output current, A
    0x0103: Scaled(">b"),  # temperature, degC
    0x0104: Scaled(">I"),  # uptime, ms
    0x0105: Scaled(">H", 0.1),  # input voltage, V; 6553.5 unknown
    0x0106: Scaled(">H", 0.01),  # input current, A
    0x0110: Words(len(CAN_STATS)),  # CAN counters
    0x0200: Scaled(">H", 0.01),  # output voltage setpoint, V
}
IOS = {0x0300: Scaled(">H", 0.01)}  # output voltage setpoint, V

# What the suites check against: identification, DIDs, routines, memory, DTCs, timing.
IDENTIFICATION = {
    0xF187: "ZLS-DCDC-0001",
    0xF18A: "ZELOS",
    0xF18C: "ZD00000001",
    0xF190: "1ZLSDCDC0BENCH001",
    0xF191: "NUCLEO-H753ZI",
    0xF195: "DCDC-1.0.0",
}
VIN, ACTIVE_SESSION = 0xF190, 0xF186
VOLTAGE, CURRENT, TEMPERATURE, UPTIME, INPUT_V, INPUT_A, SETPOINT = 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0200
OUTPUT = 0x0300
RETURN, RESET, FREEZE, ADJUST = 0, 1, 2, 3
SELF_TEST, ERASE, CHECK = 0x0201, 0xFF00, 0xFF01
SETPOINT_V = 13.8

# Memory by address: the model's state (read-only) and its calibration.
STATE_ADDRESS, STATE = 0x00010000, struct.Struct("<7fI")
CALIBRATION_ADDRESS, CALIBRATION = 0x00020000, struct.Struct("<2f")
DOWNLOAD_ADDRESS, DOWNLOAD_SIZE, BLOCK_LENGTH = 0x00100000, 0x10000, 0x402

DTC_OVERTEMPERATURE, DTC_UNDERVOLTAGE, DTC_OVERCURRENT, DTC_BMS_LOST = 0x1A0098, 0x1A0116, 0x1A0219, 0xC11187
DTCS = (DTC_OVERTEMPERATURE, DTC_UNDERVOLTAGE, DTC_OVERCURRENT, DTC_BMS_LOST)
TF, TFTOC, PDTC, CDTC, TNCSLC, TFSLC, TNCTOC, WIR = (1 << n for n in range(8))
SNAPSHOT_DIDS = (VOLTAGE, CURRENT, TEMPERATURE, UPTIME, INPUT_V)

S3_S = 5.0
SELF_TEST_S = 2.0
MARGIN = 0.02


def dtcs(ecu: "UdsEcu", mask: int = 0xFF) -> dict[int, int]:
    """DTC to status byte, of those whose status matches mask."""
    return {d.id: d.status.get_byte_as_int() for d in ecu.client.get_dtc_by_status_mask(mask).service_data.dtcs}


def location(address: int, size: int, size_format: int = 32) -> MemoryLocation:
    return MemoryLocation(address=address, memorysize=size, address_format=32, memorysize_format=size_format)


def reset(ecu: "UdsEcu", kind=ECUReset.ResetType.hardReset):
    """ECUReset, answered first, then wait until the ECU answers again."""
    assert ecu.client.ecu_reset(kind).service_data.reset_type_echo == kind
    ecu.wait_up(frames.bound(5.0))


# Renode models no bus time: a message's consecutive frames reach the node at
# once, and more than an RX FIFO holds (32) are lost. There TransferData blocks
# stay under it; on hardware they are the node's maximum.
SIMULATED_BLOCK = 160


def transfer_block(max_length: int) -> int:
    """Data bytes per TransferData, from RequestDownload's maxNumberOfBlockLength."""
    block = max_length - 2  # less SID and counter
    return min(block, SIMULATED_BLOCK) if frames.SIMULATED else block


def key(level: int, seed: bytes, params=None) -> bytes:
    return uds_keys.key(level, seed)


class UdsEcu:
    """A tester connected to the ECU on a python-can bus. Use as a context manager.

    timeout_s bounds each wait for a response, and a pending (0x78) one;
    delay_s a wait for a security delay to end.
    """

    def __init__(self, interface: str, channel: str, timeout_s: float = 2.0, delay_s: float = SECURITY_DELAY_S):
        self.interface, self.channel = interface, channel
        self.timeout_s, self.delay_s = timeout_s, delay_s

    def _client(self, txid: int) -> Client:
        stack = isotp.NotifierBasedCanStack(
            self.bus,
            self.notifier,
            address=isotp.Address(isotp.AddressingMode.Normal_11bits, txid=txid, rxid=RESPONSE),
            params={"tx_padding": 0xCC, "tx_data_min_length": 8, "blocking_send": True},
        )
        config = dict(default_client_config)
        config.update(
            request_timeout=None,
            p2_timeout=self.timeout_s,
            p2_star_timeout=max(5.0, self.timeout_s),
            # Timing is the suite's to assert, not the client's to adopt.
            use_server_timing=False,
            security_algo=key,
            data_identifiers=DIDS,
            input_output=IOS,
        )
        client = Client(PythonIsoTpConnection(stack), config=config)
        client.open()
        return client

    def __enter__(self):
        config = prepare_bus_config(
            {"interface": self.interface, "channel": self.channel},
            advanced={**BUS_DEFAULTS, "receive_own_messages": False, "log_raw_frames": False},
        )
        self.bus = open_python_can_bus(config, "uds")
        self.notifier = can.Notifier(self.bus, [])
        try:
            self.client = self._client(PHYSICAL)
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *exc):
        try:
            if hasattr(self, "client"):
                self.client.close()
            self.notifier.stop()
        finally:
            self.bus.shutdown()

    @contextlib.contextmanager
    def functional(self):
        """A client on the functional identifier, for the block.

        Only while it is open: its ISO-TP stack would also answer the ECU's
        multi-frame responses to physical requests with flow control.
        """
        client = self._client(FUNCTIONAL)
        try:
            yield client
        finally:
            client.close()

    def raw(self, payload: bytes, functional: bool = False, timeout_s: float | None = None) -> bytes | None:
        """Send payload as is; the response, or None if there is none in timeout_s."""
        with self.functional() if functional else contextlib.nullcontext(self.client) as client:
            client.conn.empty_rxqueue()
            client.conn.send(payload)
            return client.conn.wait_frame(timeout=self.timeout_s if timeout_s is None else timeout_s)

    def read(self, did: int):
        return self.client.read_data_by_identifier(did).service_data.values[did]

    def session(self) -> int:
        return self.read(0xF186)

    def enter(self, *sessions: int):
        """Enter each session in turn, e.g. extended then programming."""
        for s in sessions:
            self.client.change_session(s)

    def unlock(self, level: int, delay_s: float | None = None):
        """Unlock level, waiting out a security delay (after power-up, say) of up to delay_s."""
        end = time.monotonic() + (self.delay_s if delay_s is None else delay_s)
        while True:
            try:
                self.client.unlock_security_access(level)
                return
            except NegativeResponseException as e:
                if e.response.code != 0x37 or time.monotonic() > end:
                    raise
            time.sleep(0.5)

    def wait_up(self, timeout_s: float):
        """After a reset: until the ECU answers again."""
        end = time.monotonic() + timeout_s
        # Short polls: one sent while the ECU reboots is lost, and waiting out
        # the full response timeout for it would run past power-up timers
        # (the security delay) the caller then checks.
        while self.raw(b"\x3e\x00", timeout_s=min(self.timeout_s, 1.0)) != b"\x7e\x00":
            assert time.monotonic() < end, f"no answer {timeout_s:.0f} s after the reset"
