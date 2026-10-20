"""Demo UDS ECU: the bench DC-DC's UDS server, in Python, on any python-can bus.

A port of the firmware's server (zelos-examples `lib/uds/core/uds_core.c`, the
node's `nodes/dcdc/src/uds.c` and its model in `main.c`); the contract is in
docs/behaviour.md.

Default bus: the in-process zelos-can virtual bus, which serves the extension
and tests, not other programs; `interface` takes any python-can bus. There is
no BMS on the bus: the demo plays one (`bms`), and DTC test results can be
forced (`force`) to exercise the DTC paths.
"""

from __future__ import annotations

import logging
import math
import os
import struct
import threading
import time
import zlib

import can
import isotp
from zelos_can import isotp as uds_link

logger = logging.getLogger(__name__)

REQUEST_ID, FUNCTIONAL_ID, RESPONSE_ID = 0x7E0, 0x7DF, 0x7E8
PADDING = 0xCC

DEFAULT, PROGRAMMING, EXTENDED = 0x01, 0x02, 0x03
LEVEL_EXTENDED, LEVEL_PROGRAMMING = 0x01, 0x11
#: Key = seed XOR this, per level (zelos_testing.uds_keys; the shipped demo key file).
KEY_XOR = {LEVEL_EXTENDED: 0x5A5AA5A5, LEVEL_PROGRAMMING: 0xC3A53C5A}

P2_MS, P2_STAR_MS = 50, 5000
S3 = 5.0
PENDING_REPEAT_S = 2.0
SELF_TEST_S = 2.0
ERASE_S = 1.0
SECURITY_ATTEMPTS = 3
SECURITY_DELAY_S = 10.0
#: Security delay armed at power-up. Tests may shorten it; the contract's is SECURITY_DELAY_S.
POWER_UP_DELAY_S = SECURITY_DELAY_S
#: Model and DTC test cycle.
CYCLE_S = 0.05

DOWNLOAD_ADDRESS, DOWNLOAD_SIZE = 0x00100000, 0x10000
#: maxNumberOfBlockLength (the server's buffer), lengthFormatIdentifier.
BLOCK_LENGTH, LENGTH_FORMAT = 0x402, 0x20
STATE_ADDRESS, STATE = 0x00010000, struct.Struct("<7fI")
CALIBRATION_ADDRESS, CALIBRATION = 0x00020000, struct.Struct("<2f")

RID_SELF_TEST, RID_ERASE, RID_CHECK = 0x0201, 0xFF00, 0xFF01

SETPOINT, SETPOINT_MIN, SETPOINT_MAX = 1380, 1000, 1600
VIN = "1ZLSDCDC0BENCH001"
IDENTIFICATION = {
    0xF187: b"ZLS-DCDC-0001",
    0xF18A: b"ZELOS",
    0xF18C: b"ZD00000001",
    0xF191: b"NUCLEO-H753ZI",
    0xF195: b"DCDC-1.0.0",
}
#: DTCs in index order: overtemperature, input undervoltage, output overcurrent, BMS lost;
#: SAE J2012 generic codes P0A94-00, P0A09-00, P0A08-00, U0111-00. The firmware adds
#: P062F-00 (0x062F00) once its flash store fails; this ECU has no flash.
DTCS = (0x0A9400, 0x0A0900, 0x0A0800, 0xC11100)
OVERTEMPERATURE, UNDERVOLTAGE, OVERCURRENT, BMS_LOST = range(4)
SNAPSHOT_DIDS = (0x0101, 0x0102, 0x0103, 0x0104, 0x0105)
#: Snapshot records, in order: OBD-II first frame, the node's DIDs, OBD-II second frame.
RECORD_FIRST, RECORD_DIDS, RECORD_LATEST = 0x00, 0x01, 0xF0
RECORDS = (RECORD_FIRST, RECORD_DIDS, RECORD_LATEST)
TF, TFTOC, PDTC, CDTC, TNCSLC, TFSLC, TNCTOC, WIR = (1 << n for n in range(8))
DTC_CLEARED = TNCSLC | TNCTOC
#: The firmware's Kconfig defaults: CCR 1968.2 (d)(2.2.2), (d)(2.3.2), (d)(2.4).
CONFIRM_CYCLES, HEALING_CYCLES, AGING_CYCLES = 2, 3, 40
#: OBD-II freeze frame PIDs (records 0x00, 0xF0), each from a snapshot DID: (PID, DID).
FRAME_PIDS = ((0x1F, 0x0104), (0x42, 0x0101), (0x46, 0x0103), (0x5B, 0x0105))
PACK_FULL_V, UNDERVOLTAGE_V = 400.0, 250.0

# Model (nodes/dcdc/src/main.c).
AMBIENT_C, THERMAL_GAIN_C_PER_A, THERMAL_TAU_S = 28.0, 4.5, 6.0
PACK_NOMINAL_V, EFFICIENCY, DROOP_V_PER_A = 374.0, 0.93, 0.0035
BMS_TIMEOUT_S = 0.5

NRC_SERVICE_NOT_SUPPORTED = 0x11
NRC_SUBFUNCTION_NOT_SUPPORTED = 0x12
NRC_INCORRECT_LENGTH = 0x13
NRC_BUSY_REPEAT = 0x21
NRC_CONDITIONS = 0x22
NRC_SEQUENCE = 0x24
NRC_OUT_OF_RANGE = 0x31
NRC_SECURITY_DENIED = 0x33
NRC_INVALID_KEY = 0x35
NRC_ATTEMPTS_EXCEEDED = 0x36
NRC_DELAY_NOT_EXPIRED = 0x37
NRC_DOWNLOAD_NOT_ACCEPTED = 0x70
NRC_TRANSFER_SUSPENDED = 0x71
NRC_WRONG_BSC = 0x73
NRC_PENDING = 0x78
NRC_SUBFUNCTION_NOT_IN_SESSION = 0x7E
NRC_SERVICE_NOT_IN_SESSION = 0x7F
#: ISO 14229-1 7.5: never sent in answer to a functional request.
FUNCTIONAL_SILENT = {0x11, 0x12, 0x31, 0x7E, 0x7F}


class Nrc(Exception):
    def __init__(self, code: int) -> None:
        self.code = code


def _need(ok: bool, code: int) -> None:
    if not ok:
        raise Nrc(code)


def _within(base: int, limit: int, addr: int, size: int) -> bool:
    return addr >= base and size <= limit and addr - base <= limit - size


def _scaled(value: float, step: float, lo: int, hi: int) -> int:
    """Rounded to `step`, saturating; NaN lands on `lo` (as the firmware's)."""
    raw = round(value / step) if not math.isnan(value) else lo
    return lo if not raw >= lo else min(raw, hi)


class Dtc:
    """One DTC's memory: status, counters, first and second frame (the snapshot DIDs'
    bytes). Survives a reset, not power-off."""

    def __init__(self) -> None:
        self.clear()

    def clear(self) -> None:
        self.status, self.occurrences, self.aging = DTC_CLEARED, 0, 0
        self.failed_cycles = self.healing = 0
        self.snapshot: bytes | None = None
        self.latest: bytes | None = None

    def start_cycle(self) -> None:
        """The end of an operation cycle, at the start of the next (power-up, reset):
        ISO 14229-1 Annex D, then the OBD-II lifecycle, CCR 1968.2 (d)(2.2)-(2.4)."""
        tested, failed = not self.status & TNCTOC, bool(self.status & TFTOC)
        if not failed and self.status & (CDTC | WIR) == CDTC:
            self.aging += 1
            if self.aging >= AGING_CYCLES:  # (d)(2.4): with the MIL off; frames go with it
                self.status &= ~CDTC
                self.aging = 0
                self.snapshot = self.latest = None
        if tested and not failed:
            self.status &= ~PDTC
            self.failed_cycles = 0
            if not self.status & CDTC:  # (d)(2.2.7)(B)(i): a pending code takes its frames
                self.snapshot = self.latest = None
            if self.status & WIR:
                self.healing += 1
                if self.healing >= HEALING_CYCLES:  # (d)(2.3.2): the MIL goes off
                    self.status &= ~WIR
                    self.healing = 0
        self.status = (self.status & ~TFTOC) | TNCTOC


class DemoEcu:
    """UDS server: requests on `request_id` and `functional_id`, responses on `response_id`.

    Hooks: `bms` is the BMS it plays, (aux current limit A, pack voltage V), or None for
    no BMS on the bus. `force[i]` overrides DTC i's test result (True failing, False
    passing, None the model's).
    """

    def __init__(
        self,
        channel: str = "uds-demo",
        interface: str | None = None,
        bitrate: int | None = None,
        fd: bool = False,
        request_id: int = REQUEST_ID,
        response_id: int = RESPONSE_ID,
        extended: bool = False,
        stmin: int = 0,
        functional_id: int | None = FUNCTIONAL_ID,
    ) -> None:
        self.link = {"interface": interface or "zelos-virtual", "channel": channel, "fd_mode": fd}
        if bitrate:
            self.link["bitrate"] = bitrate
        self.ids = (request_id, response_id, functional_id, extended)
        self.fd, self.stmin = fd, stmin
        self.bms: tuple[float, float] | None = (20.0, PACK_NOMINAL_V)
        self.force: list[bool | None] = [None] * len(DTCS)
        self.dtcs = [Dtc() for _ in DTCS]
        self.lock = threading.Lock()  # the server thread vs hooks and tests
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._bus: can.BusABC | None = None
        self._notifier: can.Notifier | None = None
        self._stacks: list[isotp.NotifierBasedCanStack] = []
        self._services = {
            0x10: (self._session_control, (DEFAULT, PROGRAMMING, EXTENDED), True),
            0x11: (self._ecu_reset, (DEFAULT, PROGRAMMING, EXTENDED), True),
            0x14: (self._clear_dtc, (DEFAULT, PROGRAMMING, EXTENDED), False),
            0x19: (self._read_dtc, (DEFAULT, PROGRAMMING, EXTENDED), False),
            0x22: (self._read_did, (DEFAULT, PROGRAMMING, EXTENDED), False),
            0x23: (self._read_memory, (DEFAULT, PROGRAMMING, EXTENDED), False),
            0x27: (self._security_access, (PROGRAMMING, EXTENDED), True),
            0x28: (self._communication_control, (PROGRAMMING, EXTENDED), True),
            0x2E: (self._write_did, (PROGRAMMING, EXTENDED), False),
            0x2F: (self._io_control, (EXTENDED,), False),
            0x31: (self._routine_control, (PROGRAMMING, EXTENDED), True),
            0x34: (self._request_transfer, (PROGRAMMING,), False),
            0x35: (self._request_transfer, (PROGRAMMING,), False),
            0x36: (self._transfer_data, (PROGRAMMING,), False),
            0x37: (self._transfer_exit, (PROGRAMMING,), False),
            0x3D: (self._write_memory, (EXTENDED,), False),
            0x3E: (self._tester_present, (DEFAULT, PROGRAMMING, EXTENDED), True),
            0x85: (self._dtc_setting, (PROGRAMMING, EXTENDED), True),
        }
        self._boot(first=True)

    # ─── Lifecycle ─────────────────────────────────────────────────────────

    def start(self) -> DemoEcu:
        request_id, response_id, functional_id, extended = self.ids
        self._bus = uds_link.open_bus(self.link, "uds-demo-ecu")
        self._notifier = can.Notifier(self._bus, [], timeout=0.1)
        params = {
            **uds_link.isotp_params({"isotp_blocksize": 0, "isotp_stmin": self.stmin}, self.fd),
            "tx_padding": PADDING,
            "tx_data_min_length": None if self.fd else 8,
        }
        for rx in (request_id, functional_id):
            if rx is not None:
                address = uds_link.address(response_id, rx, extended)
                stack = isotp.NotifierBasedCanStack(
                    self._bus, self._notifier, address=address, params=params
                )
                stack.start()
                self._stacks.append(stack)
        self._thread = threading.Thread(target=self._run, name="uds-demo-ecu", daemon=True)
        self._thread.start()
        logger.info("Demo UDS ECU on %s", uds_link.bus_text(self.link))
        return self

    def stop(self) -> None:
        """Explicit order: server thread, ISO-TP stacks, notifier, bus."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(1.0)
        for stack in self._stacks:
            stack.stop()
        if self._notifier is not None:
            self._notifier.stop(timeout=0.5)
        if self._bus is not None:
            self._bus.shutdown()

    def _run(self) -> None:
        physical = self._stacks[0]
        single_frame = 62 if self.fd else 7
        next_cycle = time.monotonic()
        while not self._stop.wait(0.001):
            for stack in self._stacks:
                while (request := stack.recv(block=False)) is not None:
                    if stack is not physical and len(request) > single_frame:
                        continue  # ISO 15765-2: functional requests are single frames
                    with self.lock:
                        response = self.request(bytes(request), stack is not physical)
                    if response:
                        physical.send(response)
            with self.lock:
                response = self.tick()
                if time.monotonic() >= next_cycle:
                    next_cycle += CYCLE_S
                    self.sample()
            if response:
                physical.send(response)

    def _boot(self, first: bool = False) -> None:
        """Power-up (first) or a reset: RAM state back, the DTC memory kept and a new
        operation cycle started; the security delay armed either way."""
        now = time.monotonic()
        self.booted = now
        self.session = DEFAULT
        self.s3_deadline = now + S3
        self.unlocked = 0
        self.seed, self.seed_level = 0, 0
        self.failed_keys = {LEVEL_EXTENDED: 0, LEVEL_PROGRAMMING: 0}
        self.lockout_until = dict.fromkeys(self.failed_keys, now + POWER_UP_DELAY_S)
        self.communication, self.dtc_setting = 0x00, True
        self.vin = VIN.encode()
        self.setpoint, self.override = SETPOINT, None
        self.calibration = bytearray(CALIBRATION.pack(4.5, 10.0))
        self.pending: tuple[int, float, float] | None = None  # routine, done at, last 0x78
        self.last, self.last_result = 0, b""
        self.transfer: tuple[int, int, int] | None = None  # (sid, address, size)
        self.transfer_done, self.transfer_bsc, self.transfer_last = 0, 1, 0
        self.download = bytearray(DOWNLOAD_SIZE)
        self.erased = (0, 0)
        self.erase = (DOWNLOAD_ADDRESS, DOWNLOAD_SIZE)
        self.downloaded: tuple[int, int] | None = None
        self.input_a, self.temperature_c, self.aux_limit_a = 0.0, AMBIENT_C, 0.0
        self.limits_at, self.pack_at, self.pack_v = 0.0, 0.0, math.nan
        self.rx_was = True
        self.failing = 0
        self.state = (0.0,) * 7 + (0,)
        for dtc in self.dtcs:
            dtc.clear() if first else dtc.start_cycle()
        self.sample(test=False)

    # ─── Model (nodes/dcdc/src/main.c) ─────────────────────────────────────

    def _output(self) -> int:
        return self.setpoint if self.override is None else self.override

    def sample(self, test: bool = True) -> None:
        """One 50 ms model cycle, then the DTC tests on it."""
        now = time.monotonic()
        rx = self.communication != 0x03  # 0x01 disables Tx only
        if rx and not self.rx_was:  # reception back on: the BMS timeout runs from here
            self.limits_at = now
        self.rx_was = rx
        if rx and self.bms is not None:
            self.aux_limit_a, self.pack_v = self.bms
            self.limits_at = self.pack_at = now
        demand, slew = CALIBRATION.unpack(self.calibration)
        demand = min(max(demand, 0.0), 20.0) if not math.isnan(demand) else 0.0
        slew = min(max(slew, 0.1), 100.0) if not math.isnan(slew) else 0.1
        target, step = min(demand, self.aux_limit_a), slew * CYCLE_S
        if target < self.input_a:
            self.input_a = max(self.input_a - step, target)
        else:
            self.input_a = min(self.input_a + step, target)
        rail_v = self._output() * 0.01
        output_a = self.input_a * PACK_NOMINAL_V * EFFICIENCY / rail_v
        self.temperature_c += (AMBIENT_C + THERMAL_GAIN_C_PER_A * self.input_a
                               - self.temperature_c) * (CYCLE_S / THERMAL_TAU_S)  # fmt: skip
        fresh = self.pack_at and now - self.pack_at <= BMS_TIMEOUT_S
        input_v = self.pack_v if fresh else math.nan
        uptime = int((now - self.booted) * 1000) & 0xFFFFFFFF
        self.state = (rail_v - DROOP_V_PER_A * output_a, output_a, input_v, self.input_a,
                      self.temperature_c, rail_v, self.aux_limit_a, uptime)  # fmt: skip
        if not test:
            return
        since_boot = now - self.booted
        results = {
            OVERTEMPERATURE: self.temperature_c > 70.0,
            OVERCURRENT: output_a > 300.0,
            UNDERVOLTAGE: None if math.isnan(input_v) else input_v < 250.0,
            BMS_LOST: (now - self.limits_at > BMS_TIMEOUT_S)
            if rx and (self.limits_at or since_boot > BMS_TIMEOUT_S)
            else None,
        }
        for i, result in results.items():
            result = result if self.force[i] is None else self.force[i]
            if result is not None:
                self.failing = self.failing | 1 << i if result else self.failing & ~(1 << i)
                self._test_dtc(i, result)

    def _test_dtc(self, i: int, failed: bool) -> None:
        if not self.dtc_setting:
            return
        d = self.dtcs[i]
        if not failed:
            d.status &= ~(TF | TNCTOC | TNCSLC)  # the MIL (WIR) stays until it heals
            return
        first = not d.status & TFTOC
        if first:
            d.occurrences = min(d.occurrences + 1, 0xFF)
        # Both frames with the pending code; the second again in each later cycle.
        if d.snapshot is None:
            d.snapshot = d.latest = self._frame()
        elif first:
            d.latest = self._frame()
        d.status = (d.status | TF | TFTOC | PDTC | TFSLC) & ~(TNCTOC | TNCSLC)
        d.aging = d.healing = 0
        if first:
            d.failed_cycles = min(d.failed_cycles + 1, 0xFF)
        if d.failed_cycles >= CONFIRM_CYCLES:  # (d)(2.2.2), (d)(2.2.5): confirmed, MIL on
            d.status |= CDTC | WIR

    def _frame(self) -> bytes:
        return b"".join(self._did(did) for did in SNAPSHOT_DIDS)

    # ─── Request / tick (lib/uds/core/uds_core.c) ──────────────────────────

    def request(self, req: bytes, functional: bool = False) -> bytes | None:
        """One request in, the response out (None: none sent)."""
        if not req:
            return None
        now = time.monotonic()
        self.s3_deadline = now + S3  # every request, answered or not
        if self.pending is not None:
            if req == b"\x3e\x80":
                return None
            # Functionally, no 0x21 where idle would be silent (0x11, 0x7F).
            # suppressPosRsp hides positive responses only.
            service = self._services.get(req[0])
            if functional and (service is None or self.session not in service[1]):
                return None
            return bytes([0x7F, req[0], NRC_BUSY_REPEAT])
        suppress = False
        try:
            service = self._services.get(req[0])
            _need(service is not None, NRC_SERVICE_NOT_SUPPORTED)
            handler, sessions, subfunction = service
            _need(self.session in sessions, NRC_SERVICE_NOT_IN_SESSION)
            _need(len(req) >= 2 or not (subfunction or req[0] == 0x19), NRC_INCORRECT_LENGTH)
            suppress = subfunction and bool(req[1] & 0x80)
            body = handler(req, now)
        except Nrc as e:
            if e.code == NRC_PENDING or not (functional and e.code in FUNCTIONAL_SILENT):
                return bytes([0x7F, req[0], e.code])
            return None
        return None if suppress else bytes([req[0] + 0x40]) + body

    def tick(self) -> bytes | None:
        """Pending routines (0x78 every 2 s, then the result) and S3."""
        now = time.monotonic()
        if self.pending is not None:
            routine, done_at, sent_at = self.pending
            if now >= done_at:
                self._finish(routine)
                self.s3_deadline = now + S3
                return bytes([0x71, 0x01]) + routine.to_bytes(2, "big") + self.last_result
            if now - sent_at >= PENDING_REPEAT_S:
                self.pending = (routine, done_at, now)
                return bytes([0x7F, 0x31, NRC_PENDING])
            return None
        if self.session != DEFAULT and now >= self.s3_deadline:
            logger.info("Demo ECU: S3 expired, back to the default session")
            self._enter(DEFAULT)
        return None

    def _finish(self, routine: int) -> None:
        if routine == RID_ERASE:
            address, size = self.erase
            offset = address - DOWNLOAD_ADDRESS
            self.download[offset : offset + size] = b"\xff" * size
            self.erased = (address, address + size)
            self.downloaded = None
            self.last_result = b"\x00"
        else:
            self.last_result = bytes([self.failing])
        self.last, self.pending = routine, None

    def _enter(self, session: int) -> None:
        """Every 0x10 and S3: relock, return the output, end a transfer."""
        self.session = session
        self.unlocked, self.seed = 0, 0
        self.override = None
        self.transfer = None
        if session == DEFAULT:
            self.communication, self.dtc_setting = 0x00, True

    # ─── Services ──────────────────────────────────────────────────────────

    def _session_control(self, req: bytes, now: float) -> bytes:
        session = req[1] & 0x7F
        _need(session in (DEFAULT, PROGRAMMING, EXTENDED), NRC_SUBFUNCTION_NOT_SUPPORTED)
        _need(len(req) == 2, NRC_INCORRECT_LENGTH)
        _need(session != PROGRAMMING or self.session != DEFAULT, NRC_CONDITIONS)
        self._enter(session)
        return bytes([session]) + struct.pack(">HH", P2_MS, P2_STAR_MS // 10)

    def _ecu_reset(self, req: bytes, now: float) -> bytes:
        kind = req[1] & 0x7F
        _need(kind in (0x01, 0x02, 0x03), NRC_SUBFUNCTION_NOT_SUPPORTED)
        _need(len(req) == 2, NRC_INCORRECT_LENGTH)
        # Answered before the reset: the response is built, the reset takes effect now,
        # and the next request finds the ECU booted.
        self._boot()
        return bytes([kind])

    def _tester_present(self, req: bytes, now: float) -> bytes:
        _need(req[1] & 0x7F == 0x00, NRC_SUBFUNCTION_NOT_SUPPORTED)
        _need(len(req) == 2, NRC_INCORRECT_LENGTH)
        return b"\x00"

    def _security_access(self, req: bytes, now: float) -> bytes:
        kind = req[1] & 0x7F
        level = kind if kind & 1 else kind - 1
        _need(level in KEY_XOR, NRC_SUBFUNCTION_NOT_SUPPORTED)
        wanted = PROGRAMMING if level == LEVEL_PROGRAMMING else EXTENDED
        _need(self.session == wanted, NRC_SUBFUNCTION_NOT_IN_SESSION)
        if kind == level:
            _need(len(req) == 2, NRC_INCORRECT_LENGTH)
            _need(now >= self.lockout_until[level], NRC_DELAY_NOT_EXPIRED)
            if self.lockout_until[level]:  # the delay over: a fresh set of attempts
                self.lockout_until[level], self.failed_keys[level] = 0, 0
            if self.unlocked == level:
                self.seed = 0
            else:
                while not self.seed:
                    self.seed = int.from_bytes(os.urandom(4), "big")
                self.seed_level = level
            return bytes([kind]) + self.seed.to_bytes(4, "big")
        _need(len(req) == 6, NRC_INCORRECT_LENGTH)
        _need(self.seed != 0 and self.seed_level == level, NRC_SEQUENCE)
        seed, self.seed = self.seed, 0  # spent either way
        if int.from_bytes(req[2:6], "big") != seed ^ KEY_XOR[level]:
            self.failed_keys[level] += 1
            if self.failed_keys[level] >= SECURITY_ATTEMPTS:
                self.lockout_until[level] = now + SECURITY_DELAY_S
                raise Nrc(NRC_ATTEMPTS_EXCEEDED)
            raise Nrc(NRC_INVALID_KEY)
        self.failed_keys[level] = 0
        self.unlocked = level
        return bytes([kind])

    def _communication_control(self, req: bytes, now: float) -> bytes:
        kind = req[1] & 0x7F
        _need(kind in (0x00, 0x01, 0x03), NRC_SUBFUNCTION_NOT_SUPPORTED)
        _need(len(req) == 3, NRC_INCORRECT_LENGTH)
        _need(req[2] == 0x01, NRC_OUT_OF_RANGE)
        _need(self.unlocked != 0, NRC_SECURITY_DENIED)
        self.communication = kind
        return bytes([kind])

    def _dtc_setting(self, req: bytes, now: float) -> bytes:
        kind = req[1] & 0x7F
        _need(kind in (0x01, 0x02), NRC_SUBFUNCTION_NOT_SUPPORTED)
        _need(len(req) == 2, NRC_INCORRECT_LENGTH)
        _need(self.unlocked != 0, NRC_SECURITY_DENIED)
        self.dtc_setting = kind == 0x01
        return bytes([kind])

    def _did(self, did: int) -> bytes | None:
        out_v, out_a, in_v, in_a, temp, _sp, _aux, uptime = self.state
        values = {
            0xF186: lambda: bytes([self.session]),
            0xF190: lambda: self.vin,
            0x0101: lambda: struct.pack(">f", out_v),
            0x0102: lambda: struct.pack(">h", _scaled(out_a, 0.1, -0x8000, 0x7FFF)),
            0x0103: lambda: struct.pack(">b", _scaled(temp, 1.0, -0x80, 0x7F)),
            0x0104: lambda: struct.pack(">I", uptime),
            0x0105: lambda: struct.pack(
                ">H", 0xFFFF if math.isnan(in_v) else _scaled(in_v, 0.1, 0, 0xFFFE)
            ),
            0x0106: lambda: struct.pack(">H", _scaled(in_a, 0.01, 0, 0xFFFF)),
            0x0200: lambda: struct.pack(">H", self.setpoint),
        }
        if did in IDENTIFICATION:
            return IDENTIFICATION[did]
        return values[did]() if did in values else None

    def _read_did(self, req: bytes, now: float) -> bytes:
        _need(len(req) >= 3 and (len(req) - 1) % 2 == 0, NRC_INCORRECT_LENGTH)
        out = bytearray()
        for i in range(1, len(req), 2):
            value = self._did(int.from_bytes(req[i : i + 2], "big"))
            if value is not None:
                out += req[i : i + 2] + value
        _need(bool(out), NRC_OUT_OF_RANGE)  # ISO 14229-1: the supported DIDs; 0x31 if none
        return bytes(out)

    def _write_did(self, req: bytes, now: float) -> bytes:
        _need(len(req) >= 4, NRC_INCORRECT_LENGTH)
        did = int.from_bytes(req[1:3], "big")
        size = {0xF190: len(VIN), 0x0200: 2}.get(did)
        _need(size is not None and self.session == EXTENDED, NRC_OUT_OF_RANGE)
        _need(self.unlocked == LEVEL_EXTENDED, NRC_SECURITY_DENIED)
        _need(len(req) == 3 + size, NRC_INCORRECT_LENGTH)
        value = req[3:]
        if did == 0xF190:
            _need(all(0x20 <= b <= 0x7E for b in value), NRC_OUT_OF_RANGE)
            self.vin = value
        else:
            setpoint = int.from_bytes(value, "big")
            _need(SETPOINT_MIN <= setpoint <= SETPOINT_MAX, NRC_OUT_OF_RANGE)
            self.setpoint = setpoint
        return req[1:3]

    def _memory(self, address: int, size: int) -> tuple[bytearray | bytes, int, bool] | None:
        """(window bytes, offset, writable) holding [address, address + size), or None."""
        windows = (
            (STATE_ADDRESS, STATE.pack(*self.state), False),
            (CALIBRATION_ADDRESS, self.calibration, True),
        )
        for base, data, writable in windows:
            if size > 0 and _within(base, len(data), address, size):
                return data, address - base, writable
        return None

    def _memory_request(self, req: bytes, minimum: int) -> tuple[int, int, int]:
        _need(len(req) >= minimum, NRC_INCORRECT_LENGTH)
        _need(req[1] in (0x44, 0x24, 0x14), NRC_OUT_OF_RANGE)
        size_len = req[1] >> 4
        _need(len(req) >= 6 + size_len, NRC_INCORRECT_LENGTH)
        address = int.from_bytes(req[2:6], "big")
        return address, int.from_bytes(req[6 : 6 + size_len], "big"), size_len

    def _read_memory(self, req: bytes, now: float) -> bytes:
        address, size, size_len = self._memory_request(req, 4)
        _need(len(req) == 6 + size_len, NRC_INCORRECT_LENGTH)
        window = self._memory(address, size)
        _need(window is not None, NRC_OUT_OF_RANGE)
        data, offset, _ = window
        return bytes(data[offset : offset + size])

    def _write_memory(self, req: bytes, now: float) -> bytes:
        address, size, size_len = self._memory_request(req, 5)
        _need(len(req) == 6 + size_len + size, NRC_INCORRECT_LENGTH)
        window = self._memory(address, size)
        _need(window is not None and window[2], NRC_OUT_OF_RANGE)
        _need(self.unlocked == LEVEL_EXTENDED, NRC_SECURITY_DENIED)
        data, offset, _ = window
        data[offset : offset + size] = req[6 + size_len :]
        return req[1 : 6 + size_len]

    def _clear_dtc(self, req: bytes, now: float) -> bytes:
        _need(len(req) == 4, NRC_INCORRECT_LENGTH)
        group = int.from_bytes(req[1:4], "big")
        if group == 0xFFFFFF:
            for d in self.dtcs:
                d.clear()
            return b""
        _need(group in DTCS, NRC_OUT_OF_RANGE)
        self.dtcs[DTCS.index(group)].clear()
        return b""

    def _read_dtc(self, req: bytes, now: float) -> bytes:
        kind = req[1]  # no suppressPosRsp here: bit 7 set is no sub-function
        pairs = list(zip(DTCS, self.dtcs, strict=True))
        if kind in (0x01, 0x02):
            _need(len(req) == 3, NRC_INCORRECT_LENGTH)
            hits = [(c, d) for c, d in pairs if d.status & req[2]]
            if kind == 0x01:
                return bytes([0x01, 0xFF, 0x01]) + len(hits).to_bytes(2, "big")
            return bytes([0x02, 0xFF]) + b"".join(_dtc(c, d) for c, d in hits)
        if kind in (0x03, 0x0A):
            _need(len(req) == 2, NRC_INCORRECT_LENGTH)
            if kind == 0x0A:
                return bytes([0x0A, 0xFF]) + b"".join(_dtc(c, d) for c, d in pairs)
            stored = (c.to_bytes(3, "big") + bytes([r]) for c, d in pairs if d.snapshot
                      for r in RECORDS)  # fmt: skip
            return b"\x03" + b"".join(stored)
        if kind in (0x04, 0x06):
            _need(len(req) == 6, NRC_INCORRECT_LENGTH)
            code, record = int.from_bytes(req[2:5], "big"), req[5]
            _need(code in DTCS, NRC_OUT_OF_RANGE)
            d = self.dtcs[DTCS.index(code)]
            head = bytes([kind]) + _dtc(code, d)
            if kind == 0x04:
                _need(record in RECORDS or record == 0xFF, NRC_OUT_OF_RANGE)
                if d.snapshot is None:
                    return head
                wanted = RECORDS if record == 0xFF else (record,)
                return head + b"".join(self._record(d, r) for r in wanted)
            _need(record in (0x01, 0x02, 0xFF), NRC_OUT_OF_RANGE)
            out = head
            if record != 0x02:
                out += bytes([0x01, d.occurrences])
            if record != 0x01:
                out += bytes([0x02, d.aging])
            return out
        raise Nrc(NRC_SUBFUNCTION_NOT_SUPPORTED)

    def _record(self, d: Dtc, record: int) -> bytes:
        """Snapshot record: number, DID count, each DID and its value. 0x00 / 0xF0 are
        OBD-II's frames: DIDs 0xF400 + PID (uds_obd_put_frame())."""
        frame = d.latest if record == RECORD_LATEST else d.snapshot
        assert frame is not None
        values, at = {}, 0
        for did in SNAPSHOT_DIDS:
            size = len(self._did(did))
            values[did], at = frame[at : at + size], at + size
        if record == RECORD_DIDS:
            items = [did.to_bytes(2, "big") + values[did] for did in SNAPSHOT_DIDS]
        else:
            items = [(0xF400 + pid).to_bytes(2, "big") + _pid(pid, values[did])
                     for pid, did in FRAME_PIDS]  # fmt: skip
        return bytes([record, len(items)]) + b"".join(items)

    def _io_control(self, req: bytes, now: float) -> bytes:
        _need(len(req) >= 4, NRC_INCORRECT_LENGTH)
        param = req[3]
        _need(int.from_bytes(req[1:3], "big") == 0x0300 and param <= 0x03, NRC_OUT_OF_RANGE)
        _need(len(req) == 4 + (2 if param == 0x03 else 0), NRC_INCORRECT_LENGTH)
        _need(self.unlocked == LEVEL_EXTENDED, NRC_SECURITY_DENIED)
        if param == 0x03:
            value = int.from_bytes(req[4:6], "big")
            _need(SETPOINT_MIN <= value <= SETPOINT_MAX, NRC_OUT_OF_RANGE)
            self.override = value
        else:
            self.override = (None, SETPOINT, self._output())[param]
        return req[1:4] + struct.pack(">H", self._output())

    def _routine_control(self, req: bytes, now: float) -> bytes:
        kind = req[1] & 0x7F
        _need(kind in (0x01, 0x02, 0x03), NRC_SUBFUNCTION_NOT_SUPPORTED)
        _need(len(req) >= 4, NRC_INCORRECT_LENGTH)
        rid = int.from_bytes(req[2:4], "big")
        if rid in (RID_ERASE, RID_CHECK):
            _need(self.session == PROGRAMMING, NRC_OUT_OF_RANGE)
            _need(kind == 0x01 or len(req) == 4, NRC_INCORRECT_LENGTH)
            (self._erase if rid == RID_ERASE else self._check)(kind, req[4:], now)
        else:
            _need(rid == RID_SELF_TEST and self.session == EXTENDED, NRC_OUT_OF_RANGE)
            _need(len(req) == 4, NRC_INCORRECT_LENGTH)
            if kind == 0x01:
                self.pending = (rid, now + SELF_TEST_S, now)
                raise Nrc(NRC_PENDING)
            _need(kind != 0x02 and self.last == rid, NRC_SEQUENCE)
        return bytes([kind]) + req[2:4] + self.last_result

    def _erase(self, kind: int, option: bytes, now: float) -> None:
        _need(len(option) in (0, 9), NRC_INCORRECT_LENGTH)
        _need(self.unlocked == LEVEL_PROGRAMMING, NRC_SECURITY_DENIED)
        if kind != 0x01:  # nothing runs between requests
            _need(kind == 0x03 and self.last == RID_ERASE, NRC_SEQUENCE)
            return
        _need(self.transfer is None, NRC_CONDITIONS)
        address, size = DOWNLOAD_ADDRESS, DOWNLOAD_SIZE
        if option:
            address, size = int.from_bytes(option[1:5], "big"), int.from_bytes(option[5:9], "big")
            valid = (
                option[0] == 0x44
                and size
                and _within(DOWNLOAD_ADDRESS, DOWNLOAD_SIZE, address, size)
            )
            _need(bool(valid), NRC_OUT_OF_RANGE)
        self.erase = (address, size)
        self.pending = (RID_ERASE, now + ERASE_S, now)
        raise Nrc(NRC_PENDING)

    def _check(self, kind: int, option: bytes, now: float) -> None:
        _need(kind != 0x01 or len(option) == 4, NRC_INCORRECT_LENGTH)
        _need(self.unlocked == LEVEL_PROGRAMMING, NRC_SECURITY_DENIED)
        if kind != 0x01:
            _need(kind == 0x03 and self.last == RID_CHECK, NRC_SEQUENCE)
            return
        _need(self.downloaded is not None, NRC_SEQUENCE)
        address, size = self.downloaded
        offset = address - DOWNLOAD_ADDRESS
        crc = zlib.crc32(self.download[offset : offset + size])
        ok = crc == int.from_bytes(option, "big")
        self.last, self.last_result = (
            RID_CHECK,
            bytes([0x00 if ok else 0x01]) + crc.to_bytes(4, "big"),
        )

    def _request_transfer(self, req: bytes, now: float) -> bytes:
        # ISO 14229-1 order: 0x13, 0x31 format, 0x13, 0x33, 0x31 range, 0x22, 0x70
        _need(len(req) >= 3, NRC_INCORRECT_LENGTH)
        address_len, size_len = req[2] & 0x0F, req[2] >> 4
        _need(req[1] == 0x00 and 1 <= address_len <= 4 and 1 <= size_len <= 4, NRC_OUT_OF_RANGE)
        _need(len(req) == 3 + address_len + size_len, NRC_INCORRECT_LENGTH)
        address = int.from_bytes(req[3 : 3 + address_len], "big")
        size = int.from_bytes(req[3 + address_len :], "big")
        _need(self.unlocked == LEVEL_PROGRAMMING, NRC_SECURITY_DENIED)
        _need(size and _within(DOWNLOAD_ADDRESS, DOWNLOAD_SIZE, address, size), NRC_OUT_OF_RANGE)
        _need(self.transfer is None, NRC_CONDITIONS)
        download = req[0] == 0x34
        if download:
            lo, hi = self.erased
            _need(_within(lo, hi - lo, address, size), NRC_DOWNLOAD_NOT_ACCEPTED)
            self.erased, self.downloaded = (0, 0), None  # written: no longer erased or checked
        self.transfer = (req[0], address, size)
        self.transfer_done, self.transfer_bsc, self.transfer_last = 0, 1, 0
        return bytes([LENGTH_FORMAT]) + BLOCK_LENGTH.to_bytes(2, "big")

    def _transfer_data(self, req: bytes, now: float) -> bytes:
        _need(len(req) >= 2, NRC_INCORRECT_LENGTH)
        _need(self.transfer is not None, NRC_SEQUENCE)
        sid, address, size = self.transfer
        bsc = req[1]
        repeat = self.transfer_done > 0 and bsc == (self.transfer_bsc - 1) & 0xFF
        _need(repeat or bsc == self.transfer_bsc, NRC_WRONG_BSC)
        at = address - DOWNLOAD_ADDRESS
        if sid == 0x35:
            _need(len(req) == 2, NRC_INCORRECT_LENGTH)
            if repeat:
                n = self.transfer_last
                start = at + self.transfer_done - n
            else:
                n = min(size - self.transfer_done, BLOCK_LENGTH - 2)
                _need(n > 0, NRC_SEQUENCE)
                start = at + self.transfer_done
                self.transfer_done += n
                self.transfer_last = n
                self.transfer_bsc = (self.transfer_bsc + 1) & 0xFF
            return bytes([bsc]) + bytes(self.download[start : start + n])
        n = len(req) - 2
        _need(n > 0, NRC_INCORRECT_LENGTH)
        if not repeat:
            _need(n <= size - self.transfer_done, NRC_TRANSFER_SUSPENDED)
            start = at + self.transfer_done
            self.download[start : start + n] = req[2:]
            self.transfer_done += n
            self.transfer_bsc = (self.transfer_bsc + 1) & 0xFF
        return bytes([bsc])

    def _transfer_exit(self, req: bytes, now: float) -> bytes:
        _need(len(req) == 1, NRC_INCORRECT_LENGTH)
        _need(self.transfer is not None and self.transfer_done == self.transfer[2], NRC_SEQUENCE)
        sid, address, size = self.transfer
        if sid == 0x34:
            self.downloaded = (address, size)
        self.transfer = None
        return b""


def _pid(pid: int, raw: bytes) -> bytes:
    """J1979 PID bytes from its DID's bytes (nodes/dcdc/src/uds.c)."""
    if pid == 0x1F:  # run time: uptime ms -> s
        return min(int.from_bytes(raw, "big") // 1000, 0xFFFF).to_bytes(2, "big")
    if pid == 0x42:  # control module voltage: float V -> mV
        return _scaled(struct.unpack(">f", raw)[0], 0.001, 0, 0xFFFF).to_bytes(2, "big")
    if pid == 0x46:  # ambient temperature: int8 degC -> A - 40
        return bytes([min(max(struct.unpack(">b", raw)[0] + 40, 0), 0xFF)])
    pack = int.from_bytes(raw, "big")  # 0x5B pack life: 0.1 V, 0 % at 250 V, 100 % at 400 V
    if pack == 0xFFFF:
        return b"\x00"
    life = min(max((pack * 0.1 - UNDERVOLTAGE_V) / (PACK_FULL_V - UNDERVOLTAGE_V), 0.0), 1.0)
    return bytes([_scaled(life, 1 / 255, 0, 255)])


def _dtc(code: int, d: Dtc) -> bytes:
    return code.to_bytes(3, "big") + bytes([d.status])
