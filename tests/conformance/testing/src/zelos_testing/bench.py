"""Other devices on a shared bench bus, and taking the bus back from them.

A hardware bench may carry a CANopen manager of its own (a PLC): it sends SYNC,
heartbeats on 0x77F and manages the PDU. Suites detect it with
`foreign_canopen()`, failing closed: an operational PDU counts too. A module that must drive the PDU itself (NMT, SYNC) runs
under `BenchQuiet`, which pauses the PLC through a Modbus register written by a
Zelos agent action, and puts the register back as it found it afterwards.
"""

import json
import logging
import time
from dataclasses import dataclass

import can

logger = logging.getLogger(__name__)

SYNC = 0x080
# A CANopen manager's heartbeat: node-id 127, the NMT master's by convention.
MANAGER_HEARTBEAT = 0x77F
# The bench's CANopen node, the PDU (node-id 0x20).
PDU_HEARTBEAT = 0x700 + 0x20
OPERATIONAL = 0x05


@dataclass(frozen=True)
class ForeignCanopen:
    """What another device does on the bus before the suite sends anything."""

    manager: bool
    sync: bool
    node_operational: bool

    @property
    def present(self) -> bool:
        return self.manager or self.sync or self.node_operational


def foreign_canopen(bus: can.BusABC, window_s: float = 1.2) -> ForeignCanopen:
    """Listen for window_s: a manager heartbeat (0x77F), SYNC, or the PDU operational means a foreign CANopen master.

    The PDU boots pre-operational and only a manager starts it, so an
    operational one counts even with no manager heard. Call before this process
    sends SYNC or NMT itself: its own frames would count.
    """
    manager = sync = operational = False
    end = time.monotonic() + window_s
    while (left := end - time.monotonic()) > 0 and not (manager and sync and operational):
        msg = bus.recv(left)
        if msg is None or msg.is_extended_id or msg.is_error_frame:
            continue
        manager |= msg.arbitration_id == MANAGER_HEARTBEAT
        sync |= msg.arbitration_id == SYNC
        operational |= msg.arbitration_id == PDU_HEARTBEAT and msg.data[:1] == bytes([OPERATIONAL])
    return ForeignCanopen(manager=manager, sync=sync, node_operational=operational)


def wait_managed(bus: can.BusABC, node_heartbeat: int, timeout_s: float) -> bool:
    """Whether, within timeout_s, a SYNC comes and then the node's heartbeat says operational.

    After a takeover the PLC needs a moment to manage the node again; the
    operational heartbeat must follow a SYNC so a node a test left operational
    does not pass for a managed one.
    """
    sync = False
    end = time.monotonic() + timeout_s
    while (left := end - time.monotonic()) > 0:
        msg = bus.recv(left)
        if msg is None or msg.is_extended_id:
            continue
        sync |= msg.arbitration_id == SYNC
        if sync and msg.arbitration_id == node_heartbeat and msg.data[:1] == bytes([OPERATIONAL]):
            return True
    return False


READ_ACTION = "Modbus/read_named_register"
WRITE_ACTION = "Modbus/write_named_register"


@dataclass(frozen=True)
class QuietConfig:
    """How to reach the PLC's bench_quiet register through a Zelos agent's Modbus extension.

    agent: the agent's URL. device: the extension's device for the PLC (it
    carries the unit id). register: the register's name in the device map.
    mask: the bits that pause the PLC's CANopen manager; others in the
    register are left as found.
    """

    agent: str
    device: str
    register: str = "setpoints/bench_quiet"
    mask: int = 0b10

    def manual_restore(self, value: int) -> str:
        params = json.dumps({"device": self.device, "name": self.register, "value": value})
        return f"zelos actions --host {self.agent} execute {WRITE_ACTION} --params '{params}'"


class BenchQuietError(RuntimeError):
    pass


class BenchQuiet:
    """Pause the PLC for the block; leave its register as it was found.

    client.execute(action, params, timeout) returns a result with `.ok` and
    `.value`, as zelos_sdk's `Agent.actions` does. Every write is read back.
    Entry keeps the register's value and sets the mask's bits; exit writes the
    kept value back, also after a failure in the block. A failed restore raises
    with the command that restores it by hand.
    """

    def __init__(self, config: QuietConfig, client, timeout_s: float = 5.0):
        self.config, self.client, self.timeout_s = config, client, timeout_s
        self.snapshot: int | None = None

    def _execute(self, action: str, params: dict):
        result = self.client.execute(action, params, self.timeout_s)
        value = result.value
        if not result.ok or (isinstance(value, dict) and value.get("success") is False):
            raise BenchQuietError(f"{action} {params}: {value}")
        return value

    def _read(self) -> int:
        return int(self._execute(READ_ACTION, {"device": self.config.device, "name": self.config.register})["value"])

    def _set(self, value: int):
        self._execute(WRITE_ACTION, {"device": self.config.device, "name": self.config.register, "value": value})
        if (read := self._read()) != value:
            raise BenchQuietError(f"{self.config.register} reads {read} after writing {value}")

    def __enter__(self):
        self.snapshot = self._read()
        if self.snapshot & self.config.mask != self.config.mask:
            try:
                self._set(self.snapshot | self.config.mask)
            except BaseException:
                self._restore()
                raise
        return self

    def __exit__(self, *exc):
        self._restore()

    def _restore(self):
        if self.snapshot is None or self.snapshot & self.config.mask == self.config.mask:
            return
        try:
            self._set(self.snapshot)
        except Exception as e:
            command = self.config.manual_restore(self.snapshot)
            logger.error("bench_quiet not restored; restore it by hand: %s", command)
            raise BenchQuietError(f"bench_quiet not restored ({e}); restore it by hand: {command}") from e
