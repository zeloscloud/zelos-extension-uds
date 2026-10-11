"""The DC-DC node's frames: its status, and the BMS_Limits it follows."""

from collections.abc import Iterable

import can

from zelos_testing import dbc
from zelos_testing.frames import count, until

DB = dbc.load("bench")
STATUS = DB.get_message_by_name("DCDC_Status")
LIMITS = DB.get_message_by_name("BMS_Limits")
PERIOD_S = STATUS.cycle_time / 1000
LIMITS_PERIOD_S = LIMITS.cycle_time / 1000


def input_current(msg: can.Message) -> float:
    """DCDC_Status.InputCurrent, to the signal's resolution."""
    return round(STATUS.decode(msg.data)["InputCurrent"], 2)


def cycles(bus: can.BusABC, n: int, ids: Iterable[int] = ()) -> list[can.Message]:
    """Frames on ids, with DCDC_Status, over the node's next n cycles."""
    return until(bus, lambda frames: count(frames, STATUS.frame_id) >= n, ids=[*ids, STATUS.frame_id])


def settle(bus: can.BusABC, amps: float) -> list[can.Message]:
    """DCDC_Status frames until InputCurrent reads `amps`."""
    return until(bus, lambda frames: input_current(frames[-1]) == amps, ids=[STATUS.frame_id])


class BmsLimits:
    """BMS_Limits as a BMS sends them, granting the allowance `aux`. Call for the next frame."""

    def __init__(self, aux: float):
        self.aux = aux
        self.counter = 0

    def __call__(self) -> can.Message:
        data = LIMITS.encode(
            {
                "DischargeCurrentLimit": 200.0,
                "ChargeCurrentLimit": 50.0,
                "AuxCurrentLimit": self.aux,
                "Counter": self.counter,
            }
        )
        self.counter = (self.counter + 1) & 0xFF
        return can.Message(arbitration_id=LIMITS.frame_id, data=data, is_extended_id=False)
