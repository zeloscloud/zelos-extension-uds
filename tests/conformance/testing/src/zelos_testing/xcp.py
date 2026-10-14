"""An ECU over XCP on CAN, as a test drives it.

zelos-can opens the bus, pyxcp is the XCP master, the A2L names every object,
and what the ECU measures is logged into the test's Zelos trace.
"""

import contextlib
import logging
import os
import re
import struct
import time
from pathlib import Path
from types import SimpleNamespace

import zelos_sdk
from pyxcp.config import General, Transport
from pyxcp.daq_stim import DaqList, DaqOnlinePolicy
from pyxcp.master import Master
from pyxcp.types import XcpResponseError
from traitlets.config import Config
from zelos_can import a2l
from zelos_can.bus import open_python_can_bus, prepare_bus_config

__all__ = ["Ecu", "XcpResponseError"]

# pyxcp stamps each master with the local time zone and fails on abbreviations such as PST.
os.environ["TZ"] = "UTC"
time.tzset()

# Every object on this ECU is a little-endian float.
FLOAT = struct.Struct("<f")


class Ecu:
    """Connected to the ECU the A2L describes, on a SocketCAN channel. Use as a context manager."""

    def __init__(self, channel: str, a2l_path: Path, timeout_s: float = 2.0):
        self.channel = channel
        self.a2l_path = Path(a2l_path)
        self.timeout_s = timeout_s
        self.a2l = a2l.load(self.a2l_path)
        self.event = self.a2l["events"][0]
        # XCP time units 0-9: 1 ns to 1 s, in decades.
        self.event_period_s = self.event["cycle"] * 10.0 ** (self.event["cycle_unit"] - 9)
        self.trace = zelos_sdk.TraceSourceCache(self.a2l["module"])
        self.daq = Recorder(self.trace)

    def __enter__(self):
        can_ids = next(t for t in self.a2l["transports"] if t["protocol"] == "CAN")
        c = Config()
        c.Transport.timeout = self.timeout_s
        c.Transport.Can.interface = "virtual"  # checked by pyxcp, unused: it gets our bus
        c.Transport.Can.can_id_master = can_ids["can_id_master"]
        c.Transport.Can.can_id_slave = can_ids["can_id_slave"]
        c.General.disable_error_handling = True  # raise XCP errors to the test, no retries
        config = SimpleNamespace(general=General(config=c), transport=Transport(config=c))
        self.bus = open_python_can_bus(prepare_bus_config({"interface": "zelos-socketcan", "channel": self.channel}), "ecu")
        try:
            self.master = Master("can", config, policy=self.daq, transport_layer_interface=self.bus)
            self.master.transport.connect()  # filters the bus, starts receiving
            self.master.connect()
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *exc):
        try:
            if hasattr(self, "master"):
                with contextlib.suppress(Exception):
                    self.master.freeDaq()  # leave no DAQ running for whoever connects next
                    self.master.disconnect()
                self.master.close()
        finally:
            self.bus.shutdown()

    def address(self, name: str) -> int:
        """A measurement's address, or a characteristic's (zelos-can's A2L reader carries measurements only)."""
        found = next((m["address"] for m in self.a2l["measurements"] if m["name"] == name), None)
        if found is None:
            text = self.a2l_path.read_text()
            found = int(re.search(rf"/begin CHARACTERISTIC {name}\s+\"[^\"]*\"\s+\w+\s+(0x[0-9A-Fa-f]+)", text).group(1), 16)
        return found

    def epk(self) -> str:
        """The EPK the ECU holds where the A2L says."""
        epk = self.a2l["epk"]
        self.master.setMta(epk["address"])
        return self.master.fetch(len(epk["string"])).decode()

    def read(self, name: str) -> float:
        return FLOAT.unpack(self.master.shortUpload(FLOAT.size, self.address(name)))[0]

    def write(self, name: str, value: float):
        self.master.setMta(self.address(name))
        self.master.download(FLOAT.pack(value))

    @contextlib.contextmanager
    def measuring(self, *names: str):
        """DAQ of names on the A2L's event, ECU-timestamped (stim off), into the trace under the event's name."""
        measurements = [(n, self.address(n), 0, "F32") for n in names]
        self.daq.daq_lists = [DaqList(self.event["name"], self.event["channel"], False, True, measurements)]
        self.daq.ecu_times = []
        self.daq.setup()
        self.daq.start()
        try:
            self.daq.wait(1, self.timeout_s)  # so the trace has a value from the start
            yield self.daq
        finally:
            self.daq.stop()


class Recorder(DaqOnlinePolicy):
    """Logs each DAQ sample into the trace; keeps the ECU's timestamp of each, in seconds."""

    def __init__(self, trace):
        # With a logger, pyxcp does not build its app from the command line, pytest's here.
        super().__init__([], logger=logging.getLogger("pyxcp.daq"))
        self.pid_off = False
        self.trace = trace
        self.ecu_times = []

    def wait(self, n: int, timeout_s: float) -> list[float]:
        """The ECU times of the first n samples."""
        end = time.monotonic() + timeout_s
        while len(self.ecu_times) < n:
            assert time.monotonic() < end, f"{len(self.ecu_times)} of {n} DAQ samples in {timeout_s:.0f} s"
            time.sleep(0.01)
        return self.ecu_times[:n]

    def on_daq_list(self, daq_list, host_ns, ecu_ns, values):
        lst = self.daq_lists[daq_list]
        self.ecu_times.append(ecu_ns / 1e9)
        self.trace.log(lst.name, {name: value for (name, _), value in zip(lst.headers, values)})
