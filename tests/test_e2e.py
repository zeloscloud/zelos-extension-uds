"""End to end against the demo ECU on the zelos-can virtual bus, in-process.

Every action through the action functions the app registers, one CLI path,
two ECUs on one bus, serialization, S3 keep-alive, response pending, the
production flash with the demo's key file, the stop bound and reopen after a
bus failure. The demo's own conformance is tests/conformance.
"""

from __future__ import annotations

import contextlib
import json
import random
import struct
import subprocess
import sys
import threading
import time
import zlib
from pathlib import Path
from types import SimpleNamespace

import can
import pytest
import zelos_sdk
from helpers import wait_until

from zelos_extension_uds import actions, client, services
from zelos_extension_uds.cli.app import ADVANCED_DEFAULTS, create_ecus, share_buses
from zelos_extension_uds.cli.utils import cli_ecu, start_all, stop_all
from zelos_extension_uds.client import STOP_BOUND, State
from zelos_extension_uds.demo import KEY_FILE, DemoEcu
from zelos_extension_uds.demo import ecu as demo_ecu

ROOT = Path(__file__).parent.parent
DOWNLOAD = "0x00100000"
ERASE = "0xFF00"


@pytest.fixture(autouse=True)
def no_power_up_delay(monkeypatch):
    """The contract's 10 s security delay after each boot; tests skip it."""
    monkeypatch.setattr(demo_ecu, "POWER_UP_DELAY_S", 0.0)


@contextlib.contextmanager
def running(ecus_config: list[dict], trz: Path | None = None, **advanced):
    """The app's start and stop around `ecus_config`; asserts the stop bound and no leftovers."""
    before = set(threading.enumerate())
    with contextlib.ExitStack() as stack:
        source = None
        if trz is not None:
            stack.enter_context(zelos_sdk.TraceWriter(str(trz)))
            source = zelos_sdk.TraceSource("UDS")
        settings = {**ADVANCED_DEFAULTS, **advanced}
        ecus = create_ecus({"ecus": ecus_config}, settings)
        buses = share_buses(ecus)
        for ecu in ecus:
            if source is not None:
                ecu.trace_to("UDS", source)
            actions.UDS_ECUS[ecu.name] = ecu
        start_all(ecus, buses, settings["tester_present_s"])
        try:
            assert wait_until(lambda: all(e.state == State.CONNECTED for e in ecus))
            yield ecus
        finally:
            actions.UDS_ECUS.clear()
            t0 = time.monotonic()
            stop_all(ecus, buses)
            assert time.monotonic() - t0 < STOP_BOUND
    left = [t.name for t in set(threading.enumerate()) - before if t.name.startswith("uds-")]
    assert not left


@pytest.fixture
def demo():
    with running([{"interface": "Demo"}]) as ecus:
        yield ecus[0]


def ok(result: dict) -> dict:
    assert result["status"] == "success", result
    return result


def nrc(result: dict, code: int) -> None:
    assert result["status"] == "error" and result["nrc"] == code, result


def unlock(level: str = "0x01") -> None:
    session = "Extended Diagnostic Session" if level == "0x01" else "Programming Session"
    ok(actions.session_control("demo", "Extended Diagnostic Session"))
    if session != "Extended Diagnostic Session":
        ok(actions.session_control("demo", session))
    assert ok(actions.security_access("demo", level))["access_granted"]  # demo key file


# ─── Every action ───────────────────────────────────────────────────────────


def test_discovery_and_reads(demo):
    listed = actions.list_ecus()
    assert listed["count"] == 1 and listed["ecus"][0]["state"] == "connected"
    assert listed["ecus"][0]["interface"] == "Demo"
    assert actions.get_status("demo")["tx_id"] == "0x7E0"
    vin = ok(actions.read_did("demo", "F190"))
    assert bytes.fromhex(vin["data"][2:]).decode() == demo_ecu.VIN  # multi-frame response
    volts = ok(actions.read_did("demo", "0x0101"))["representations"]["float_be"]
    assert 12 < volts <= 13.8
    nrc(actions.read_did("demo", "0x1234"), 0x31)
    with pytest.raises(ValueError, match="Unknown ECU"):
        actions.read_did("nope", "F190")


def test_writes_security_io_and_reset(demo):
    nrc(actions.write_did("demo", "0x0200", "1300", "uint16"), 0x7F)  # default session
    ok(actions.session_control("demo", "Extended Diagnostic Session"))
    nrc(actions.write_did("demo", "0x0200", "1300", "uint16"), 0x33)
    nrc(actions.security_access("demo", "0x01", "00000000"), 0x24)  # a key with no seed
    unlock()
    assert ok(actions.security_access("demo", "0x01"))["operation"] == "already_unlocked"
    ok(actions.write_did("demo", "0x0200", "1300", "uint16"))
    assert ok(actions.read_did("demo", "0x0200"))["representations"]["uint16_be"] == 1300
    nrc(actions.write_did("demo", "0x0200", "999", "uint16"), 0x31)
    nrc(actions.write_did("demo", "0xF187", "00"), 0x31)  # read only

    ok(actions.tester_present("demo"))
    ok(actions.tester_present("demo", suppress_response=True))
    adjusted = ok(actions.io_control("demo", "0x0300", "Short Term Adjustment", "1500", "uint16"))
    assert adjusted["control_state"] == "0x05DC"
    assert (
        ok(actions.io_control("demo", "0x0300", "Return Control To ECU"))["control_state"]
        == "0x0514"
    )

    ok(actions.ecu_reset("demo", "Hard Reset"))
    assert ok(actions.read_did("demo", "F186"))["data"] == "0x01"
    assert ok(actions.read_did("demo", "0x0200"))["representations"]["uint16_be"] == 1380


def test_dtc_reports_and_control(demo):
    demo.demo.force[0] = True  # overtemperature failing
    assert wait_until(
        lambda: ok(actions.read_dtc("demo", status_mask="Test Failed"))["dtc_count"] == 1
    )
    assert ok(actions.read_dtc("demo", "Number By Status Mask", "Test Failed"))["dtc_count"] == 1
    assert ok(actions.read_dtc("demo", "Supported DTCs"))["dtc_count"] == 4
    ids = ok(actions.read_dtc("demo", "Snapshot Identification"))["records"]
    assert ids == [{"id": "0x0A9400", "record": 1}]
    snapshot = ok(actions.read_dtc("demo", "Snapshot By DTC", dtc="0A9400", record="1"))
    assert snapshot["records"].startswith("0x0105")  # record 01, 5 DIDs, 0x0101 first
    extended = ok(actions.read_dtc("demo", "Extended Data By DTC", dtc="0A9400"))
    assert extended["records"] == "0x01010200"  # one occurrence, aging 0
    nrc(actions.read_dtc("demo", "Snapshot By DTC", dtc="123456"), 0x31)

    unlock()
    ok(actions.control_dtc_setting("demo", "Off"))
    demo.demo.force[0] = None
    ok(actions.clear_dtc("demo"))
    time.sleep(0.2)  # cycles pass with DTC setting off: no test results recorded
    assert ok(actions.read_dtc("demo", "Number By Status Mask"))["dtc_count"] == 4  # 0x50 each
    ok(actions.control_dtc_setting("demo", "On"))
    ok(actions.communication_control("demo", "Disable Rx And Tx"))
    ok(actions.communication_control("demo", "Enable Rx And Tx"))
    nrc(actions.communication_control("demo", "Disable Rx Enable Tx"), 0x12)


def test_memory_by_address(demo):
    state = ok(actions.read_memory("demo", "0x00010000", "32"))
    assert struct.unpack("<7fI", bytes.fromhex(state["data"][2:]))[5] == pytest.approx(13.8)
    nrc(actions.read_memory("demo", "0x00030000", "4"), 0x31)
    unlock()
    ok(actions.write_memory("demo", "0x00020000", "3.0", "float", "little"))
    calibration = ok(actions.read_memory("demo", "0x00020000", "4"))
    assert calibration["representations"]["float_le"] == 3.0


def test_routine_answers_after_response_pending(demo):
    """Self-test answers 0x78 for 2 s: longer than P2 (1 s), within P2* (5 s)."""
    nrc(actions.routine_control("demo", "0x0201"), 0x7F)
    ok(actions.session_control("demo", "Extended Diagnostic Session"))
    result = ok(actions.routine_control("demo", "0x0201"))
    assert result["response_data"] == "0x00" and result["elapsed_ms"] >= 1900
    ok(actions.routine_control("demo", "0x0201", "Request Results"))


def test_flash_upload_and_download_by_hand(demo, tmp_path):
    image = random.Random(1).randbytes(5000)
    done = ok(actions.flash_firmware("demo", DOWNLOAD, erase_routine=ERASE, data=image.hex()))
    assert [s["step"] for s in done["steps"]] == [
        "session_extended", "session_programming", "security_access", "erase",
        "request_download", "transfer_data", "request_transfer_exit", "check_dependencies",
    ]  # fmt: skip
    assert done["block_size"] == 1024 and done["crc32"] == f"0x{zlib.crc32(image):08X}"
    out = tmp_path / "up.bin"
    up = ok(actions.upload_memory("demo", DOWNLOAD, "5000", str(out)))
    assert out.read_bytes() == image and up["crc32"] == done["crc32"]
    small = ok(actions.upload_memory("demo", DOWNLOAD, "16"))
    assert bytes.fromhex(small["data"][2:]) == image[:16]

    # By hand: erase, download, exit, check.
    ok(actions.routine_control("demo", ERASE))
    assert ok(actions.request_download("demo", DOWNLOAD, "4"))["max_block_size"] == 0x402
    nrc(actions.transfer_data("demo", "2", "00"), 0x73)
    ok(actions.transfer_data("demo", "1", "01 02 03 04"))
    ok(actions.request_transfer_exit("demo"))
    crc = zlib.crc32(bytes([1, 2, 3, 4]))
    check = ok(actions.routine_control("demo", "0xFF01", data=f"{crc:08X}"))
    assert check["response_data"].startswith("0x00")

    image_file = tmp_path / "fw.bin"
    image_file.write_bytes(image[:3000])
    # No erase unless asked: the written range refuses the download.
    unerased = actions.flash_firmware("demo", DOWNLOAD, file_path=str(image_file))
    assert unerased["failed_step"] == "request_download" and unerased["nrc"] == 0x70
    again = ok(actions.flash_firmware("demo", DOWNLOAD, erase_routine=ERASE, block_size=100,
                                      file_path=str(image_file), reset="Hard Reset"))  # fmt: skip
    assert again["blocks"] == 30 and again["steps"][-1]["step"] == "ecu_reset"
    assert ok(actions.read_did("demo", "F186"))["data"] == "0x01"

    failed = actions.flash_firmware("demo", "0x0", data=image.hex(), erase_routine=ERASE)
    assert failed["failed_step"] == "erase" and failed["nrc"] == 0x31  # outside the window


def test_flash_with_explicit_key_requests_a_seed_first(demo, monkeypatch):
    seed = 0x12345678
    monkeypatch.setattr(demo_ecu, "os", SimpleNamespace(urandom=lambda n: seed.to_bytes(n, "big")))
    key = f"{seed ^ demo_ecu.KEY_XOR[0x11]:08X}"
    done = ok(
        actions.flash_firmware("demo", DOWNLOAD, erase_routine=ERASE, data="00" * 16, key=key)
    )
    assert next(s for s in done["steps"] if s["step"] == "security_access")["status"] == "success"


def test_cli_against_the_demo():
    """The shell path, in its own process: the demo ECU runs inside it."""
    args = ["read", "--interface", "demo", "--txid", "7E0", "--rxid", "7E8", "--id", "F190"]
    done = subprocess.run(
        [sys.executable, "main.py", *args], cwd=ROOT, capture_output=True, text=True, timeout=30
    )
    assert done.returncode == 0, done.stderr
    assert bytes.fromhex(json.loads(done.stdout)["data"][2:]).decode() == demo_ecu.VIN


def test_cli_passes_any_python_can_interface_through():
    server = DemoEcu("uds-cli").start()
    try:
        with cli_ecu("zelos-virtual", "uds-cli", None, False, None, "7E0", "7E8", False) as ecu:
            assert ok(services.read_did(ecu, "F190"))["data"]
    finally:
        server.stop()


# ─── Transport ──────────────────────────────────────────────────────────────


def test_can_fd_and_extended_ids():
    """64-byte ISO-TP frames and 29-bit ids, end to end."""
    ecu = {"interface": "Demo", "fd_mode": True, "extended_ids": True}
    with running([{**ecu, "tx_id": "18DA10F1", "rx_id": "18DAF110"}]) as (demo,):
        bus, sent = demo.shared.bus, []
        bus.send = (lambda send: lambda m, timeout=None: (sent.append(m), send(m, timeout)))(
            bus.send
        )
        assert (
            bytes.fromhex(ok(actions.read_did("demo", "F190"))["data"][2:]).decode() == demo_ecu.VIN
        )
        image = random.Random(2).randbytes(3000)
        ok(actions.flash_firmware("demo", DOWNLOAD, erase_routine=ERASE, data=image.hex()))
        assert demo.demo.download[:3000] == image
        assert all(m.is_fd and m.is_extended_id and m.arbitration_id == 0x18DA10F1 for m in sent)
        assert max(len(m.data) for m in sent) == 64


def _other(channel: str, **ecu) -> dict:
    config = json.dumps({"interface": "zelos-virtual", "channel": channel})
    return {"interface": "Other (python-can)", "config_json": config, **ecu}


def test_slow_flow_control_long_blocks_within_p2():
    """ECU flow control STmin 8 ms: a 1026-byte block takes over a second to send, longer
    than P2 (1 s), which starts after the last frame."""
    server = DemoEcu("uds-slow", stmin=8).start()
    try:
        ecu = _other("uds-slow", name="demo", tx_id="7E0", rx_id="7E8", key_file=str(KEY_FILE))
        with running([ecu]):
            image = random.Random(3).randbytes(4096)
            result = ok(
                actions.flash_firmware("demo", DOWNLOAD, erase_routine=ERASE, data=image.hex())
            )
            assert result["block_size"] == 1024 and server.download[:4096] == image
    finally:
        server.stop()


def test_p2_bounds_the_start_of_a_long_response():
    """Our flow control asks for STmin 5 ms: a 1026-byte upload block takes about 0.75 s
    to arrive, its first frame within P2 (0.3 s). udsoncan alone times it out."""
    with running([{"interface": "Demo"}], p2_timeout=0.3, isotp_stmin=5):
        ok(actions.session_control("demo", "Extended Diagnostic Session"))
        ok(actions.session_control("demo", "Programming Session"))
        assert ok(actions.security_access("demo", "0x11"))["access_granted"]
        up = ok(actions.upload_memory("demo", DOWNLOAD, "2048"))
        assert up["size"] == 2048


def test_two_ecus_share_one_bus():
    servers = [
        DemoEcu("uds-shared", request_id=0x7E0, response_id=0x7E8).start(),
        DemoEcu("uds-shared", request_id=0x7E1, response_id=0x7E9, functional_id=None).start(),
    ]
    try:
        configs = [
            _other("uds-shared", name="a", tx_id="7E0", rx_id="7E8"),
            _other("uds-shared", name="b", tx_id="7E1", rx_id="7E9"),
        ]
        with running(configs) as (a, b):
            assert a.shared is b.shared
            ok(actions.session_control("b", "Extended Diagnostic Session"))
            assert ok(actions.read_did("a", "F186"))["data"] == "0x01"
            assert ok(actions.read_did("b", "F186"))["data"] == "0x03"
    finally:
        for server in servers:
            server.stop()


# ─── Lifecycle ──────────────────────────────────────────────────────────────


def test_concurrent_actions_serialize(demo):
    ok(actions.session_control("demo", "Extended Diagnostic Session"))
    ok(actions.periodic_tester_present("demo", True, 0.5))
    results: list[dict] = []

    def work(n: int) -> None:
        if n % 4 == 0:
            image = bytes([n]) * 3000
            results.append(
                actions.flash_firmware(
                    "demo", DOWNLOAD, erase_routine=ERASE, data=image.hex(), block_size=256
                )
            )
        else:
            results.append(actions.read_did("demo", "F190"))

    threads = [threading.Thread(target=work, args=(n,)) for n in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert len(results) == 12 and all(r["status"] == "success" for r in results), results
    assert demo.counts["timeouts"] == 0 and demo.counts["errors"] == 0


def test_concurrent_tester_present_enables_leave_one_thread(demo):
    def tp_threads():
        return [t for t in threading.enumerate() if t.name == "uds-tp-demo" and t.is_alive()]

    for _ in range(20):
        barrier = threading.Barrier(3)

        def enable(barrier=barrier):
            barrier.wait()
            actions.periodic_tester_present("demo", True, 0.5)

        threads = [threading.Thread(target=enable) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(tp_threads()) == 1
    actions.periodic_tester_present("demo", False, 0.5)
    assert not tp_threads()


def test_periodic_tester_present_holds_the_session(demo, monkeypatch):
    monkeypatch.setattr(demo_ecu, "S3", 1.0)
    ok(actions.session_control("demo", "Extended Diagnostic Session"))
    assert ok(actions.periodic_tester_present("demo", True, 0.5))["state"] == "started"
    time.sleep(2.5)
    assert ok(actions.read_did("demo", "F186"))["data"] == "0x03"
    assert ok(actions.periodic_tester_present("demo", False, 0.5))["state"] == "stopped"
    time.sleep(1.5)
    assert ok(actions.read_did("demo", "F186"))["data"] == "0x01"


def test_stop_with_a_request_in_flight(monkeypatch):
    """A routine waiting on response-pending and periodic TP queued behind it: the bus
    still closes within the bound."""
    monkeypatch.setattr(demo_ecu, "SELF_TEST_S", 4.5)
    before = set(threading.enumerate())
    ecus = create_ecus({"ecus": [{"interface": "Demo"}]}, ADVANCED_DEFAULTS)
    buses = share_buses(ecus)
    start_all(ecus, buses, 0.5)
    (ecu,) = ecus
    assert wait_until(lambda: ecu.state == State.CONNECTED)
    from zelos_extension_uds import services

    ok(services.session_control(ecu, "Extended Diagnostic Session"))
    results: list[dict] = []
    routine = threading.Thread(
        target=lambda: results.append(services.routine_control(ecu, "0x0201", "Start Routine"))
    )
    routine.start()
    time.sleep(0.8)
    t0 = time.monotonic()
    stop_all(ecus, buses)
    assert time.monotonic() - t0 < STOP_BOUND
    assert buses[0].bus is None and not buses[0]._thread.is_alive()
    routine.join(10)
    assert results[0]["status"] == "error"
    left = [t.name for t in set(threading.enumerate()) - before if t.name.startswith("uds-")]
    assert not left


def _rows(trz: Path, event: str) -> dict[str, list]:
    import pyarrow as pa

    with zelos_sdk.TraceReader(str(trz)) as reader:
        span = reader.time_range()
        for seg in reader.list_data_segments():
            fields = [
                f.path
                for src in reader.list_fields(seg.id)
                for ev in src.events
                if f"{src.name}/{ev.name}" == f"UDS/demo/{event}"
                for f in ev.fields
            ]
            if fields:
                result = reader.query(
                    data_segment_ids=[seg.id], fields=fields, start=span.start, end=span.end
                )
                table = pa.ipc.open_stream(result.to_arrow()).read_all()
    return {n.rsplit(".", 1)[-1]: table.column(n).to_pylist() for n in table.column_names}


def _send_fails(*_args, **_kwargs):
    raise OSError("send failed")


def test_trace_rows_and_counters(tmp_path, monkeypatch):
    """tx: the request after the SID; rx: the response after the SID (0x7F's too)."""
    trz = tmp_path / "uds.trz"
    with running([{"interface": "Demo"}], trz):
        ok(actions.read_did("demo", "F190"))
        nrc(actions.read_did("demo", "0x1234"), 0x31)
        ok(actions.read_dtc("demo", status_mask="Confirmed DTC"))
        assert "not a hex number" in actions.read_did("demo", "zz")["error"]  # nothing sent
        with monkeypatch.context() as m:  # a failed send: neither counted nor traced
            m.setattr(client.PythonIsoTpConnection, "send", _send_fails)
            assert "send failed" in actions.read_did("demo", "F190")["error"]
        metrics = actions.get_status("demo")["metrics"]
    assert metrics["requests"] == 3 and metrics["responses"] == 3
    assert metrics["positive"] == 2 and metrics["negative"] == 1
    tx, rx = _rows(trz, "tx"), _rows(trz, "rx")
    assert tx["data"] == [b"\xf1\x90", b"\x12\x34", b"\x02\x08"]
    assert tx["parameter"] == [0xF190, 0x1234, 0x02]
    assert rx["nrc"] == [0, 0x31, 0] and rx["success"] == [True, False, True]
    assert rx["data"][0] == b"\xf1\x90" + demo_ecu.VIN.encode() and rx["data"][1] == b"\x22\x31"


def test_action_schemas_require_only_what_has_no_default():
    import inspect as pyinspect

    class Registry:
        def register(self, *_args, **_kwargs):
            pass

    for name in actions.register_actions(Registry()):
        func = getattr(actions, name)
        params = pyinspect.signature(func).parameters.values()
        needed = {p.name for p in params if p.default is pyinspect.Parameter.empty}
        assert set(func._action.to_schema().get("required", [])) == needed, name


def test_auto_config_ships_the_demo_key_file(tmp_path):
    (ecu,) = actions.auto_config()["config"]["ecus"]
    assert Path(ecu["key_file"]) == KEY_FILE and KEY_FILE.is_file()
    bad = tmp_path / "bad.py"
    bad.write_text("x = 1\n")
    with pytest.raises(SystemExit):
        create_ecus({"ecus": [{"interface": "Demo", "key_file": str(bad)}]}, ADVANCED_DEFAULTS)


def test_permanent_open_error_not_retried():
    ecus = create_ecus(
        {"ecus": [{"interface": "Other (python-can)", "name": "x", "tx_id": "7E0", "rx_id": "7E8",
                   "config_json": '{"interface": "no-such-interface", "channel": "x"}'}]},
        ADVANCED_DEFAULTS,
    )  # fmt: skip
    buses = share_buses(ecus)
    start_all(ecus, buses, None)
    try:
        assert wait_until(lambda: ecus[0].state == State.ERROR)
        assert buses[0].join(1.0) and buses[0].reopens == 0
    finally:
        stop_all(ecus, buses)


def test_reopen_after_bus_failure(monkeypatch):
    monkeypatch.setattr(client, "RECONNECT_INITIAL", 0.3)
    with running([{"interface": "Demo"}]) as (ecu,):
        shared, broken = ecu.shared, ecu.shared.bus

        def down(timeout):
            raise can.CanOperationError("Network is down")

        broken.shutdown()
        monkeypatch.setattr(broken, "_recv_internal", down)
        assert wait_until(lambda: ecu.state == State.ERROR)
        t0 = time.monotonic()
        failed = actions.read_did("demo", "F190")
        assert "Network is down" in failed["error"] and time.monotonic() - t0 < 0.1
        assert wait_until(lambda: ecu.state == State.CONNECTED)
        assert shared.bus is not broken and shared.reopens == 1
        ok(actions.read_did("demo", "F190"))
