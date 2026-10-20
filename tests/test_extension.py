"""Integration sanity checks: the extension, started as the app starts it, against its own
demo ECU on the zelos-can virtual bus (`can`) and behind the DoIP entity simulator (`doip`)."""

from __future__ import annotations

import contextlib
import json
import random
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import can
import pyarrow as pa
import pytest
import zelos_sdk
from doip_entity import EID, PORT, DoipEntity
from zelos_sdk.extensions import ConfigValidationError, load_config

from zelos_extension_uds import actions, client
from zelos_extension_uds.cli.app import create_ecus, migrate_legacy, resolve_advanced, share_buses
from zelos_extension_uds.cli.utils import start_all, stop_all
from zelos_extension_uds.client import STOP_BOUND, State
from zelos_extension_uds.demo import KEY_FILE, DemoEcu
from zelos_extension_uds.demo import ecu as demo_ecu

ROOT = Path(__file__).parent.parent
VIN = demo_ecu.VIN.encode()
DOWNLOAD, ERASE = "0x00100000", "0xFF00"
OVERTEMPERATURE = "0x0A9400"
PCAN = {
    "interface": "PCAN",
    "channel": "PCAN_USBBUS1",
    "bitrate": 500000,
    "tx_id": "7E0",
    "rx_id": "7E8",
}


def wait_until(pred, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not (val := pred()) and time.monotonic() < deadline:
        time.sleep(0.01)
    return val


def ok(result: dict) -> dict:
    assert result["status"] == "success", result
    return result


def nrc(result: dict, code: int) -> None:
    assert result["status"] == "error" and result.get("nrc") == code, result


@pytest.fixture(autouse=True)
def no_power_up_delay(monkeypatch):
    """The demo's 10 s security delay after each boot."""
    monkeypatch.setattr(demo_ecu, "POWER_UP_DELAY_S", 0.0)


def _can(channel: str, name: str = "ecu", **ecu) -> dict:
    config_json = json.dumps({"interface": "zelos-virtual", "channel": channel})
    return {"interface": "Other (python-can)", "name": name, "config_json": config_json,
            "tx_id": "7E0", "rx_id": "7E8", "key_file": str(KEY_FILE), **ecu}  # fmt: skip


@pytest.fixture(params=["can", "doip"])
def target(request):
    """The demo ECU and the ECU config that reaches it. `sent()`: what we sent it (CAN: our
    frames on 0x7E0; DoIP: the length of each diagnostic message)."""
    if request.param == "can":
        channel = f"uds-{uuid.uuid4().hex[:8]}"
        server = DemoEcu(channel).start()
        wire = can.Bus(interface="zelos-virtual", channel=channel, receive_own_messages=False)
        seen: list[can.Message] = []
        notifier = can.Notifier(wire, [seen.append], timeout=0.1)
        yield SimpleNamespace(
            kind="can", config=_can(channel), server=server, wire=wire,
            sent=lambda: [bytes(m.data) for m in seen if m.arbitration_id == 0x7E0],
        )  # fmt: skip
        notifier.stop(timeout=1.0)
        wire.shutdown()
        server.stop()
    else:
        entity = DoipEntity(port=0, udp_port=None).start()
        doip = {"host": "127.0.0.1", "port": entity.port, "ecu_address": "0x1001"}
        yield SimpleNamespace(
            kind="doip", server=entity.ecu,
            config={"interface": "DoIP", "name": "ecu", "key_file": str(KEY_FILE), "doip": doip},
            sent=lambda: [n for way, n in entity.diagnostics if way == "in"],
        )  # fmt: skip
        entity.stop()


def load(tmp_path: Path, monkeypatch, config: dict) -> tuple[dict, dict]:
    """The app's config path: config.json through the schema, the 0.1.x shim, Advanced."""
    (tmp_path / "config.json").write_text(json.dumps(config))
    monkeypatch.setenv("ZELOS_CONFIG_PATH", str(tmp_path / "config.json"))
    monkeypatch.chdir(ROOT)
    config = migrate_legacy(load_config())
    return config, resolve_advanced(config)


@contextlib.contextmanager
def started(tmp_path: Path, monkeypatch, config: dict, trz: Path | None = None):
    """Start as run_app_mode does; on exit, stop within the bound and leave no threads."""
    config, advanced = load(tmp_path, monkeypatch, config)
    before = set(threading.enumerate())
    with contextlib.ExitStack() as stack:
        source = None
        if trz is not None:
            stack.enter_context(zelos_sdk.TraceWriter(str(trz)))
            source = zelos_sdk.TraceSource("UDS")
        ecus = create_ecus(config, advanced)
        buses = share_buses(ecus)
        for ecu in ecus:
            if source is not None:
                ecu.trace_to("UDS", source)
            actions.UDS_ECUS[ecu.name] = ecu
        start_all(ecus, buses, advanced["tester_present_s"])
        try:
            yield ecus
        finally:
            actions.UDS_ECUS.clear()
            t0 = time.monotonic()
            stop_all(ecus, buses)
            assert time.monotonic() - t0 < STOP_BOUND
    left = [t.name for t in set(threading.enumerate()) - before if t.name.startswith("uds-")]
    assert not left


def connected(ecus) -> None:
    assert wait_until(lambda: all(e.state == State.CONNECTED for e in ecus))


def did(ecu: str, ident: str) -> bytes:
    return bytes.fromhex(ok(actions.read_did(ecu, ident))["data"][2:])


def _rows(trz: Path, event: str) -> dict[str, list]:
    """`event`'s rows, across data segments (a new one when a source re-announces)."""
    tables = []
    with zelos_sdk.TraceReader(str(trz)) as reader:
        span = reader.time_range()
        for seg in reader.list_data_segments():
            fields = [f.path for src in reader.list_fields(seg.id) for ev in src.events
                      if f"{src.name}/{ev.name}" == event for f in ev.fields]  # fmt: skip
            if fields:
                result = reader.query(
                    data_segment_ids=[seg.id], fields=fields, start=span.start, end=span.end
                ).to_arrow()
                if result:
                    tables.append(pa.ipc.open_stream(result).read_all())
    table = pa.concat_tables(tables)
    return {n.rsplit(".", 1)[-1]: table.column(n).to_pylist() for n in table.column_names}


def test_starts_from_config_and_decodes_into_trace_and_results(target, tmp_path, monkeypatch):
    trz = tmp_path / "uds.trz"
    with started(tmp_path, monkeypatch, {"ecus": [target.config]}, trz) as ecus:
        connected(ecus)
        assert actions.list_ecus()["ecus"][0]["state"] == "connected"
        assert did("ecu", "F190") == VIN
        target.server.force[0] = True  # overtemperature failing
        assert wait_until(
            lambda: ok(actions.read_dtc("ecu", status_mask="Test Failed"))["dtc_count"] == 1
        )
        (dtc,) = ok(actions.read_dtc("ecu", status_mask="Test Failed"))["dtcs"]
        assert dtc["id"] == OVERTEMPERATURE and int(dtc["status"], 16) & 0x01
    tx, rx = _rows(trz, "UDS/ecu/tx"), _rows(trz, "UDS/ecu/rx")
    assert tx["data"][0] == b"\xf1\x90" and tx["parameter"][0] == 0xF190
    assert rx["data"][0] == b"\xf1\x90" + VIN and rx["success"][0] and rx["nrc"][0] == 0
    assert tx["data"][-1] == b"\x02\x01"  # report by status mask, testFailed
    assert rx["data"][-1][:1] == b"\x02" and b"\x0a\x94\x00" in rx["data"][-1]


def test_session_and_security_gate(target, tmp_path, monkeypatch):
    monkeypatch.setattr(demo_ecu, "S3", 1.0)
    with started(tmp_path, monkeypatch, {"ecus": [target.config]}) as ecus:
        connected(ecus)
        nrc(actions.write_did("ecu", "0x0200", "1300", "uint16"), 0x7F)  # default session
        ok(actions.session_control("ecu", "Extended Diagnostic Session"))
        assert did("ecu", "F186") == b"\x03"
        nrc(actions.write_did("ecu", "0x0200", "1300", "uint16"), 0x33)  # locked
        assert ok(actions.security_access("ecu", "0x01"))["access_granted"]  # key file
        ok(actions.write_did("ecu", "0x0200", "1300", "uint16"))
        assert ok(actions.read_did("ecu", "0x0200"))["representations"]["uint16_be"] == 1300
        # Periodic tester present holds the session past S3; without it, it lapses.
        ok(actions.periodic_tester_present("ecu", True, 0.3))
        time.sleep(2.0)
        assert did("ecu", "F186") == b"\x03"
        ok(actions.periodic_tester_present("ecu", False))
        time.sleep(1.5)  # a request would restart S3: read once
        assert did("ecu", "F186") == b"\x01"
        ok(actions.session_control("ecu", "Extended Diagnostic Session"))
        nrc(actions.write_did("ecu", "0x0200", "1300", "uint16"), 0x33)  # relocked


def test_every_action_once(target, tmp_path, monkeypatch):
    """Each registered action succeeds once. On CAN, P2 0.3 s and our STmin 5 ms make an
    upload block take longer than P2 to arrive: P2 bounds its start, not its end."""
    monkeypatch.setattr(client, "RECONNECT_INITIAL", 0.3)  # DoIP: reconnect after the reset
    called: set[str] = set()

    def call(name: str, *args, **kwargs) -> dict:
        called.add(name)
        result = getattr(actions, name)(*args, **kwargs)
        assert "error" not in result and result.get("status", "success") == "success", result
        return result

    config = {"ecus": [target.config], "advanced": {"p2_timeout": 0.3, "isotp_stmin": 5}}
    image = random.Random(1).randbytes(3000)
    results: list[dict] = []
    with started(tmp_path, monkeypatch, config) as ecus:
        connected(ecus)
        call("list_ecus")
        call("get_status", "ecu")
        call("list_interfaces")
        assert Path(call("auto_config")["config"]["ecus"][0]["key_file"]) == KEY_FILE
        call("read_did", "ecu", "F190")
        call("tester_present", "ecu")
        call("periodic_tester_present", "ecu", True, 0.5)
        call("periodic_tester_present", "ecu", False)
        call("session_control", "ecu", "Extended Diagnostic Session")
        call("security_access", "ecu", "0x01")
        call("write_did", "ecu", "0x0200", "1300", "uint16")
        assert call("io_control", "ecu", "0x0300", "Short Term Adjustment", "1500", "uint16")[
            "control_state"
        ] == "0x05DC"  # fmt: skip
        assert call("routine_control", "ecu", "0x0201")["response_data"] == "0x00"  # after 0x78
        call("read_dtc", "ecu")
        call("clear_dtc", "ecu")
        call("control_dtc_setting", "ecu", "Off")
        call("control_dtc_setting", "ecu", "On")
        call("communication_control", "ecu", "Disable Rx And Tx")
        call("communication_control", "ecu", "Enable Rx And Tx")
        call("read_memory", "ecu", "0x00010000", "32")
        call("write_memory", "ecu", "0x00020000", "3.0", "float", "little")
        assert call("read_memory", "ecu", "0x00020000", "4")["representations"]["float_le"] == 3.0
        flashed = call("flash_firmware", "ecu", DOWNLOAD, data=image.hex(), erase_routine=ERASE)
        assert flashed["steps"][-1]["step"] == "check_dependencies"
        unerased = actions.flash_firmware("ecu", DOWNLOAD, data=image.hex())  # no erase asked
        assert unerased["failed_step"] == "request_download" and unerased["nrc"] == 0x70
        up = call("upload_memory", "ecu", DOWNLOAD, "2048")
        assert bytes.fromhex(up["data"][2:]) == image[:2048]
        call("request_upload", "ecu", DOWNLOAD, "4")
        assert call("transfer_data", "ecu", "1")["data"] == f"0x{image[:4].hex().upper()}"
        call("request_transfer_exit", "ecu")
        call("routine_control", "ecu", ERASE)
        call("request_download", "ecu", DOWNLOAD, "4")
        call("transfer_data", "ecu", "1", "01 02 03 04")
        call("request_transfer_exit", "ecu")
        call("ecu_reset", "ecu", "Hard Reset")
        assert wait_until(lambda: actions.read_did("ecu", "F186").get("data") == "0x01")

        # Concurrent actions serialize on the ECU.
        threads = [threading.Thread(target=lambda: results.append(actions.read_did("ecu", "F190")))
                   for _ in range(8)]  # fmt: skip
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        assert [r["status"] for r in results] == ["success"] * 8

        # Stop with a request in flight (the self-test's 0x78 wait): the bound holds.
        ok(actions.session_control("ecu", "Extended Diagnostic Session"))
        pending = threading.Thread(
            target=lambda: results.append(actions.routine_control("ecu", "0x0201"))
        )
        pending.start()
        time.sleep(0.5)
    pending.join(10)
    assert results[-1]["status"] == "error"
    assert called == set(actions.register_actions(SimpleNamespace(register=lambda *a, **k: None)))


def test_idle_sends_nothing(target, tmp_path, monkeypatch):
    """Connected and idle: nothing to the ECU, even while another tester's multi-frame
    response passes on our response id (CAN). A request then sends only itself."""
    with started(tmp_path, monkeypatch, {"ecus": [target.config]}) as ecus:
        connected(ecus)
        if target.kind == "can":
            ff = can.Message(arbitration_id=0x7E8, is_extended_id=False,
                             data=bytes.fromhex("101462F190") + VIN[:3])  # fmt: skip
            for _ in range(5):
                target.wire.send(ff)
                time.sleep(0.2)
        else:
            time.sleep(1.0)
        assert target.sent() == []
        assert did("ecu", "F190") == VIN
        time.sleep(0.2)
        if target.kind == "can":  # request and our flow control, padded to DLC 8 with 0xCC
            assert target.sent() == [
                b"\x03\x22\xf1\x90" + b"\xcc" * 4,
                b"\x30\x00\x00" + b"\xcc" * 5,
            ]
        else:
            assert target.sent() == [3]


@pytest.mark.parametrize(
    "ecus",
    [
        [{"interface": "Nope"}],
        [{**PCAN, "tx_id": "7E0g"}],
        [{"interface": "SocketCAN", "channel": "can0"}],  # no ids
        [{"interface": "DoIP", "doip": {"host": "10.0.0.2"}}],  # no ECU address, no Discover
        [{**PCAN, "tx_id": "18DA10F1"}],  # 29-bit id without Extended IDs
        [{**PCAN, "name": "a"}, {**PCAN, "name": "b"}],  # one CAN id twice on one bus
        [{**PCAN, "name": "a"}, {**PCAN, "name": "b", "tx_id": "7E1", "rx_id": "7E9",
                                 "bitrate": 250000}],  # one bus, two bitrates
        [{"interface": "DoIP", "name": n, "doip": {"host": "h", "ecu_address": "0x1001"}}
         for n in ("a", "b")],  # one entity, one tester address
        [{"interface": "Demo", "key_file": "missing.py"}],
        [{"interface": "Demo", "name": "a/b"}],
        [],
    ],
    ids=["interface", "id", "no ids", "doip address", "29-bit", "shared id", "bitrates",
         "doip tester", "key file", "name", "no ecus"],
)  # fmt: skip
def test_bad_config_refused_before_any_bus_opens(ecus, tmp_path, monkeypatch):
    """By the schema (the settings form's check too) or at start, with the reason logged."""
    with pytest.raises((ConfigValidationError, SystemExit)):
        config, advanced = load(tmp_path, monkeypatch, {"ecus": ecus})
        share_buses(create_ecus(config, advanced))


@pytest.mark.parametrize("settings", ["auto-configure", "0.1.x"])
def test_demo_settings_and_the_cli_reach_the_demo(settings, tmp_path, monkeypatch):
    """Auto-configure's settings, 0.1.x flat settings (one ECU), and the shell path in its
    own process."""
    config = (
        actions.auto_config()["config"]
        if settings == "auto-configure"
        else {"interface": "demo", "request_timeout": 3.0}
    )
    with started(tmp_path, monkeypatch, config) as ecus:
        connected(ecus)
        assert ecus[0].name == "demo" and did("demo", "F190") == VIN
    args = ["read", "--interface", "demo", "--txid", "7E0", "--rxid", "7E8", "--id", "F190"]
    done = subprocess.run([sys.executable, "main.py", *args], cwd=ROOT, capture_output=True,
                          text=True, timeout=30)  # fmt: skip
    assert done.returncode == 0, done.stderr
    assert bytes.fromhex(json.loads(done.stdout)["data"][2:]) == VIN


def test_doip_discovery_and_refused_activation(tmp_path, monkeypatch):
    """Discover takes the ECU address from the entity; a refused routing activation is the
    action error and is not retried."""
    entity = DoipEntity(port=0, udp_port=PORT).start()
    doip = {"host": "127.0.0.1", "port": entity.port}
    config = {"ecus": [
        {"interface": "DoIP", "name": "found", "doip": {**doip, "discover": True}},
        {"interface": "DoIP", "name": "refused",
         "doip": {**doip, "ecu_address": "0x1001", "tester_address": "0x0E81"}},
    ]}  # fmt: skip
    try:
        with started(tmp_path, monkeypatch, config) as (found, refused):
            connected([found])
            status = actions.get_status("found")
            assert status["ecu_address"] == "0x1001" and status["vehicle"]["eid"] == EID.hex(":")
            assert did("found", "F190") == status["vehicle"]["vin"].encode()
            assert wait_until(lambda: not refused.shared._thread.is_alive())
            assert refused.state == State.ERROR
            result = actions.read_did("refused", "F190")
            assert "routing activation refused: 0x00 unknown source address" in result["error"]
            assert actions.get_status("refused")["reopens"] == 0
    finally:
        entity.stop()


def test_can_bus_failure(tmp_path, monkeypatch):
    """A bus that fails reopens; one that cannot open (unknown interface) is not retried."""
    monkeypatch.setattr(client, "RECONNECT_INITIAL", 0.3)
    channel = f"uds-{uuid.uuid4().hex[:8]}"
    server = DemoEcu(channel).start()
    bad = json.dumps({"interface": "no-such-interface", "channel": "x"})
    config = {"ecus": [_can(channel), _can("other", name="bad", config_json=bad)]}
    try:
        with started(tmp_path, monkeypatch, config) as (ecu, bad_ecu):
            connected([ecu])
            assert wait_until(lambda: bad_ecu.state == State.ERROR)
            assert bad_ecu.shared.join(1.0) and bad_ecu.shared.reopens == 0

            broken = ecu.shared.bus
            broken.shutdown()

            def down(timeout):
                raise can.CanOperationError("Network is down")

            monkeypatch.setattr(broken, "_recv_internal", down)
            assert wait_until(lambda: ecu.state == State.ERROR)
            assert "Network is down" in actions.read_did("ecu", "F190")["error"]
            connected([ecu])
            assert ecu.shared.bus is not broken and ecu.shared.reopens == 1
            assert did("ecu", "F190") == VIN
    finally:
        server.stop()
