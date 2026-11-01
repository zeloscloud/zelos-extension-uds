"""Integration sanity checks: the extension, started as the app starts it, against its own
demo ECU on the zelos-can virtual bus (`can`) and behind the DoIP entity simulator (`doip`)."""

from __future__ import annotations

import contextlib
import json
import logging
import random
import shutil
import subprocess
import sys
import threading
import time
import tomllib
import uuid
from pathlib import Path
from types import SimpleNamespace

import can
import pyarrow as pa
import pytest
import zelos_sdk
from doip_entity import EID, PORT, DoipEntity
from jsonschema import Draft202012Validator
from zelos_sdk.actions import ActionsRegistry
from zelos_sdk.extensions import ConfigValidationError, load_config

from zelos_extension_uds import actions, client
from zelos_extension_uds.cli import read
from zelos_extension_uds.cli.app import (
    create_ecus,
    migrate_legacy,
    resolve_advanced,
    run_app_mode,
    share_buses,
)
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


def test_actions_register_under_the_manifest_name(tmp_path, monkeypatch):
    names: list[str | None] = []

    def init(name: str | None = None, **_kwargs) -> None:
        names.append(name)
        raise SystemExit(0)

    monkeypatch.setattr(zelos_sdk, "init", init)
    monkeypatch.setattr(zelos_sdk, "init_global_source", lambda _name: None)
    monkeypatch.setattr(zelos_sdk, "actions_registry", ActionsRegistry())
    load(tmp_path, monkeypatch, {"ecus": [{"interface": "Demo"}]})
    with pytest.raises(SystemExit):
        run_app_mode(demo=False, file=None)
    manifest = tomllib.loads((ROOT / "extension.toml").read_text())
    assert names == [manifest["name"]]


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


def test_action_flags():
    """Pins each action's flags, so a new action or a changed flag is a deliberate choice."""
    registered = {}
    actions.register_actions(SimpleNamespace(register=lambda f, name: registered.update({name: f})))
    flags = {n: (f._action.read_only, f._action.hidden) for n, f in registered.items()}
    assert flags == {
        "list_ecus": (True, True),
        "get_status": (True, True),
        "session_control": (False, False),
        "read_did": (True, False),
        "write_did": (False, False),
        "ecu_reset": (False, False),
        "routine_control": (False, False),
        "io_control": (False, False),
        "tester_present": (False, False),
        "periodic_tester_present": (False, False),
        "read_dtc": (True, False),
        "clear_dtc": (False, False),
        "control_dtc_setting": (False, False),
        "communication_control": (False, False),
        "security_access": (False, False),
        "read_memory": (True, False),
        "write_memory": (False, False),
        "request_download": (False, True),
        "request_upload": (False, True),
        "transfer_data": (False, True),
        "request_transfer_exit": (False, True),
        "upload_memory": (False, False),
        "flash_firmware": (False, False),
        "auto_config": (True, True),
        "list_interfaces": (True, True),
    }


def test_ecu_may_be_unset_with_one_ecu(tmp_path, monkeypatch):
    """Called as the agent calls them: without `ecu`, the only ECU answers; with two
    configured, the action names them."""
    registered = {}
    actions.register_actions(SimpleNamespace(register=lambda f, name: registered.update({name: f})))
    schemas = [f._action.to_schema() for f in registered.values()]
    takes_ecu = [s for s in schemas if "ecu" in s["properties"]]
    assert len(takes_ecu) == 22
    assert not [s["title"] for s in takes_ecu if "ecu" in s.get("required", [])]
    execute = zelos_sdk.actions_registry.execute
    with started(tmp_path, monkeypatch, {"ecus": [{"interface": "Demo"}]}) as ecus:
        connected(ecus)
        assert execute("get_status", {}).value["name"] == "demo"
        assert execute("get_status", {"ecu": None}).value["name"] == "demo"
        assert bytes.fromhex(execute("read_did", {"did": "F190"}).value["data"][2:]) == VIN
        actions.UDS_ECUS["other"] = ecus[0]
        with pytest.raises(RuntimeError, match=r"Set ecu\. Available: \['demo', 'other'\]"):
            execute("get_status", {})


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
    ids=["interface", "id", "doip address", "29-bit", "shared id", "bitrates",
         "doip tester", "key file", "name", "no ecus"],
)  # fmt: skip
def test_bad_config_refused_before_any_bus_opens(ecus, tmp_path, monkeypatch):
    """By the schema (the settings form's check too) or at start, with the reason logged."""
    with pytest.raises((ConfigValidationError, SystemExit)):
        config, advanced = load(tmp_path, monkeypatch, {"ecus": ecus})
        share_buses(create_ecus(config, advanced))


def test_can_ids_default_to_the_settings_form_pair(tmp_path, monkeypatch):
    """A CAN entry that names no ids gets 0x7E0 and 0x7E8, the defaults the settings form shows."""
    config, _ = load(
        tmp_path, monkeypatch, {"ecus": [{"interface": "SocketCAN", "channel": "can0"}]}
    )
    assert (config["ecus"][0]["tx_id"], config["ecus"][0]["rx_id"]) == ("0x7E0", "0x7E8")


@pytest.mark.parametrize(
    ("saved", "errors"),
    [
        ({"interface": "demo", "request_timeout": 3.0}, []),
        ({"interface": "socketcan", "channel": "can0", "tx_id": "7E1", "rx_id": "7E9"}, []),
        ({"ecus": [{"interface": "Demo"}]}, []),
        ({}, ["'ecus' is a required property"]),
        ({"advanced": {"log_level": "DEBUG"}}, ["'ecus' is a required property"]),
    ],
    ids=["0.1.x demo", "0.1.x socketcan", "ecus", "nothing", "no ecus"],
)
def test_update_check_takes_0_1_x_settings(saved, errors):
    """An update of a running extension checks its saved settings against the new schema as
    saved, with no defaults filled in: the 0.1.x flat shape passes, for app mode to convert."""
    schema = json.loads((ROOT / "config.schema.json").read_text())
    assert [e.message for e in Draft202012Validator(schema).iter_errors(saved)] == errors


@pytest.mark.parametrize(
    ("advanced", "reason"),
    [
        (
            {"log_level": "VERBOSE"},
            "advanced.log_level: 'VERBOSE' is not one of ['DEBUG', 'INFO', 'WARNING', 'ERROR']",
        ),
        (
            {"p2_timeout": 0, "isotp_stmin": 200},
            "advanced.p2_timeout: 0 is less than the minimum of 0.01; "
            "advanced.isotp_stmin: 200 is greater than the maximum of 127",
        ),
    ],
    ids=["one error", "two errors"],
)
def test_saved_settings_off_the_schema_exit(advanced, reason, tmp_path, monkeypatch, caplog):
    """Started with saved settings that fail the schema: one ERROR line, then exit 1."""
    saved = tmp_path / "config.json"
    saved.write_text(json.dumps({"ecus": [{"interface": "Demo"}], "advanced": advanced}))
    monkeypatch.setenv("ZELOS_CONFIG_PATH", str(saved))
    monkeypatch.chdir(ROOT)
    with pytest.raises(SystemExit) as exc:
        run_app_mode(demo=False, file=None)
    assert exc.value.code == 1
    errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors == [f"Invalid configuration: {reason}"]


@pytest.mark.parametrize("target", ["can"], indirect=True)
def test_access_level_labels(target, tmp_path, monkeypatch):
    """0.1.x labels: "Level 1".."Level 4" request seeds 0x01, 0x03, 0x05, 0x07."""
    with started(tmp_path, monkeypatch, {"ecus": [target.config]}) as ecus:
        connected(ecus)
        ok(actions.session_control("ecu", "Extended Diagnostic Session"))
        assert ok(actions.security_access("ecu", "Level 1"))["access_granted"]
        for label in ("Level 2", "Level 3", "Level 4"):
            nrc(actions.security_access("ecu", label), 0x12)
    assert [frame[2] for frame in target.sent() if frame[1] == 0x27] == [1, 2, 3, 5, 7]


def test_cli_takes_socketcan_and_python_can_names(capsys):
    """`socketcan` is SocketCAN; any other name opens that python-can interface."""
    args = ["--txid", "7E0", "--rxid", "7E8", "--id", "F190"]
    ctx = read.make_context("read", ["--interface", "socketcan", *args])
    assert ctx.params["interface"] == "SocketCAN"
    channel = f"uds-{uuid.uuid4().hex[:8]}"
    server = DemoEcu(channel, interface="virtual").start()
    try:
        read.main(["--interface", "virtual", "--channel", channel, *args], standalone_mode=False)
    finally:
        server.stop()
    assert bytes.fromhex(json.loads(capsys.readouterr().out)["data"][2:]) == VIN


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


def test_saved_demo_key_file_follows_an_update(tmp_path, monkeypatch, caplog):
    """The demo key file's path names the installed version's folder, which an update deletes.
    Saved by Auto-configure or by an earlier version, it loads this install's copy; the user's
    own key file loads from where it is."""

    def installed(version: str) -> Path:
        return tmp_path / "uds" / version / "code" / "zelos_extension_uds" / "demo" / "key.py"

    monkeypatch.setattr("zelos_extension_uds.demo.KEY_FILE", installed("0.3.0"))
    auto = actions.auto_config()["config"]["ecus"][0]
    current, own = installed("0.3.2"), tmp_path / "keys" / "key.py"
    for copy in (current, own):
        copy.parent.mkdir(parents=True)
        shutil.copy(KEY_FILE, copy)
    monkeypatch.setattr("zelos_extension_uds.demo.KEY_FILE", current)
    config = {"ecus": [
        auto,
        {"name": "bench", "interface": "Demo", "key_file": str(installed("0.2.0"))},
        {"name": "own", "interface": "Demo", "key_file": str(own)},
    ]}  # fmt: skip
    with started(tmp_path, monkeypatch, config) as ecus:
        connected(ecus)
        for name in ("demo", "bench", "own"):
            ok(actions.session_control(name, "Extended Diagnostic Session"))
            assert ok(actions.security_access(name, "0x01"))["access_granted"]
    assert [m for m in caplog.messages if "seed/key from" in m] == [
        f"ECU demo: seed/key from {current}",
        f"ECU bench: seed/key from {current}",
        f"ECU own: seed/key from {own}",
    ]


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


def _send_fails(*_args, **_kwargs):
    raise OSError("send failed")


@pytest.mark.parametrize("case", ["failed send", "two ecus", "slow flow control"])
def test_wire_safety(case, tmp_path, monkeypatch):
    """A failed send is neither counted nor traced; two ECUs on one bus get only their own
    responses; an ECU slow to take a long block (its flow control STmin 8 ms: a 1026-byte
    block takes over P2's 1 s to send) does not time the request out: P2 starts after it."""
    channel = f"uds-{uuid.uuid4().hex[:8]}"
    servers = [DemoEcu(channel, stmin=8 if case == "slow flow control" else 0).start()]
    ecus = [_can(channel, name="a")]
    if case == "two ecus":
        servers.append(DemoEcu(channel, request_id=0x7E1, response_id=0x7E9,
                               functional_id=None).start())  # fmt: skip
        ecus.append(_can(channel, name="b", tx_id="7E1", rx_id="7E9"))
    trz = tmp_path / "uds.trz"
    try:
        with started(tmp_path, monkeypatch, {"ecus": ecus}, trz) as started_ecus:
            connected(started_ecus)
            if case == "failed send":
                assert did("a", "F190") == VIN
                with monkeypatch.context() as m:
                    m.setattr(client.PythonIsoTpConnection, "send", _send_fails)
                    assert "send failed" in actions.read_did("a", "F190")["error"]
                metrics = actions.get_status("a")["metrics"]
                assert metrics["requests"] == metrics["responses"] == 1
            elif case == "two ecus":
                assert started_ecus[0].shared is started_ecus[1].shared
                ok(actions.session_control("b", "Extended Diagnostic Session"))
                assert (did("a", "F186"), did("b", "F186")) == (b"\x01", b"\x03")
            else:
                image = random.Random(3).randbytes(4096)
                done = ok(actions.flash_firmware("a", DOWNLOAD, data=image.hex(),
                                                 erase_routine=ERASE))  # fmt: skip
                assert done["block_size"] == 1024 and servers[0].download[:4096] == image
        if case == "failed send":
            assert _rows(trz, "UDS/a/tx")["data"] == [b"\xf1\x90"]
    finally:
        for server in servers:
            server.stop()
