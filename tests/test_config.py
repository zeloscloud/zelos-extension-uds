"""Config: the schema, its defaults, the 0.1.x shim and bus sharing rules."""

import json
from pathlib import Path

import jsonschema
import pytest
from zelos_sdk.extensions import load_config

from zelos_extension_uds.actions import auto_config
from zelos_extension_uds.cli.app import (
    ADVANCED_DEFAULTS,
    create_ecus,
    migrate_legacy,
    resolve_advanced,
    share_buses,
)
from zelos_extension_uds.constants import CLI_INTERFACES, INTERFACES

SCHEMA = json.loads((Path(__file__).parent.parent / "config.schema.json").read_text())
#: Draft 7, as the form reads it: later drafts ignore `dependencies`.
validate = jsonschema.Draft7Validator(SCHEMA).validate
CAN = {"tx_id": "0x7E0", "rx_id": "0x7E8"}


def test_schema_defaults_match_advanced_defaults():
    advanced = SCHEMA["properties"]["advanced"]["properties"]
    assert {k: v.get("default") for k, v in advanced.items()} == ADVANCED_DEFAULTS
    assert resolve_advanced({"advanced": {"prefix": ""}})["prefix"] == ""


@pytest.mark.parametrize(
    "ecu",
    [
        {"interface": "Demo"},
        {"interface": "SocketCAN", "channel": "can0", **CAN},
        {"interface": "SocketCAN over SSH", "remote_host": "edge", **CAN},
        {"interface": "PCAN", "channel": "PCAN_USBBUS1", "bitrate": 500000, **CAN},
        {"interface": "Kvaser", "channel": "0", "bitrate": 500000, "fd_mode": True,
         "data_bitrate": 2000000, **CAN},
        {"interface": "slcan (serial)", "channel": "/dev/ttyACM0", "bitrate": 500000, **CAN},
        {"interface": "Other (python-can)", "config_json": '{"interface": "ixxat"}',
         "tx_id": "18DA10F1", "rx_id": "18DAF110", "extended_ids": True},
    ],
)  # fmt: skip
def test_schema_accepts(ecu):
    validate({"ecus": [ecu], "advanced": {"isotp_padding": 204}})


def test_schema_refuses_bad_id_and_missing_id():
    with pytest.raises(jsonschema.ValidationError):
        validate({"ecus": [_pcan("a", "7E0g", "7E8")]})
    with pytest.raises(jsonschema.ValidationError):
        validate({"ecus": [{"interface": "SocketCAN", "channel": "can0"}]})


def test_auto_config_validates():
    jsonschema.Draft7Validator.check_schema(SCHEMA)
    result = auto_config()
    assert result["status"] == "success"
    validate(result["config"])


def test_labels():
    enum = SCHEMA["properties"]["ecus"]["items"]["properties"]["interface"]["enum"]
    assert set(enum) == set(INTERFACES)
    assert set(CLI_INTERFACES.values()) <= set(INTERFACES)
    assert CLI_INTERFACES["socketcan"] == "SocketCAN"
    assert INTERFACES["SocketCAN"] == "zelos-socketcan"


def test_legacy_flat_config_is_one_ecu(caplog, tmp_path, monkeypatch):
    legacy = {
        "interface": "pcan",
        "channel": "PCAN_USBBUS1",
        "bitrate": 250000,
        "tx_id": "0x7E1",
        "show_advanced": True,
        "request_timeout": 12.0,
        "p2_timeout": 2.5,
        "p2_star_timeout": 20.0,
        "isotp_tx_padding": 0xAA,
        "log_level": "DEBUG",
    }
    # Through load_config: its schema defaults must not overwrite the legacy values.
    (tmp_path / "config.json").write_text(json.dumps(legacy))
    monkeypatch.setenv("ZELOS_CONFIG_PATH", str(tmp_path / "config.json"))
    monkeypatch.chdir(Path(__file__).parent.parent)
    config = migrate_legacy(load_config())
    assert config["ecus"] == [
        {
            "interface": "PCAN",
            "channel": "PCAN_USBBUS1",
            "bitrate": 250000,
            "tx_id": "0x7E1",
            "rx_id": "0x7E8",
            "extended_ids": False,
        }
    ]
    assert resolve_advanced(config) == {
        **ADVANCED_DEFAULTS,
        "request_timeout": 12.0,
        "p2_timeout": 2.5,
        "p2_star_timeout": 20.0,
        "isotp_padding": 0xAA,
        "log_level": "DEBUG",
    }
    assert "0.1.x" in caplog.text
    validate(config)
    assert migrate_legacy({"interface": "demo"})["ecus"][0]["interface"] == "Demo"
    for extended in ({"extended_id": True}, {"tx_id": "18DA10F1", "rx_id": "18DAF110"}):
        assert migrate_legacy({"interface": "pcan", **extended})["ecus"][0]["extended_ids"]
    current = {"ecus": [{"interface": "Demo"}]}
    assert migrate_legacy(current) is current


def _pcan(name, tx, rx, **extra):
    return {"name": name, "interface": "PCAN", "channel": "PCAN_USBBUS1", "bitrate": 500000,
            "tx_id": tx, "rx_id": rx, **extra}  # fmt: skip


def test_ecus_on_one_channel_share_one_bus():
    ecus = create_ecus({"ecus": [_pcan("a", "7E0", "7E8"), _pcan("b", "7E1", "7E9")]},
                       ADVANCED_DEFAULTS)  # fmt: skip
    buses = share_buses(ecus)
    assert len(buses) == 1 and buses[0].ecus == ecus


@pytest.mark.parametrize(
    "second",
    [_pcan("b", "7E1", "7E9", bitrate=250000), _pcan("b", "7E1", "7E9", fd_mode=True),
     _pcan("b", "7E0", "7E8"), _pcan("b", "7E1", "7E8"), _pcan("b", "7E0", "7E9"),
     _pcan("b", "7E8", "7E1")],
)  # fmt: skip
def test_conflicting_ecus_on_one_bus_refused(second, caplog):
    ecus = create_ecus({"ecus": [_pcan("a", "7E0", "7E8"), second]}, ADVANCED_DEFAULTS)
    with pytest.raises(SystemExit):
        share_buses(ecus)
    assert "share" in caplog.text
