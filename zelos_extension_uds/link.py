"""UDS on CAN: the CAN ids, ISO-TP settings and the bus.

The bus comes from `zelos_can.bus`. The extension owns the bus: no DBC
decode, no raw frame trace (the CAN extension's job).
"""

from __future__ import annotations

import sys
from typing import Any

import can
import isotp
from zelos_can.bus import BUS_DEFAULTS, open_python_can_bus, prepare_bus_config
from zelos_can.ssh_socketcan import SshPermanentError

MAX_STANDARD = 0x7FF
MAX_EXTENDED = 0x1FFF_FFFF

#: ECU keys that are not the bus's.
ECU_KEYS = ("name", "tx_id", "rx_id", "extended_ids", "key_file")

#: Bus settings two ECUs on one bus must agree on.
BUS_SETTINGS = (
    "bitrate",
    "fd_mode",
    "data_bitrate",
    "config_json",
    "ssh_key_path",
    "ssh_host_key_policy",
    "ssh_extra_opts",
    "ssh_hw_timestamps",
)


def parse_id(text: str | int, label: str, extended: bool) -> int:
    """A hex CAN id (`7E0`, `0x7E0`) that fits the id format; ValueError otherwise."""
    try:
        value = text if isinstance(text, int) else int(str(text).strip(), 16)
    except ValueError:
        raise ValueError(f"{label} {text!r} is not a hex CAN id, e.g. 0x7E0") from None
    limit = MAX_EXTENDED if extended else MAX_STANDARD
    if not 0 <= value <= limit:
        kind = "extended" if extended else "standard (turn on Extended IDs)"
        raise ValueError(f"{label} {text} does not fit a {kind} CAN id")
    return value


def ids(link: dict[str, Any]) -> tuple[int, int, bool]:
    """(request id, response id, extended). Both ids must be set: never guessed."""
    extended = bool(link.get("extended_ids"))
    out = []
    for key, label in (("tx_id", "Request CAN ID"), ("rx_id", "Response CAN ID")):
        text = link.get(key)
        if text is None or str(text).strip() == "":
            raise ValueError(f"no {label}: set it on the ECU")
        out.append(parse_id(text, label, extended))
    if out[0] == out[1]:
        raise ValueError("Request and Response CAN ID must differ")
    return out[0], out[1], extended


def id_text(can_id: int, extended: bool) -> str:
    return f"0x{can_id:08X}" if extended else f"0x{can_id:03X}"


def address(tx_id: int, rx_id: int, extended: bool) -> isotp.Address:
    mode = isotp.AddressingMode.Normal_29bits if extended else isotp.AddressingMode.Normal_11bits
    return isotp.Address(mode, txid=tx_id, rxid=rx_id)


def isotp_params(advanced: dict[str, Any], fd: bool) -> dict[str, Any]:
    """ISO-TP parameters. CAN FD: 64-byte frames, padded to FD lengths by can-isotp."""
    params: dict[str, Any] = {
        "stmin": int(advanced.get("isotp_stmin") or 0),
        "blocksize": int(advanced.get("isotp_blocksize") or 0),
        "tx_data_length": 64 if fd else 8,
        "can_fd": fd,
        "bitrate_switch": fd,
        # send() returns after the last consecutive frame, so P2 starts there.
        "blocking_send": True,
    }
    padding = advanced.get("isotp_padding")
    if padding is not None:
        params["tx_padding"] = int(padding)
    return params


def bus_link(link: dict[str, Any]) -> dict[str, Any]:
    """The bus part of an ECU's config."""
    return {k: v for k, v in link.items() if k not in ECU_KEYS}


def bus_key(link: dict[str, Any]) -> tuple:
    """What makes two ECUs share one bus: interface and channel (remote host, channel, user
    and port over ssh; the whole `config_json` for Other)."""
    interface = link.get("interface")
    if interface == "zelos-ssh-socketcan":
        host, channel = link.get("remote_host"), link.get("remote_channel", "can0")
        return interface, host, channel, link.get("ssh_user"), link.get("ssh_port") or 22
    if interface == "other":
        return interface, link.get("config_json")
    return interface, str(link.get("channel", ""))


def bus_settings(link: dict[str, Any]) -> dict[str, Any]:
    """Settings that change how the bus opens. `data_bitrate` counts with CAN FD only."""
    out = {k: link.get(k) for k in BUS_SETTINGS}
    out["fd_mode"] = bool(out["fd_mode"])
    if not out["fd_mode"]:
        out.pop("data_bitrate")
    return out


def bus_text(link: dict[str, Any]) -> str:
    key = bus_key(link)
    return f"{key[0]}://{':'.join(str(k) for k in key[1:] if k)}"


def open_bus(link: dict[str, Any], name: str) -> can.BusABC:
    """Open a bus with the zelos-can factory; own frames are not received.

    Over ssh they always are; ISO-TP drops ids it does not listen on.
    """
    interface = link.get("interface")
    own = interface == "zelos-ssh-socketcan"
    advanced = {**BUS_DEFAULTS, "receive_own_messages": own, "log_raw_frames": False}
    config = prepare_bus_config({**link, "name": name}, advanced=advanced)
    if config["interface"] == "zelos-virtual":
        config.pop("receive_own_messages")  # not a virtual-bus kwarg; it echoes regardless
    return open_python_can_bus(config, name)


#: Open errors no retry fixes: an operator must act (ssh host key), the interface or its
#: driver library is missing, or the configuration is invalid.
PERMANENT = (
    SshPermanentError,
    can.CanInterfaceNotImplementedError,
    NotImplementedError,
    ImportError,
    NameError,  # python-can's vendor wrappers without their library
    ValueError,
)


def permanent(e: Exception, link: dict[str, Any]) -> bool:
    """`e`, from opening `link`'s bus, will not go away by retrying."""
    linux_only = link.get("interface") == "zelos-socketcan" and sys.platform != "linux"
    return isinstance(e, PERMANENT) or linux_only
