"""Shared constants and the trace-naming rules for the UDS extension."""

from collections.abc import Collection
from enum import StrEnum

import zelos_sdk

#: Default leading trace-source name (`advanced.prefix`).
DEFAULT_PREFIX = "UDS"

#: Source the extension's logs take when the prefix is cleared; with a prefix
#: they land in it as `<prefix>/log`. Both names are reserved as ECU names.
LOG_SOURCE_NAME = "uds_log"
RESERVED_ECU_NAMES = ("log", LOG_SOURCE_NAME)


class Interface(StrEnum):
    """How an ECU is reached: a python-can interface, the demo ECU, or DoIP."""

    ZELOS_SOCKETCAN = "zelos-socketcan"
    ZELOS_SSH_SOCKETCAN = "zelos-ssh-socketcan"
    PCAN = "pcan"
    KVASER = "kvaser"
    VECTOR = "vector"
    SLCAN = "slcan"
    OTHER = "other"
    DEMO = "demo"
    DOIP = "doip"


#: An ECU's `interface` as configured (the label the form shows) -> how it is reached.
INTERFACES = {
    "SocketCAN": Interface.ZELOS_SOCKETCAN,
    "SocketCAN over SSH": Interface.ZELOS_SSH_SOCKETCAN,
    "PCAN": Interface.PCAN,
    "Kvaser": Interface.KVASER,
    "Vector": Interface.VECTOR,
    "slcan (serial)": Interface.SLCAN,
    "Other (python-can)": Interface.OTHER,
    "Demo": Interface.DEMO,
    "DoIP": Interface.DOIP,
}

#: CLI `--interface` short names -> labels.
CLI_INTERFACES = {
    "zelos-socketcan": "SocketCAN",
    "zelos-ssh-socketcan": "SocketCAN over SSH",
    "pcan": "PCAN",
    "kvaser": "Kvaser",
    "vector": "Vector",
    "slcan": "slcan (serial)",
    "other": "Other (python-can)",
    "demo": "Demo",
    "doip": "DoIP",
}

#: The ECU `--demo` and Auto-configure add; see `demo_ecu`.
DEMO_ECU = {"name": "demo", "interface": "Demo"}


def demo_ecu() -> dict:
    """DEMO_ECU with the demo's key file, wherever the package is installed."""
    from zelos_extension_uds.demo import KEY_FILE

    return {**DEMO_ECU, "key_file": str(KEY_FILE)}


def trace_layout(prefix: str, ecu: str) -> tuple[str, str | None]:
    """The one trace-naming rule: (source name, event prefix or None) for an ECU.

    With a prefix, one shared source carries every ECU and an ECU's events read
    `<ecu>/<event>`. Cleared, each ECU owns its source and its events are
    unprefixed.
    """
    if prefix:
        return prefix, ecu
    return ecu, None


def name_error(value: str, label: str, reserved: Collection[str] = ()) -> str | None:
    """Why user-typed `value` is not a legal trace name, or None if it is.

    Names become trace path segments, so a separator (`/ . @ :`) would silently
    re-nest the tree. Anything the SDK sanitizer rewrites is rejected, not renamed.
    """
    if not value:
        return None  # cleared prefix / unset ECU name; the caller decides
    if value in reserved:
        return f"Invalid {label} {value!r}: reserved for the extension's own logs."
    clean = zelos_sdk.sanitize_name(value, kind="source")
    if clean == value:
        return None
    offender = next((c for c, ok in zip(value, clean, strict=False) if c != ok), value[-1])
    return (
        f"Invalid {label} {value!r}: {offender!r} is not allowed. "
        "Use letters, digits, space, '_' or '-'."
    )
