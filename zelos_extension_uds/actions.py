"""Free-floating UDS action functions registered under `<ACTION_PREFIX>/<name>`.

One global namespace keyed by an `ecu` parameter, not per-ECU action paths:
consumers get one stable surface however many ECUs are configured, and discover
the ECUs through `list_ecus`. An address pair is an ECU: actions take no CAN
id overrides.

Functions read the shared `UDS_ECUS` registry, which `cli/app.py` populates at
startup. Free functions, not methods, so `@action.select("ecu", choices=...)`
can reference a module-level callable at decoration time.
"""

from __future__ import annotations

import inspect
import logging
import sys
from typing import TYPE_CHECKING, Any

from zelos_can.bus import discovery
from zelos_sdk.actions import ActionsRegistry, action

from zelos_extension_uds import services
from zelos_extension_uds.constants import demo_ecu
from zelos_extension_uds.utils import (
    ENDIANNESS_BIG,
    ENDIANNESS_CHOICES,
    PAYLOAD_TYPE_CHOICES,
    PAYLOAD_TYPE_HEX,
)

if TYPE_CHECKING:
    from zelos_extension_uds.client import UdsEcu

logger = logging.getLogger(__name__)

# Shared ECU registry, populated by `cli/app.py`.
UDS_ECUS: dict[str, UdsEcu] = {}

#: Seconds a flash, upload or routine (a slow erase) may take before the action gives up.
FLASH_TIMEOUT = 600.0

_TYPE_HELP = "'hex' = raw hex; numeric types pack the number to the type's width."
_ENDIAN_HELP = "Byte order for numeric types. Ignored for 'hex' and 1-byte types."


def _available_ecus(*_args: Any) -> list[str]:
    """`choices=` provider for the `ecu` select field, evaluated at form-render time."""
    return sorted(UDS_ECUS.keys())


def _get_ecu(name: str) -> UdsEcu:
    ecu = UDS_ECUS.get(name)
    if ecu is None:
        raise ValueError(f"Unknown ECU '{name}'. Available: {_available_ecus()}")
    return ecu


def _ecu_field(func: Any) -> Any:
    return action.select("ecu", title="ECU", choices=_available_ecus)(func)


# ─── Discovery and state ────────────────────────────────────────────────────


#: `list_ecus` fields, those of an ECU's status it has: CAN ids or DoIP addresses.
_LISTED = ("name", "interface", "endpoint", "tx_id", "rx_id", "tester_address", "ecu_address",
           "state")  # fmt: skip


@action(
    "List ECUs",
    "Every configured ECU with its interface, endpoint, CAN ids or DoIP addresses and state: "
    "the names the other actions accept as `ecu`.",
    read_only=True,
    hidden=True,
)
def list_ecus() -> dict[str, Any]:
    ecus = [
        {k: s[k] for k in _LISTED if k in s}
        for s in (ecu.status() for _, ecu in sorted(UDS_ECUS.items()))
    ]
    return {"ecus": ecus, "count": len(ecus)}


@action(
    "Get Status",
    "State, last error, CAN ids or DoIP addresses (and, with Discover, the vehicle "
    "identification), periodic tester present and request counters for one ECU. Sends nothing.",
    read_only=True,
    hidden=True,
)
@_ecu_field
def get_status(ecu: str) -> dict[str, Any]:
    return _get_ecu(ecu).status()


# ─── Services ───────────────────────────────────────────────────────────────
#
# Every field with a default is optional (`required=False`): a caller sends only what
# it changes. Typed data fields: see `_TYPE_HELP`.


def _data_fields(name: str, title: str, placeholder: str, default: str = "") -> Any:
    """A typed data field, its type and its byte order."""

    def apply(func: Any) -> Any:
        func = action.select(
            "endianness", title="Endianness", description=_ENDIAN_HELP,
            choices=ENDIANNESS_CHOICES, default=ENDIANNESS_BIG, required=False,
        )(func)  # fmt: skip
        type_name = "data_type" if name in ("data",) else f"{name}_type"
        func = action.select(
            type_name, title=f"{title} Type", choices=PAYLOAD_TYPE_CHOICES,
            default=PAYLOAD_TYPE_HEX, required=False,
        )(func)  # fmt: skip
        return action.text(
            name, title=title, description=_TYPE_HELP, placeholder=placeholder,
            default=default, required=False,
        )(func)  # fmt: skip

    return apply


@action("Diagnostic Session Control", "Change the diagnostic session (0x10).")
@_ecu_field
@action.select(
    "session_type",
    title="Session Type",
    choices=list(services.SESSIONS),
    default="Extended Diagnostic Session",
    required=False,
)
def session_control(ecu: str, session_type: str = "Extended Diagnostic Session") -> dict[str, Any]:
    return services.session_control(_get_ecu(ecu), session_type)


@action(
    "Read Data By Identifier",
    "Read a DID (0x22): hex, and integer/float readings of 1, 2, 4 and 8-byte values.",
    read_only=True,
)
@_ecu_field
@action.text("did", title="Data Identifier (hex)", placeholder="0xF190")
def read_did(ecu: str, did: str) -> dict[str, Any]:
    return services.read_did(_get_ecu(ecu), did)


@action("Write Data By Identifier", "Write a DID (0x2E).")
@_ecu_field
@action.text("did", title="Data Identifier (hex)", placeholder="0x0200")
@_data_fields("data", "Data", "01 02")
def write_did(
    ecu: str,
    did: str,
    data: str = "",
    data_type: str = PAYLOAD_TYPE_HEX,
    endianness: str = ENDIANNESS_BIG,
) -> dict[str, Any]:
    return services.write_did(_get_ecu(ecu), did, data, data_type, endianness)


@action("ECU Reset", "Reset the ECU (0x11).")
@_ecu_field
@action.select(
    "reset_type",
    title="Reset Type",
    choices=list(services.RESET_TYPES),
    default="Soft Reset",
    required=False,
)
def ecu_reset(ecu: str, reset_type: str = "Soft Reset") -> dict[str, Any]:
    return services.ecu_reset(_get_ecu(ecu), reset_type)


@action(
    "Routine Control", "Start, stop or read the results of a routine (0x31).", timeout=FLASH_TIMEOUT
)
@_ecu_field
@action.text("routine_id", title="Routine ID (hex)", placeholder="0x0201")
@action.select(
    "control_type",
    title="Control Type",
    choices=list(services.ROUTINE_CONTROLS),
    default="Start Routine",
    required=False,
)
@_data_fields("data", "Data (optional)", "01 02")
def routine_control(
    ecu: str,
    routine_id: str,
    control_type: str = "Start Routine",
    data: str = "",
    data_type: str = PAYLOAD_TYPE_HEX,
    endianness: str = ENDIANNESS_BIG,
) -> dict[str, Any]:
    return services.routine_control(
        _get_ecu(ecu), routine_id, control_type, data, data_type, endianness
    )


@action("Input Output Control", "Control an input or output by DID (0x2F).")
@_ecu_field
@action.text("did", title="Data Identifier (hex)", placeholder="0x0300")
@action.select(
    "control_parameter",
    title="Control Parameter",
    choices=list(services.IO_CONTROLS),
    default="Return Control To ECU",
    required=False,
)
@_data_fields("control_option", "Control Option Record (optional)", "05 64")
def io_control(
    ecu: str,
    did: str,
    control_parameter: str = "Return Control To ECU",
    control_option: str = "",
    control_option_type: str = PAYLOAD_TYPE_HEX,
    endianness: str = ENDIANNESS_BIG,
) -> dict[str, Any]:
    return services.io_control(
        _get_ecu(ecu), did, control_parameter, control_option, control_option_type, endianness
    )


@action("Tester Present", "Send one tester present (0x3E).")
@_ecu_field
@action.boolean(
    "suppress_response",
    title="Suppress Positive Response",
    description="The ECU answers only on error; nothing is waited for.",
    default=False,
    widget="toggle",
    required=False,
)
def tester_present(ecu: str, suppress_response: bool = False) -> dict[str, Any]:
    return services.tester_present(_get_ecu(ecu), suppress_response)


@action(
    "Periodic Tester Present",
    "Start or stop tester present (suppressed response) every interval, to hold a "
    "non-default session. `state`: started, stopped or inactive.",
)
@_ecu_field
@action.boolean("enabled", title="Enable", default=False, widget="toggle", required=False)
@action.number(
    "interval",
    title="Interval (seconds)",
    minimum=0.5,
    maximum=10.0,
    multiple_of=0.1,
    default=2.0,
    widget="range",
    required=False,
)
def periodic_tester_present(ecu: str, enabled: bool = False, interval: float = 2.0) -> dict:
    return services.periodic_tester_present(_get_ecu(ecu), enabled, interval)


@action(
    "Read DTC Information",
    "Read DTCs (0x19): by status mask, their number, snapshot ids, a snapshot or extended "
    "data record of one DTC (raw hex), or every supported DTC.",
    read_only=True,
)
@_ecu_field
@action.select(
    "report", title="Report", choices=list(services.DTC_REPORTS), default="By Status Mask",
    required=False,
)  # fmt: skip
@action.select(
    "status_mask",
    title="DTC Status Mask",
    description="For By Status Mask and Number By Status Mask",
    choices=list(services.DTC_MASKS),
    default="All DTCs",
    required=False,
)
@action.text(
    "dtc", title="DTC (hex)", description="For Snapshot and Extended Data By DTC",
    placeholder="0A9400", default="", required=False,
)  # fmt: skip
@action.text(
    "record", title="Record Number", description="For Snapshot and Extended Data; 0xFF: all",
    default="0xFF", required=False,
)  # fmt: skip
def read_dtc(
    ecu: str,
    report: str = "By Status Mask",
    status_mask: str = "All DTCs",
    dtc: str = "",
    record: str = "0xFF",
) -> dict[str, Any]:
    return services.read_dtc(_get_ecu(ecu), status_mask, report, dtc, record)


@action("Clear Diagnostic Information", "Clear DTCs (0x14).")
@_ecu_field
@action.text(
    "group",
    title="DTC Group (hex)",
    description="3 bytes; FFFFFF clears every DTC",
    placeholder="FFFFFF",
    default="FFFFFF",
    required=False,
)
def clear_dtc(ecu: str, group: str = "FFFFFF") -> dict[str, Any]:
    return services.clear_dtc(_get_ecu(ecu), group)


@action("Control DTC Setting", "Turn DTC status updates on or off (0x85).")
@_ecu_field
@action.select("setting", title="Setting", choices=list(services.DTC_SETTINGS), default="Off",
               required=False)  # fmt: skip
def control_dtc_setting(ecu: str, setting: str = "Off") -> dict[str, Any]:
    return services.control_dtc_setting(_get_ecu(ecu), setting)


@action("Communication Control", "Enable or disable the ECU's transmission and reception (0x28).")
@_ecu_field
@action.select(
    "control_type", title="Control Type", choices=list(services.COMM_CONTROLS),
    default="Enable Rx And Tx", required=False,
)  # fmt: skip
@action.select(
    "communication_type", title="Communication Type", choices=list(services.COMM_TYPES),
    default="Normal", required=False,
)  # fmt: skip
def communication_control(
    ecu: str, control_type: str = "Enable Rx And Tx", communication_type: str = "Normal"
) -> dict[str, Any]:
    return services.communication_control(_get_ecu(ecu), control_type, communication_type)


@action(
    "Security Access",
    "Request a seed, or send a key (0x27). With no key and the ECU's key file, the seed is "
    "answered with the computed key.",
)
@_ecu_field
@action.text(
    "access_level",
    title="Access Level",
    description="requestSeed sub-function, odd: 0x01, 0x11, ...",
    default="0x01",
    required=False,
)
@action.text(
    "key",
    title="Security Key (hex, optional)",
    description="Empty: request a seed (and answer it with the key file, when set)",
    default="",
    required=False,
)
def security_access(ecu: str, access_level: str = "0x01", key: str = "") -> dict[str, Any]:
    return services.security_access(_get_ecu(ecu), access_level, key)


@action(
    "Read Memory By Address",
    "Read memory (0x23): 4-byte address, size in 1, 2 or 4 bytes.",
    read_only=True,
)
@_ecu_field
@action.text("address", title="Memory Address (hex)", placeholder="0x20000000")
@action.text("size", title="Size (bytes)", placeholder="4")
def read_memory(ecu: str, address: str, size: str) -> dict[str, Any]:
    return services.read_memory(_get_ecu(ecu), address, size)


@action("Write Memory By Address", "Write memory (0x3D): 4-byte address, size from the data.")
@_ecu_field
@action.text("address", title="Memory Address (hex)", placeholder="0x20000000")
@_data_fields("data", "Data", "01 02 03 04")
def write_memory(
    ecu: str,
    address: str,
    data: str = "",
    data_type: str = PAYLOAD_TYPE_HEX,
    endianness: str = ENDIANNESS_BIG,
) -> dict[str, Any]:
    return services.write_memory(_get_ecu(ecu), address, data, data_type, endianness)


@action("Request Download", "Start a download to the ECU (0x34).", hidden=True)
@_ecu_field
@action.text("address", title="Memory Address (hex)", placeholder="0x08000000")
@action.text("size", title="Data Size (bytes)", placeholder="1024")
def request_download(ecu: str, address: str, size: str) -> dict[str, Any]:
    return services.request_download(_get_ecu(ecu), address, size)


@action("Request Upload", "Start an upload from the ECU (0x35).", hidden=True)
@_ecu_field
@action.text("address", title="Memory Address (hex)", placeholder="0x08000000")
@action.text("size", title="Data Size (bytes)", placeholder="1024")
def request_upload(ecu: str, address: str, size: str) -> dict[str, Any]:
    return services.request_upload(_get_ecu(ecu), address, size)


@action(
    "Transfer Data",
    "Send one block of a download, or (data empty) fetch one block of an upload (0x36).",
    hidden=True,
)
@_ecu_field
@action.text("sequence", title="Sequence Number", description="0-255", default="1",
             required=False)  # fmt: skip
@action.text("data", title="Data (hex bytes)", placeholder="00 11 22 33", default="",
             required=False)  # fmt: skip
def transfer_data(ecu: str, sequence: str = "1", data: str = "") -> dict[str, Any]:
    return services.transfer_data(_get_ecu(ecu), sequence, data)


@action("Request Transfer Exit", "Finish a download or upload (0x37).", hidden=True)
@_ecu_field
def request_transfer_exit(ecu: str) -> dict[str, Any]:
    return services.request_transfer_exit(_get_ecu(ecu))


@action(
    "Upload Memory",
    f"Request upload, transfer and exit in one action. Written to File Path on the agent's "
    f"host, else returned as hex (up to {services.UPLOAD_INLINE_MAX} bytes).",
    timeout=FLASH_TIMEOUT,
)
@_ecu_field
@action.text("address", title="Memory Address (hex)", placeholder="0x08000000")
@action.text("size", title="Size (bytes)", placeholder="1024")
@action.text("file_path", title="File Path (optional)", placeholder="~/upload.bin", default="",
             required=False)  # fmt: skip
def upload_memory(ecu: str, address: str, size: str, file_path: str = "") -> dict[str, Any]:
    return services.upload_memory(_get_ecu(ecu), address, size, file_path)


@action(
    "Flash Firmware",
    "Extended and programming session, security (key or key file), optional erase "
    "routine, download, check routine, optional reset. Nothing else is sent to the ECU meanwhile; "
    "every step is reported.",
    timeout=FLASH_TIMEOUT,
)
@_ecu_field
@action.text("address", title="Memory Address (hex)", placeholder="0x08000000")
@action.text("file_path", title="Image File (raw binary, on the agent's host)", default="",
             required=False)  # fmt: skip
@action.text("data", title="Image Data (hex, instead of a file)", default="", required=False)
@action.integer(
    "block_size",
    title="Block Size (bytes)",
    description="Data bytes per TransferData, 0 for the most the ECU accepts",
    minimum=0,
    maximum=65535,
    default=0,
    required=False,
)
@action.boolean(
    "change_session", title="Enter Programming Session (via Extended)", default=True,
    widget="toggle", required=False,
)  # fmt: skip
@action.text("security_level", title="Security Level", description="requestSeed sub-function; "
             "empty: none", default="0x11", required=False)  # fmt: skip
@action.text("key", title="Security Key (hex)", description="Empty: the ECU's key file",
             default="", required=False)  # fmt: skip
@action.text("erase_routine", title="Erase Routine ID", description="Empty: no erase",
             default="", placeholder="0xFF00", required=False)  # fmt: skip
@action.boolean("erase_range", title="Erase Record: Address and Size", default=True,
                widget="toggle", required=False)  # fmt: skip
@action.text("check_routine", title="Check Routine ID", description="Record: CRC32 of the "
             "image. Empty: no check", default="0xFF01", required=False)  # fmt: skip
@action.select("reset", title="Reset After", choices=["None", *services.RESET_TYPES],
               default="None", required=False)  # fmt: skip
def flash_firmware(
    ecu: str,
    address: str,
    file_path: str = "",
    data: str = "",
    block_size: int = 0,
    change_session: bool = True,
    security_level: str = "0x11",
    key: str = "",
    erase_routine: str = "",
    erase_range: bool = True,
    check_routine: str = "0xFF01",
    reset: str = "None",
) -> dict[str, Any]:
    image = services.read_image(file_path, data)
    if isinstance(image, dict):
        return image
    plan = services.flash_plan(address, security_level, key, erase_routine, check_routine)
    if "error" in plan:
        return plan
    sessions = ("Extended Diagnostic Session", "Programming Session") if change_session else ()
    return services.flash_firmware(
        _get_ecu(ecu), plan["address"], image, int(block_size), sessions,
        plan["security_level"], plan["key"], plan["erase_routine"], erase_range,
        plan["check_routine"], None if reset == "None" else reset,
    )  # fmt: skip


# ─── Config form ────────────────────────────────────────────────────────────


@action(
    "Auto-configure",
    "One demo ECU, for the config form's Auto-configure button. Review it, then save and start.",
    standalone=True,
    read_only=True,
    hidden=True,
)
def auto_config() -> dict[str, Any]:
    """The app's auto-configure contract: the keys of `config` replace the form's.

    Only `ecus` is returned, so whatever is set under Advanced survives.
    """
    return {"status": "success", "config": {"ecus": [demo_ecu()]}}


@action(
    "List CAN Interfaces",
    "SocketCAN interfaces on the machine running the agent, as choices for an ECU's Channel "
    "field, which also accepts a name typed by hand. Empty on macOS/Windows, which have no "
    "SocketCAN.",
    standalone=True,
    read_only=True,
    hidden=True,
)
def list_interfaces() -> dict[str, Any]:
    """The app's `action-choices` contract. Reads sysfs only: no socket, no privileges."""
    return {"status": "success", "choices": discovery.list_interfaces()}


# ─── Registration helper ────────────────────────────────────────────────────


def register_actions(registry: ActionsRegistry) -> list[str]:
    """Register every @action-decorated free function in this module by its bare
    function name. The leading `UDS/` segment comes from
    `zelos_sdk.init(name=ACTION_PREFIX, actions=True)`."""
    module = sys.modules[__name__]
    registered: list[str] = []
    for name, obj in inspect.getmembers(module):
        if name.startswith("_"):
            continue
        if inspect.isfunction(obj) and hasattr(obj, "_action"):
            registry.register(obj, name=name)
            registered.append(name)
    logger.info("Registered %d UDS actions", len(registered))
    return registered
