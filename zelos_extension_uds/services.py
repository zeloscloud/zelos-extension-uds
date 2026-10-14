"""UDS service bodies, shared by the actions and the CLI.

Inputs are the strings a form or command line carries; every function returns
a result dict: `status` `success` with the decoded response, or `error` with
`error`, plus `nrc` and `nrc_name` for a negative response.
"""

from __future__ import annotations

import logging
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

from udsoncan import Request
from udsoncan.common.MemoryLocation import MemoryLocation
from udsoncan.exceptions import NegativeResponseException, TimeoutException
from udsoncan.services import (
    ClearDiagnosticInformation,
    CommunicationControl,
    ControlDTCSetting,
    DiagnosticSessionControl,
    ECUReset,
    InputOutputControlByIdentifier,
    ReadDataByIdentifier,
    ReadDTCInformation,
    ReadMemoryByAddress,
    RequestDownload,
    RequestTransferExit,
    RequestUpload,
    RoutineControl,
    SecurityAccess,
    TesterPresent,
    TransferData,
    WriteDataByIdentifier,
    WriteMemoryByAddress,
)

from zelos_extension_uds.client import UdsEcu, Unavailable, tester_present_suppressed
from zelos_extension_uds.keys import compute_key
from zelos_extension_uds.utils import (
    ENDIANNESS_BIG,
    PAYLOAD_TYPE_HEX,
    format_hex_id,
    format_hex_string,
    format_typed_representations,
    parse_hex_string,
    parse_typed_payload,
    validate_hex_id,
)

logger = logging.getLogger(__name__)

SESSIONS = {
    "Default Session": DiagnosticSessionControl.Session.defaultSession,
    "Programming Session": DiagnosticSessionControl.Session.programmingSession,
    "Extended Diagnostic Session": DiagnosticSessionControl.Session.extendedDiagnosticSession,
    "Safety System Diagnostic Session": (
        DiagnosticSessionControl.Session.safetySystemDiagnosticSession
    ),
}
RESET_TYPES = {
    "Hard Reset": ECUReset.ResetType.hardReset,
    "Soft Reset": ECUReset.ResetType.softReset,
    "Key Off On Reset": ECUReset.ResetType.keyOffOnReset,
}
ROUTINE_CONTROLS = {
    "Start Routine": RoutineControl.ControlType.startRoutine,
    "Stop Routine": RoutineControl.ControlType.stopRoutine,
    "Request Results": RoutineControl.ControlType.requestRoutineResults,
}
IO_CONTROLS = {
    "Return Control To ECU": InputOutputControlByIdentifier.ControlParam.returnControlToECU,
    "Reset To Default": InputOutputControlByIdentifier.ControlParam.resetToDefault,
    "Freeze Current State": InputOutputControlByIdentifier.ControlParam.freezeCurrentState,
    "Short Term Adjustment": InputOutputControlByIdentifier.ControlParam.shortTermAdjustment,
}
DTC_MASKS = {
    "All DTCs": 0xFF,
    "Test Failed": 0x01,
    "Test Failed This Operation Cycle": 0x02,
    "Pending DTC": 0x04,
    "Confirmed DTC": 0x08,
    "Test Not Completed Since Last Clear": 0x10,
    "Test Failed Since Last Clear": 0x20,
    "Test Not Completed This Operation Cycle": 0x40,
    "Warning Indicator Requested": 0x80,
}
#: ReadDTCInformation sub-functions offered.
DTC_REPORTS = {
    "By Status Mask": 0x02,
    "Number By Status Mask": 0x01,
    "Snapshot Identification": 0x03,
    "Snapshot By DTC": 0x04,
    "Extended Data By DTC": 0x06,
    "Supported DTCs": 0x0A,
}
#: 0.1.x security level labels -> requestSeed sub-function.
SECURITY_LEVELS = {"Level 1": 1, "Level 2": 3, "Level 3": 5, "Level 4": 7}
COMM_CONTROLS = {
    "Enable Rx And Tx": 0x00,
    "Enable Rx Disable Tx": 0x01,
    "Disable Rx Enable Tx": 0x02,
    "Disable Rx And Tx": 0x03,
}
COMM_TYPES = {"Normal": 0x01, "Network Management": 0x02, "Normal And Network Management": 0x03}
DTC_SETTINGS = {"On": ControlDTCSetting.SettingType.on, "Off": ControlDTCSetting.SettingType.off}
#: Largest upload returned as hex in the result; larger ones need a file path.
UPLOAD_INLINE_MAX = 4096


def error(message: str, **extra: Any) -> dict[str, Any]:
    return {"status": "error", "error": message, **extra}


def _call(
    ecu: UdsEcu,
    service: Any,
    parameter: int,
    call: Callable[[Any], Any],
    ok: Callable[[Any], dict[str, Any]],
) -> dict[str, Any]:
    """One request on `ecu`, its outcome as a result dict. NRCs and timeouts are logged here
    (once; the library's own lines are off unless `debug_frames`)."""
    sid = service.request_id()
    try:
        response, elapsed = ecu.request(sid, parameter, call)
    except NegativeResponseException as e:
        code, name = e.response.code, e.response.code_name
        logger.warning("[%s] %s: NRC %s (0x%02X)", ecu.name, service.get_name(), name, code)
        return error(f"NRC: {name} (0x{code:02X})", nrc=code, nrc_name=name)
    except Unavailable as e:
        return error(f"ECU {ecu.name} unavailable: {e}")
    except TimeoutException:
        logger.warning("[%s] %s: timeout", ecu.name, service.get_name())
        return error("Timeout waiting for response")
    except Exception as e:
        logger.warning("[%s] %s: %s", ecu.name, service.get_name(), e)
        return error(str(e) or type(e).__name__)
    return {"status": "success", **ok(response), "elapsed_ms": round(elapsed * 1000, 2)}


def _hex_id(text: str, label: str) -> int | dict[str, Any]:
    value = validate_hex_id(text)
    return error(f"Invalid {label}: {value['error']}") if isinstance(value, dict) else value


def _number(text: str | int, label: str) -> int | dict[str, Any]:
    """Decimal, or hex with 0x."""
    if isinstance(text, int):
        return text
    try:
        return int(str(text).strip(), 0)
    except ValueError:
        return error(f"Invalid {label}: '{text}' is not a number (decimal, or hex with 0x)")


def _payload(text: str, data_type: str, endianness: str) -> bytes | dict[str, Any]:
    """Optional typed payload: empty text is no bytes."""
    if not text.strip():
        return b""
    value = parse_typed_payload(text, data_type, endianness)
    return error(value["error"]) if isinstance(value, dict) else value


def memory_location(address: int, size: int) -> MemoryLocation:
    """addressAndLengthFormatIdentifier from the values: 4-byte addresses (5 above 32 bits),
    sizes in 1, 2 or 4 bytes."""
    address_bytes = max(4, (address.bit_length() + 7) // 8)
    size_bytes = next(n for n in (1, 2, 4) if size < 1 << (8 * n))
    return MemoryLocation(address, size, 8 * address_bytes, 8 * size_bytes)


# ─── Sessions, data, routines ───────────────────────────────────────────────


def session_control(ecu: UdsEcu, session_type: str) -> dict[str, Any]:
    session = SESSIONS.get(session_type)
    if session is None:
        return error(f"Unknown session type: {session_type}")
    return _call(
        ecu,
        DiagnosticSessionControl,
        session,
        lambda c: c.change_session(session),
        lambda r: {"session_type": session_type},
    )


def read_did(ecu: UdsEcu, did: str) -> dict[str, Any]:
    did_int = _hex_id(did, "DID")
    if isinstance(did_int, dict):
        return did_int

    def ok(response: Any) -> dict[str, Any]:
        data = response.service_data.values.get(did_int, b"")
        out = {"did": format_hex_id(did_int, 4), "data": format_hex_string(data)}
        out["length"] = len(data)
        if representations := format_typed_representations(data):
            out["representations"] = representations
        return out

    return _call(
        ecu, ReadDataByIdentifier, did_int, lambda c: c.read_data_by_identifier([did_int]), ok
    )


def write_did(
    ecu: UdsEcu,
    did: str,
    data: str,
    data_type: str = PAYLOAD_TYPE_HEX,
    endianness: str = ENDIANNESS_BIG,
) -> dict[str, Any]:
    did_int = _hex_id(did, "DID")
    if isinstance(did_int, dict):
        return did_int
    value = parse_typed_payload(data, data_type, endianness)
    if isinstance(value, dict):
        return error(value["error"])
    return _call(
        ecu,
        WriteDataByIdentifier,
        did_int,
        lambda c: c.write_data_by_identifier(did_int, value),
        lambda r: {"did": format_hex_id(did_int, 4), "data_written": format_hex_string(value)},
    )


def ecu_reset(ecu: UdsEcu, reset_type: str, suppress_response: bool = False) -> dict[str, Any]:
    reset = RESET_TYPES.get(reset_type)
    if reset is None:
        return error(f"Invalid reset type: {reset_type}")

    def call(c: Any) -> Any:
        if not suppress_response:
            return c.ecu_reset(reset)
        with c.suppress_positive_response(wait_nrc=False):
            return c.ecu_reset(reset)

    def ok(response: Any) -> dict[str, Any]:
        out: dict[str, Any] = {"reset_type": reset_type}
        power_down = getattr(response.service_data, "powerdown_time", None) if response else None
        if power_down is not None:
            out["power_down_time_ms"] = power_down
        return out

    return _call(ecu, ECUReset, reset, call, ok)


def routine_control(
    ecu: UdsEcu,
    routine_id: str,
    control_type: str,
    data: str = "",
    data_type: str = PAYLOAD_TYPE_HEX,
    endianness: str = ENDIANNESS_BIG,
) -> dict[str, Any]:
    control = ROUTINE_CONTROLS.get(control_type)
    if control is None:
        return error(f"Invalid control type: {control_type}")
    rid = _hex_id(routine_id, "routine ID")
    if isinstance(rid, dict):
        return rid
    payload = _payload(data, data_type, endianness)
    if isinstance(payload, dict):
        return payload

    def ok(response: Any) -> dict[str, Any]:
        out = {"control_type": control_type, "routine_id": format_hex_id(rid, 4)}
        record = getattr(response.service_data, "routine_status_record", None)
        if record:
            out["response_data"] = format_hex_string(record)
        return out

    return _call(
        ecu,
        RoutineControl,
        rid,
        lambda c: c.routine_control(rid, control, data=payload or None),
        ok,
    )


def io_control(
    ecu: UdsEcu,
    did: str,
    control_parameter: str,
    control_option: str = "",
    control_option_type: str = PAYLOAD_TYPE_HEX,
    endianness: str = ENDIANNESS_BIG,
) -> dict[str, Any]:
    param = IO_CONTROLS.get(control_parameter)
    if param is None:
        return error(f"Invalid control parameter: {control_parameter}")
    did_int = _hex_id(did, "DID")
    if isinstance(did_int, dict):
        return did_int
    option = _payload(control_option, control_option_type, endianness)
    if isinstance(option, dict):
        return option

    def ok(response: Any) -> dict[str, Any]:
        out = {"did": format_hex_id(did_int, 4), "control_parameter": control_parameter}
        state = getattr(response.service_data, "decoded_data", None)
        if state:
            out["control_state"] = format_hex_string(state)
        return out

    return _call(
        ecu,
        InputOutputControlByIdentifier,
        did_int,
        # One value for the codec, which takes bytes as they are.
        lambda c: c.io_control(did_int, param, values=[option] if option else None),
        ok,
    )


def tester_present(ecu: UdsEcu, suppress_response: bool = False) -> dict[str, Any]:
    call = tester_present_suppressed if suppress_response else (lambda c: c.tester_present())
    return _call(
        ecu,
        TesterPresent,
        0x00,
        call,
        lambda r: {"suppress_response": True} if suppress_response else {},
    )


def periodic_tester_present(ecu: UdsEcu, enabled: bool, interval: float) -> dict[str, Any]:
    if not enabled:
        was = ecu.tp_period is not None
        ecu.set_tester_present(None)
        if was:
            logger.info("[%s] periodic tester present stopped", ecu.name)
        return {"status": "success", "state": "stopped" if was else "inactive"}
    if interval <= 0:
        return error("Interval must be positive")
    ecu.set_tester_present(float(interval))
    logger.info("[%s] periodic tester present every %gs", ecu.name, interval)
    return {"status": "success", "state": "started", "interval": interval}


# ─── DTCs ───────────────────────────────────────────────────────────────────


def _dtc_list(dtcs: Any) -> list[dict[str, str]]:
    return [{"id": f"0x{d.id:06X}", "status": f"0x{d.status.get_byte_as_int():02X}"} for d in dtcs]


def read_dtc(
    ecu: UdsEcu,
    status_mask: str | int = "All DTCs",
    report: str = "By Status Mask",
    dtc: str = "",
    record: str = "0xFF",
) -> dict[str, Any]:
    """ReadDTCInformation `report`. `status_mask` for the mask reports; `dtc` and `record`
    (0xFF: all) for snapshot and extended data, returned as raw hex records."""
    sub = DTC_REPORTS.get(report)
    if sub is None:
        return error(f"Unknown DTC report: {report}")
    mask = status_mask if isinstance(status_mask, int) else DTC_MASKS.get(status_mask)
    if mask is None:
        return error(f"Unknown status mask: {status_mask}")
    if sub in (0x04, 0x06):
        dtc_int, record_int = _hex_id(dtc, "DTC"), _number(record, "record number")
        if isinstance(dtc_int, dict) or isinstance(record_int, dict):
            return dtc_int if isinstance(dtc_int, dict) else record_int
        if dtc_int > 0xFFFFFF or not 0 <= record_int <= 0xFF:
            return error("DTC must fit 3 bytes and the record number 1 byte")
        raw = dtc_int.to_bytes(3, "big") + bytes([record_int])

    def raw_request(data: bytes = b"") -> Callable[[Any], Any]:
        return lambda c: c.send_request(Request(ReadDTCInformation, subfunction=sub, data=data))

    if sub == 0x01:
        call = lambda c: c.get_number_of_dtc_by_status_mask(mask)  # noqa: E731
        ok = lambda r: {"dtc_count": r.service_data.dtc_count}  # noqa: E731
    elif sub == 0x02:
        call = lambda c: c.get_dtc_by_status_mask(mask)  # noqa: E731
        ok = lambda r: _dtcs(_dtc_list(r.service_data.dtcs))  # noqa: E731
    elif sub == 0x0A:
        call = lambda c: c.get_supported_dtc()  # noqa: E731
        ok = lambda r: _dtcs(_dtc_list(r.service_data.dtcs))  # noqa: E731
    elif sub == 0x03:
        call = raw_request()

        def ok(r: Any) -> dict[str, Any]:
            body = bytes(r.data[1:])
            records = [
                {"id": f"0x{body[i : i + 3].hex().upper()}", "record": body[i + 3]}
                for i in range(0, len(body) - 3, 4)
            ]
            return {"records": records, "count": len(records)}
    else:
        call = raw_request(raw)

        def ok(r: Any) -> dict[str, Any]:
            body = bytes(r.data[1:])
            if len(body) < 4:
                return {"id": f"0x{dtc_int:06X}", "records": ""}
            status = f"0x{body[3]:02X}"
            return {"id": f"0x{body[:3].hex().upper()}", "dtc_status": status,
                    "records": format_hex_string(body[4:])}  # fmt: skip

    result = _call(ecu, ReadDTCInformation, sub, call, ok)
    return {**result, "report": report} if result["status"] == "success" else result


def _dtcs(dtcs: list[dict[str, str]]) -> dict[str, Any]:
    return {"dtc_count": len(dtcs), "dtcs": dtcs}


def clear_dtc(ecu: UdsEcu, group: str = "FFFFFF") -> dict[str, Any]:
    group_bytes = parse_hex_string(group)
    if isinstance(group_bytes, dict):
        return error(f"Invalid group: {group_bytes['error']}")
    if len(group_bytes) != 3:
        return error(f"Group must be 3 bytes, got {len(group_bytes)}")
    group_int = int.from_bytes(group_bytes, "big")
    return _call(
        ecu,
        ClearDiagnosticInformation,
        group_int,
        lambda c: c.clear_dtc(group_int),
        lambda r: {"group": f"0x{group_int:06X}"},
    )


def control_dtc_setting(ecu: UdsEcu, setting: str) -> dict[str, Any]:
    value = DTC_SETTINGS.get(setting)
    if value is None:
        return error(f"Unknown DTC setting: {setting}")
    return _call(
        ecu,
        ControlDTCSetting,
        value,
        lambda c: c.control_dtc_setting(value),
        lambda r: {"setting": setting},
    )


def communication_control(
    ecu: UdsEcu, control_type: str, communication_type: str = "Normal"
) -> dict[str, Any]:
    control, kind = COMM_CONTROLS.get(control_type), COMM_TYPES.get(communication_type)
    if control is None or kind is None:
        return error(f"Unknown control or communication type: {control_type}, {communication_type}")
    return _call(
        ecu,
        CommunicationControl,
        control,
        lambda c: c.communication_control(control, kind),
        lambda r: {"control_type": control_type, "communication_type": communication_type},
    )


# ─── Security ───────────────────────────────────────────────────────────────


def _level(access_level: str | int) -> int | dict[str, Any]:
    """requestSeed sub-function: a 0.1.x label, or the number (odd, 0x01-0x7D)."""
    level = SECURITY_LEVELS.get(access_level) if isinstance(access_level, str) else None
    level = level if level is not None else _number(access_level, "access level")
    if isinstance(level, dict) or level % 2 == 0 or not 0 < level < 0x7F:
        return error(f"Invalid access level: {access_level} (an odd requestSeed sub-function)")
    return level


def security_access(ecu: UdsEcu, access_level: str | int, key: str = "") -> dict[str, Any]:
    """`key` given: send it. Empty: request the seed; with the ECU's key file, also compute
    and send the key. Keys are never logged."""
    level = _level(access_level)
    if isinstance(level, dict):
        return level
    if key.strip():
        key_bytes = parse_hex_string(key)
        if isinstance(key_bytes, dict):
            return error(f"Invalid key: {key_bytes['error']}")
        return _send_key(ecu, level, key_bytes)
    return _unlock(ecu, level, access_level)


def _unlock(
    ecu: UdsEcu, level: int, access_level: str | int, key: bytes | None = None
) -> dict[str, Any]:
    """requestSeed, then sendKey with `key`, else the key file's. Neither: the seed only."""
    with ecu.busy("security_access"):  # seed and key back to back
        seed = _call(
            ecu,
            SecurityAccess,
            level,
            lambda c: c.request_seed(level),
            lambda r: {"seed": format_hex_string(r.service_data.seed or b"")},
        )
        if seed["status"] != "success" or (key is None and ecu.key_fn is None):
            return {**seed, "operation": "request_seed", "access_level": access_level}
        raw = bytes.fromhex(seed["seed"][2:]) if seed["seed"] else b""
        if not any(raw):
            return {**seed, "operation": "already_unlocked", "access_granted": True}
        if key is None:
            try:
                key = compute_key(ecu.key_fn, level, raw)
            except ValueError as e:
                return error(str(e))
        return {**_send_key(ecu, level, key), "seed": seed["seed"]}


def _send_key(ecu: UdsEcu, level: int, key: bytes) -> dict[str, Any]:
    return _call(
        ecu,
        SecurityAccess,
        level + 1,
        lambda c: c.send_key(level + 1, key),
        lambda r: {"operation": "send_key", "access_level": level, "access_granted": True},
    )


# ─── Memory ─────────────────────────────────────────────────────────────────


def _address_size(address: str, size: str | int) -> tuple[int, int] | dict[str, Any]:
    address_int = _hex_id(address, "address")
    if isinstance(address_int, dict):
        return address_int
    size_int = _number(size, "size")
    if isinstance(size_int, dict):
        return size_int
    if not 0 < size_int < 1 << 32:
        return error("Size must be 1 to 2^32-1 bytes")
    return address_int, size_int


def read_memory(ecu: UdsEcu, address: str, size: str | int) -> dict[str, Any]:
    span = _address_size(address, size)
    if isinstance(span, dict):
        return span
    address_int, size_int = span

    def ok(response: Any) -> dict[str, Any]:
        block = bytes(response.service_data.memory_block)
        out = {"address": f"0x{address_int:08X}", "data": format_hex_string(block)}
        out["length"] = len(block)
        if representations := format_typed_representations(block):
            out["representations"] = representations
        return out

    return _call(
        ecu,
        ReadMemoryByAddress,
        address_int,
        lambda c: c.read_memory_by_address(memory_location(address_int, size_int)),
        ok,
    )


def write_memory(
    ecu: UdsEcu,
    address: str,
    data: str,
    data_type: str = PAYLOAD_TYPE_HEX,
    endianness: str = ENDIANNESS_BIG,
) -> dict[str, Any]:
    address_int = _hex_id(address, "address")
    if isinstance(address_int, dict):
        return address_int
    value = parse_typed_payload(data, data_type, endianness)
    if isinstance(value, dict):
        return error(value["error"])
    location = memory_location(address_int, len(value))
    return _call(
        ecu,
        WriteMemoryByAddress,
        address_int,
        lambda c: c.write_memory_by_address(location, value),
        lambda r: {"address": f"0x{address_int:08X}", "data_written": format_hex_string(value)},
    )


def _transfer_request(ecu: UdsEcu, service: Any, address: str, size: str | int) -> dict:
    span = _address_size(address, size)
    if isinstance(span, dict):
        return span
    address_int, size_int = span
    method = "request_download" if service is RequestDownload else "request_upload"
    return _call(
        ecu,
        service,
        address_int,
        lambda c: getattr(c, method)(memory_location(address_int, size_int)),
        lambda r: {
            "address": f"0x{address_int:08X}",
            "size": size_int,
            "max_block_size": r.service_data.max_length,
        },
    )


def request_download(ecu: UdsEcu, address: str, size: str | int) -> dict[str, Any]:
    return _transfer_request(ecu, RequestDownload, address, size)


def request_upload(ecu: UdsEcu, address: str, size: str | int) -> dict[str, Any]:
    return _transfer_request(ecu, RequestUpload, address, size)


def transfer_data(ecu: UdsEcu, sequence: str | int, data: str = "") -> dict[str, Any]:
    """One TransferData. `data` empty for an upload block, which is returned."""
    seq = _number(sequence, "sequence")
    if isinstance(seq, dict):
        return seq
    if not 0 <= seq <= 255:
        return error("Sequence must be 0-255")
    block = parse_hex_string(data) if data.strip() else b""
    if isinstance(block, dict):
        return error(block["error"])

    def ok(response: Any) -> dict[str, Any]:
        out: dict[str, Any] = {"sequence": seq, "bytes_transferred": len(block)}
        received = response.service_data.parameter_records
        if received:
            out["data"] = format_hex_string(received)
        return out

    return _call(ecu, TransferData, seq, lambda c: c.transfer_data(seq, block or None), ok)


def request_transfer_exit(ecu: UdsEcu) -> dict[str, Any]:
    return _call(ecu, RequestTransferExit, 0, lambda c: c.request_transfer_exit(), lambda r: {})


def upload_memory(
    ecu: UdsEcu, address: str, size: str | int, file_path: str = ""
) -> dict[str, Any]:
    """RequestUpload, TransferData until `size` bytes, RequestTransferExit. Written to
    `file_path` on the agent's host, else returned as hex up to UPLOAD_INLINE_MAX bytes."""
    span = _address_size(address, size)
    if isinstance(span, dict):
        return span
    size_int = span[1]
    if not file_path and size_int > UPLOAD_INLINE_MAX:
        return error(f"Uploads over {UPLOAD_INLINE_MAX} bytes need a file path")
    data = bytearray()
    try:
        with ecu.busy("upload_memory"):
            for name, result in _upload_steps(ecu, address, size_int, data):
                if result["status"] != "success":
                    return {**result, "error": f"{name}: {result['error']}"}
    except Unavailable as e:
        return error(f"ECU {ecu.name} unavailable: {e}")
    out: dict[str, Any] = {
        "status": "success",
        "size": len(data),
        "crc32": f"0x{zlib.crc32(data):08X}",
    }
    if file_path:
        path = Path(file_path).expanduser()
        try:
            path.write_bytes(data)
        except OSError as e:
            return error(f"cannot write {path}: {e.strerror or e}")
        out["file_path"] = str(path)
    else:
        out["data"] = format_hex_string(bytes(data))
    return out


def _upload_steps(ecu: UdsEcu, address: str, size: int, data: bytearray):
    yield "request_upload", request_upload(ecu, address, size)
    seq = 1
    while len(data) < size:
        block = transfer_data(ecu, seq)
        if block["status"] == "success":
            received = bytes.fromhex(block.get("data", "0x")[2:])
            if not received or len(data) + len(received) > size:
                block = error(f"block {seq} carried {len(received)} bytes, {size - len(data)} left")
            else:
                data += received
        yield "transfer_data", block
        seq = (seq + 1) % 256
    yield "request_transfer_exit", request_transfer_exit(ecu)


# ─── Flash ──────────────────────────────────────────────────────────────────


def read_image(file_path: str, data: str) -> bytes | dict[str, Any]:
    """The image from a file on the agent's host, else from hex."""
    if file_path.strip():
        path = Path(file_path).expanduser()
        try:
            return path.read_bytes()
        except OSError as e:
            return error(f"cannot read {path}: {e.strerror or e}")
    image = parse_hex_string(data)
    return error(f"Invalid image data: {image['error']}") if isinstance(image, dict) else image


def flash_plan(
    address: str, security_level: str, key: str, erase_routine: str, check_routine: str
) -> dict[str, Any]:
    """Form strings parsed for `flash_firmware`; empty means skip. An `error` key on failure."""
    plan: dict[str, Any] = {"address": _hex_id(address, "address")}
    plan["security_level"] = _level(security_level) if security_level.strip() else None
    plan["key"] = parse_hex_string(key) if key.strip() else None
    for name, text in (("erase_routine", erase_routine), ("check_routine", check_routine)):
        plan[name] = _hex_id(text, name.replace("_", " ")) if text.strip() else None
    for value in plan.values():
        if isinstance(value, dict):
            return value if "status" in value else error(value["error"])
    return plan


def flash_firmware(
    ecu: UdsEcu,
    address: int,
    firmware: bytes,
    block_size: int = 0,
    sessions: tuple[str, ...] = ("Extended Diagnostic Session", "Programming Session"),
    security_level: int | None = 0x11,
    key: bytes | None = None,
    erase_routine: int | None = None,
    erase_range: bool = True,
    check_routine: int | None = 0xFF01,
    reset: str | None = None,
    tester_present_every: int = 0,
) -> dict[str, Any]:
    """Production sequence, holding the ECU throughout: `sessions` in order, security
    (requestSeed, then `key`, else the key file's; skipped with neither), erase routine if
    given (record: ALFID 0x44, address, size when `erase_range`), RequestDownload,
    TransferData blocks, RequestTransferExit, check routine (record: CRC32 of the image; a
    non-zero first result byte fails), ECU reset. Every step is in `steps`; the first
    failure ends it.

    `block_size`: data bytes per TransferData, 0 for the most the ECU accepts
    (its maxNumberOfBlockLength less the SID and sequence bytes).
    """
    if not firmware:
        return error("Firmware data is empty")
    steps: list[dict[str, Any]] = []
    logger.info("[%s] flashing %d bytes at 0x%08X", ecu.name, len(firmware), address)
    try:
        with ecu.busy("flash_firmware"):
            failed = _flash(
                ecu, address, firmware, block_size, sessions, security_level, key,
                erase_routine, erase_range, check_routine, reset, tester_present_every, steps,
            )  # fmt: skip
    except Unavailable as e:
        return error(f"ECU {ecu.name} unavailable: {e}", steps=steps)
    if failed:
        return failed
    transfer = next(s for s in steps if s["step"] == "transfer_data")
    logger.info("[%s] flashed %d blocks", ecu.name, transfer["blocks"])
    return {
        "status": "success",
        "address": f"0x{address:08X}",
        "size": len(firmware),
        "crc32": f"0x{zlib.crc32(firmware):08X}",
        "blocks": transfer["blocks"],
        "block_size": transfer["block_size"],
        "steps": steps,
    }


def _flash(
    ecu: UdsEcu,
    address: int,
    firmware: bytes,
    block_size: int,
    sessions: tuple[str, ...],
    security_level: int | None,
    key: bytes | None,
    erase_routine: int | None,
    erase_range: bool,
    check_routine: int | None,
    reset: str | None,
    tester_present_every: int,
    steps: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Runs the steps into `steps`; the error result of the first failure, else None."""

    def step(name: str, result: dict[str, Any], **extra: Any) -> dict[str, Any] | None:
        keep = ("status", "elapsed_ms", "error", "nrc", "nrc_name", "response_data")
        steps.append({"step": name, **{k: result[k] for k in keep if k in result}, **extra})
        if result["status"] == "success":
            return None
        return {**result, "error": f"{name}: {result['error']}", "failed_step": name,
                "steps": steps, **extra}  # fmt: skip

    for session in sessions:
        name = "session_" + session.split()[0].lower()
        if failed := step(name, session_control(ecu, session)):
            return failed
    if security_level and (key or ecu.key_fn):
        result = _unlock(ecu, security_level, security_level, key)
        if failed := step("security_access", result):
            return failed
    elif security_level:
        steps.append(
            {"step": "security_access", "status": "skipped", "reason": "no key or key file"}
        )
    if erase_routine is not None:
        record = b"\x44" + address.to_bytes(4, "big") + len(firmware).to_bytes(4, "big")
        data = record.hex() if erase_range else ""
        if failed := step("erase", routine_control(ecu, hex(erase_routine), "Start Routine", data)):
            return failed
    download = request_download(ecu, hex(address), len(firmware))
    if failed := step("request_download", download):
        return failed
    most = download["max_block_size"] - 2
    if most <= 0:
        return step("request_download", error(f"ECU block length {most + 2} leaves no room"))
    size = min(block_size, most) if block_size > 0 else most
    blocks = (len(firmware) + size - 1) // size
    for n in range(blocks):
        if tester_present_every and n and n % tester_present_every == 0:
            tester_present(ecu, suppress_response=True)
        result = transfer_data(ecu, (n + 1) % 256, firmware[n * size : (n + 1) * size].hex())
        if result["status"] != "success":
            return step("transfer_data", result, blocks_transferred=n, block_size=size)
    steps.append(
        {"step": "transfer_data", "status": "success", "blocks": blocks, "block_size": size}
    )
    if failed := step("request_transfer_exit", request_transfer_exit(ecu)):
        return failed
    if check_routine is not None:
        crc = f"{zlib.crc32(firmware):08X}"
        result = routine_control(ecu, hex(check_routine), "Start Routine", crc)
        status = result.get("response_data", "0x00")[2:4]
        if result["status"] == "success" and status not in ("", "00"):
            result = {**result, **error(f"the ECU reported 0x{status}")}
        if failed := step("check_dependencies", result):
            return failed
    if reset and (failed := step("ecu_reset", ecu_reset(ecu, reset))):
        return failed
    return None
