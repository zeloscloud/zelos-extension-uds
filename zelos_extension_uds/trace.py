"""Trace events: one `tx` row per request, one `rx` row per response."""

from __future__ import annotations

import zelos_sdk
from udsoncan.BaseService import BaseService

_T = zelos_sdk.DataType
TX_FIELDS = [
    zelos_sdk.TraceEventFieldMetadata("service_id", _T.UInt8),
    zelos_sdk.TraceEventFieldMetadata("service_name", _T.String),
    zelos_sdk.TraceEventFieldMetadata("parameter", _T.UInt32),
    zelos_sdk.TraceEventFieldMetadata("data", _T.Binary),
]
RX_FIELDS = [
    *TX_FIELDS,
    zelos_sdk.TraceEventFieldMetadata("success", _T.Boolean),
    zelos_sdk.TraceEventFieldMetadata("nrc", _T.UInt8),
    zelos_sdk.TraceEventFieldMetadata("elapsed_ms", _T.Float32, "ms"),
]


def service_name(sid: int) -> str:
    service = BaseService.from_request_id(sid)
    return service.get_name() if service else f"Unknown_0x{sid:02X}"


class Trace:
    """An ECU's `tx` and `rx` events in `source`, under `event_prefix` when set."""

    def __init__(self, source: zelos_sdk.TraceSource, event_prefix: str | None) -> None:
        self._source = source
        self._tx = f"{event_prefix}/tx" if event_prefix else "tx"
        self._rx = f"{event_prefix}/rx" if event_prefix else "rx"
        source.add_event(self._tx, TX_FIELDS)
        source.add_event(self._rx, RX_FIELDS)

    def tx(self, sid: int, parameter: int, data: bytes) -> None:
        self._source.log(self._tx, _row(sid, parameter, data))

    def rx(self, sid: int, parameter: int, data: bytes, nrc: int, elapsed_s: float) -> None:
        row = _row(sid, parameter, data)
        row.update(success=nrc == 0, nrc=nrc, elapsed_ms=elapsed_s * 1000.0)
        self._source.log(self._rx, row)


def _row(sid: int, parameter: int, data: bytes) -> dict:
    return {
        "service_id": sid,
        "service_name": service_name(sid),
        "parameter": parameter & 0xFFFF_FFFF,
        "data": bytes(data),
    }
