"""Unified Diagnostic Services (UDS) over CAN.

A Zelos extension for automotive diagnostics using UDS (ISO 14229) protocol.
"""

from zelos_extension_uds import cli

__all__: list[str] = [
    "cli",
]


def __getattr__(name: str):
    """Lazy import UDSClient to avoid import errors when only using CLI."""
    if name == "UDSClient":
        from zelos_extension_uds.extension import UDSClient

        return UDSClient
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
