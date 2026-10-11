"""Zelos UDS

A Zelos extension for UDS (ISO 14229) diagnostics over CAN with ISO-TP.
"""

#: Action namespace for this extension. Single source for both surfaces: the
#: live registration (`zelos_sdk.init(name=ACTION_PREFIX)`) and the at-rest
#: inventory the packaging step dumps from `main.py`, which re-exports this.
#: A mismatch would silently produce two unrelated action trees.
#:
#: Matches `name` in `extension.toml`, which is what a user sees in the
#: extension list, so the address they read there is the address they type.
ACTION_PREFIX = "UDS"

__all__: list[str] = ["ACTION_PREFIX"]
