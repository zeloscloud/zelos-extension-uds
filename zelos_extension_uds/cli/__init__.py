"""CLI commands for zelos-extension-uds."""

from .app import run_app_mode
from .clear import clear
from .comm import comm
from .demo_ecu import demo_ecu
from .dtc import dtc
from .dtc_setting import dtc_setting
from .flash import flash
from .io import io
from .memory import read_mem, upload, write_mem
from .read import read
from .reset import reset
from .routine import routine
from .security import security
from .session import session
from .tp import tp
from .write import write

#: Subcommands, in help order.
COMMANDS = [
    session, read, write, reset, routine, io, tp, dtc, clear, dtc_setting, comm, security,
    read_mem, write_mem, upload, flash, demo_ecu,
]  # fmt: skip

__all__ = ["COMMANDS", "run_app_mode"]
