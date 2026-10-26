"""Demo UDS ECU for the `Demo` interface, tests and `main.py demo-ecu`."""

from pathlib import Path

from zelos_extension_uds.demo.ecu import DemoEcu

#: The demo ECU's seed/key file, wherever the package is installed.
KEY_FILE = Path(__file__).with_name("key.py")

__all__ = ["KEY_FILE", "DemoEcu"]
