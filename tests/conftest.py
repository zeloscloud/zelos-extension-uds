"""Shared test helpers, and the vendored conformance suite's pytest plugin."""

import os
import sys
from pathlib import Path

# The conformance suite's plugin and package (tests/conformance), on an in-process bus
# unless told otherwise. python-can's `virtual`, not zelos-virtual: the suite times
# frames by their receive timestamp, which zelos-virtual leaves at 0.
sys.path.insert(0, str(Path(__file__).parent / "conformance" / "testing" / "src"))
os.environ.setdefault("ZELOS_TEST_INTERFACE", "virtual")
os.environ.setdefault("ZELOS_TEST_CHANNEL", "uds-conformance")
pytest_plugins = ["zelos_testing.plugin"]


def pytest_configure(config):
    """Zelos SDK pytest plugin attributes."""
    config.zelos_local_artifacts_dir = None
    config.zelos_remote_artifacts_dir = None
    config.zelos_device_id = None
