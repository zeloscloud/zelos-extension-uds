"""The wire formats in the repository's dbc/."""

from pathlib import Path

import cantools

# testing/src/zelos_testing/ -> the repository root. The bench's tester mounts
# dbc/ at the same place relative to its copy of this package.
DBC_DIR = Path(__file__).resolve().parents[3] / "dbc"


def load(name: str) -> cantools.database.Database:
    """Load dbc/<name>.dbc."""
    return cantools.database.load_file(DBC_DIR / f"{name}.dbc")
