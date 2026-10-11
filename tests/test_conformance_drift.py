"""The vendored conformance suite is the zelos-examples one, unedited."""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent / "conformance"))
import vendor  # noqa: E402


def test_vendored_copy_matches_its_manifest():
    recorded = vendor.manifest()
    assert set(recorded) == set(vendor.FILES)
    for name, sha in recorded.items():
        assert vendor.digest(vendor.HERE / name) == sha, f"{name} edited: change it upstream"


def test_upstream_has_not_moved_on():
    """Against a zelos-examples checkout named by ZELOS_EXAMPLES; skipped without one."""
    source = os.environ.get("ZELOS_EXAMPLES")
    if not source or not all((Path(source) / f).is_file() for f in vendor.FILES):
        pytest.skip("no zelos-examples checkout with the UDS suite (set ZELOS_EXAMPLES)")
    drifted = [f for f, sha in vendor.manifest().items() if vendor.digest(Path(source) / f) != sha]
    assert not drifted, f"run `just sync-conformance {source}`: {drifted}"
