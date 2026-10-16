"""The vendored zelos-examples UDS conformance suite: what is copied, and its manifest.

`just sync-conformance PATH` copies FILES from a zelos-examples checkout at PATH
and records their SHA-256 in MANIFEST. Edit them there, never here: the drift
test fails on a vendored copy that differs from the manifest.
"""

import hashlib
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).parent
MANIFEST = HERE / "MANIFEST"
#: Repository-relative, as in zelos-examples.
FILES = (
    "testing/src/zelos_testing/__init__.py",
    "testing/src/zelos_testing/frames.py",
    "testing/src/zelos_testing/plugin.py",
    "testing/src/zelos_testing/uds.py",
    "testing/src/zelos_testing/uds_keys.py",
    "testing/suites/uds/conftest.py",
    "testing/suites/uds/test_uds_conformance.py",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest() -> dict[str, str]:
    lines = MANIFEST.read_text().splitlines()
    return {name: sha for sha, name in (line.split("  ", 1) for line in lines if line)}


def sync(source: Path) -> None:
    lines = []
    for name in FILES:
        target = HERE / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
        lines.append(f"{digest(target)}  {name}")
    MANIFEST.write_text("\n".join(lines) + "\n")
    print(f"vendored {len(FILES)} files from {source}")


if __name__ == "__main__":
    sync(Path(sys.argv[1]).expanduser())
