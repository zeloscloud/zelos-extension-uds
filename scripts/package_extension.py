#!/usr/bin/env python3
"""Package the Zelos extension into a tar.gz archive."""

import sys
import tarfile
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore


def filter_archive_files(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo | None:
    """Filter out unwanted files from archive per Zelos security requirements.

    :param tarinfo: Tar member info
    :return: None if should be excluded, tarinfo otherwise
    """
    # Skip Python cache files
    if "__pycache__" in tarinfo.name or tarinfo.name.endswith((".pyc", ".pyo")):
        return None

    # Skip hidden files/directories (security requirement)
    parts = Path(tarinfo.name).parts
    if any(part.startswith(".") for part in parts):
        return None

    # Ensure no symlinks or special files (security requirement)
    if tarinfo.issym() or tarinfo.islnk():
        print(f"WARNING: Skipping symlink: {tarinfo.name}")
        return None
    if not (tarinfo.isfile() or tarinfo.isdir()):
        print(f"WARNING: Skipping special file: {tarinfo.name}")
        return None

    return tarinfo


def main() -> None:
    """Package the extension."""
    # Load manifest
    try:
        with Path("extension.toml").open("rb") as f:
            manifest = tomllib.load(f)
    except FileNotFoundError:
        print("ERROR: extension.toml not found")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to parse extension.toml: {e}")
        sys.exit(1)

    version = manifest.get("version")
    if not version:
        print("ERROR: No version in extension.toml")
        sys.exit(1)

    # Collect files to package
    files = ["extension.toml"]  # Always required

    runtime = manifest.get("runtime", {})
    if "entry" in runtime:
        files.append(runtime["entry"])
    if "requirements" in runtime:
        req_file = runtime["requirements"]
        if Path(req_file).exists():
            files.append(req_file)

    if Path("pyproject.toml").exists():
        files.append("pyproject.toml")
    if Path("uv.lock").exists():
        files.append("uv.lock")

    # Add optional files referenced in manifest
    # (skip files in assets/ directory since we'll add the whole directory)
    for key in ["icon", "readme", "changelog"]:
        if key in manifest:
            file_path = manifest[key]
            # Only add if not in assets directory
            if not file_path.startswith("assets/"):
                files.append(file_path)

    # Add config schema if present
    config = manifest.get("config", {})
    if "schema" in config:
        files.append(config["schema"])

    # Add assets directory if it exists (includes icon and other assets)
    if Path("assets").exists():
        files.append("assets")

    # Add Python packages from root directory
    exclude_dirs = {
        "tests",
        "test",
        "__pycache__",
        ".venv",
        ".git",
        ".vscode",
        ".github",
        "scripts",
    }
    for path in Path().iterdir():
        if path.is_dir() and path.name not in exclude_dirs and (path / "__init__.py").exists():
            files.append(path.name)

    # Create archive
    project_name = Path.cwd().name
    archive_name = f"{project_name}-v{version}.tar.gz"

    print(f"Creating {archive_name}...")
    print("Packaging files for Zelos marketplace...")

    with tarfile.open(archive_name, "w:gz") as tar:
        for file_path in sorted(set(files)):
            path = Path(file_path)
            if not path.exists():
                print(f"ERROR: Required file missing: {file_path}")
                sys.exit(1)

            tar.add(file_path, arcname=file_path, filter=filter_archive_files)
            print(f"  + {file_path}")

    # Verify archive size constraints
    archive_path = Path(archive_name)
    size_bytes = archive_path.stat().st_size
    size_kb = size_bytes / 1024
    size_mb = size_kb / 1024

    # Check against Zelos marketplace limits
    MAX_SIZE_MB = 500
    if size_mb > MAX_SIZE_MB:
        print(f"\n❌ ERROR: Archive too large ({size_mb:.1f} MB > {MAX_SIZE_MB} MB limit)")
        sys.exit(1)

    print(f"\n✓ Package created: {archive_name}")
    print(f"  Size: {size_kb:.1f} KB ({size_mb:.2f} MB)")
    print("  Ready for marketplace submission!")


if __name__ == "__main__":
    main()
