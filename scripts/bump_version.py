#!/usr/bin/env python3
"""Bump version in extension.toml and pyproject.toml."""

import re
import sys
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore


def validate_semver(version: str) -> bool:
    """Validate semantic version format.

    :param version: Version string to validate
    :return: True if valid semver format
    """
    pattern = r"^\d+\.\d+\.\d+$"
    return bool(re.match(pattern, version))


def update_toml_version(file_path: Path, new_version: str) -> bool:
    """Update version in a TOML file.

    For extension.toml, only updates top-level version, not [zelos].version.
    For pyproject.toml, updates the [project] version.

    :param file_path: Path to TOML file
    :param new_version: New version string
    :return: True if file was modified
    """
    content = file_path.read_text()
    original_content = content

    if file_path.name == "extension.toml":
        # Only update top-level version, not [zelos].version
        # Pattern: version = "old" at start of line, not in [zelos] section
        content = re.sub(
            r'^version = ".*?"$',
            f'version = "{new_version}"',
            content,
            count=1,  # Only first occurrence (top-level)
            flags=re.MULTILINE,
        )
    elif file_path.name == "pyproject.toml":
        # Update [project] version
        content = re.sub(
            r'^version = ".*?"$',
            f'version = "{new_version}"',
            content,
            count=1,
            flags=re.MULTILINE,
        )

    if content != original_content:
        file_path.write_text(content)
        return True
    return False


def main() -> None:
    """Bump version in project files."""
    if len(sys.argv) != 2:
        print("Usage: python scripts/bump_version.py VERSION")
        print("Example: python scripts/bump_version.py 1.2.3")
        sys.exit(1)

    new_version = sys.argv[1]

    # Validate version format
    if not validate_semver(new_version):
        print(f"ERROR: Invalid version format: {new_version}")
        print("Version must be in format X.Y.Z (e.g., 1.2.3)")
        sys.exit(1)

    # Check files exist
    extension_toml = Path("extension.toml")
    pyproject_toml = Path("pyproject.toml")

    if not extension_toml.exists():
        print("ERROR: extension.toml not found")
        sys.exit(1)

    if not pyproject_toml.exists():
        print("ERROR: pyproject.toml not found")
        sys.exit(1)

    # Verify current versions
    print("Current versions:")
    try:
        with extension_toml.open("rb") as f:
            manifest = tomllib.load(f)
            current_ext_version = manifest.get("version", "unknown")
            print(f"  extension.toml: {current_ext_version}")
    except Exception as e:
        print(f"  extension.toml: Failed to read ({e})")
        current_ext_version = None

    try:
        with pyproject_toml.open("rb") as f:
            project = tomllib.load(f)
            current_proj_version = project.get("project", {}).get("version", "unknown")
            print(f"  pyproject.toml: {current_proj_version}")
    except Exception as e:
        print(f"  pyproject.toml: Failed to read ({e})")
        current_proj_version = None

    # Check if versions are already correct
    if current_ext_version == new_version and current_proj_version == new_version:
        print(f"\n✓ Both files already at version {new_version}")
        sys.exit(0)

    # Update files
    print(f"\nUpdating to version {new_version}...")

    ext_updated = update_toml_version(extension_toml, new_version)
    if ext_updated:
        print("  ✓ Updated extension.toml")
    else:
        print("  - extension.toml unchanged")

    proj_updated = update_toml_version(pyproject_toml, new_version)
    if proj_updated:
        print("  ✓ Updated pyproject.toml")
    else:
        print("  - pyproject.toml unchanged")

    if ext_updated or proj_updated:
        print(f"\n✓ Version bumped to {new_version}")
        print("\nNext steps:")
        print("  1. Review changes: git diff")
        print("  2. Run checks: just check && just test")
        print(f"  3. Commit: git commit -am 'Release v{new_version}'")
        print(f"  4. Tag: git tag v{new_version}")
        print(f"  5. Push: git push origin main v{new_version}")
    else:
        print("\n⚠️  No files were updated")


if __name__ == "__main__":
    main()
