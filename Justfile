set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

default:
    @just --list

# Install dependencies
install:
    uv sync --extra dev
    uv run pre-commit install

# Install dependencies for CI (no pre-commit hooks)
ci-install:
    uv sync --extra dev

# Format code
format:
    uv run ruff format .
    uv run ruff check --fix .

# Run checks
check:
    uv run ruff check .

# Run tests
test:
    uv run pytest

# Run extension locally
dev:
    uv run python main.py

# Package extension
package:
    uv run python scripts/package_extension.py

# Release new version
release VERSION:
    #!/usr/bin/env bash
    set -euo pipefail

    VERSION="{{VERSION}}"

    # Ensure clean working directory
    git diff --quiet && git diff --staged --quiet || (echo "Error: Uncommitted changes" && exit 1)

    # Update versions
    uv run python scripts/bump_version.py "$VERSION"

    # Format and update dependencies
    just format
    uv lock

    # Run tests
    just test

    # Commit everything
    git add -A
    git commit -m "Release v$VERSION"
    git tag -a "v$VERSION" -m "Release v$VERSION"

    echo ""
    echo "✓ Release v$VERSION ready!"
    echo ""
    echo "Push with: git push --follow-tags"

# Clean build artifacts
clean:
    rm -rf dist build .pytest_cache .ruff_cache *.tar.gz .artifacts
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
