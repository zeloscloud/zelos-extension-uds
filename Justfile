set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Each shared recipe acts on the parts this project has:
# the agent runtime when pyproject.toml exists, the web project when web/package.json exists.

default:
    @just --list

# Install dependencies and the pre-commit hooks
install:
    #!/usr/bin/env bash
    set -eu -o pipefail
    if [[ -f pyproject.toml ]]; then
      uv sync
      if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        uv run pre-commit install
      else
        echo "Not a git repository: skipped the pre-commit hooks. Run git init, then just install."
      fi
    fi
    if [[ -f web/package.json ]]; then (cd web && npm install); fi

# Install dependencies from the lockfiles when they exist (CI, no pre-commit hooks)
ci-install:
    if [[ -f pyproject.toml ]]; then if [[ -f uv.lock ]]; then uv sync --locked; else uv sync; fi; fi
    just _web-install

_web-install:
    if [[ -f web/package-lock.json ]]; then (cd web && npm ci); elif [[ -f web/package.json ]]; then (cd web && npm install); fi

# Install the web project's dependencies only when web/node_modules is missing
_deps:
    if [[ -f web/package.json && ! -d web/node_modules ]]; then just _web-install; fi

# Format code (ruff, Prettier)
format: _deps
    if [[ -f pyproject.toml ]]; then uv run ruff format . && uv run ruff check --fix .; fi
    if [[ -f web/package.json ]]; then (cd web && npm run format); fi

# Check formatting, lint and type-check
check: _deps
    if [[ -f pyproject.toml ]]; then uv run ruff format --check . && uv run ruff check .; fi
    if [[ -f web/package.json ]]; then (cd web && npm run format:check && npm run check); fi

# Run tests
test: _deps
    if [[ -f pyproject.toml ]]; then uv run pytest; fi
    if [[ -f web/package.json ]]; then (cd web && npm test); fi

# Build the web project into dist/
build: _deps
    if [[ -f web/package.json ]]; then (cd web && npm run build); fi

# Build and package for the Zelos marketplace
package: build
    zelos extensions package .

# Run all CI checks
ci: ci-install check test package

# Release: bump version, format, check, test, build, commit, tag
release VERSION: _deps
    #!/usr/bin/env bash
    set -eux -o pipefail
    git diff-index --quiet HEAD || (echo "Uncommitted changes! Commit or stash first." && exit 1)
    zelos extensions bump "{{VERSION}}"
    if [[ -f pyproject.toml ]]; then uv lock; fi
    if [[ -f web/package.json ]]; then (cd web && npm version "{{VERSION}}" --no-git-tag-version --allow-same-version); fi
    just format
    just check
    just test
    just build
    git add -A
    git commit -m "Release v{{VERSION}}"
    git tag -a "v{{VERSION}}" -m "Release v{{VERSION}}"
    echo ""
    echo "✓ Release v{{VERSION}} ready!"
    echo ""
    echo "Push with: git push --follow-tags"

# Delete a GitHub release, its remote and local tag, and force-push
delete-release VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    tag="v{{VERSION}}"
    gh release delete "$tag" --yes 2>/dev/null && echo "✓ release deleted" || echo "- no release found"
    git push origin --delete "$tag" 2>/dev/null && echo "✓ remote tag deleted" || echo "- no remote tag"
    git tag -d "$tag" 2>/dev/null && echo "✓ local tag deleted" || echo "- no local tag"
    git push --force-with-lease
    echo ""
    echo "✓ Cleaned up $tag — ready to re-release"

# Remove build output, caches and packages
clean:
    rm -rf dist build web/node_modules .pytest_cache .ruff_cache *.tar.gz actions.json
    find . -type d -name "__pycache__" -prune -exec rm -rf {} + 2>/dev/null || true

# Run the agent runtime locally
run:
    uv run python main.py

# Run the demo ECU to point a tester at, e.g. --interface socketcan --channel vcan0
sim *ARGS="--interface socketcan --channel vcan0":
    uv run python main.py demo-ecu {{ARGS}}

# Run the DoIP entity simulator (the demo ECU over DoIP), e.g. --host 0.0.0.0
sim-doip *ARGS="--host 127.0.0.1":
    uv run python tests/doip_entity.py {{ARGS}}

# Update uv.lock after changing dependencies
lock:
    uv lock
