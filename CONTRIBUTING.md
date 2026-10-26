# Contributing

## Prerequisites

- [Zelos](https://zeloscloud.io) 26.0.10 or later
- [Zelos CLI](https://docs.zeloscloud.io/reference/cli/) 0.1.11 or later
- [just](https://github.com/casey/just)
- [uv](https://docs.astral.sh/uv/)

## Layout

`extension.toml` describes everything the extension contributes:

| Part | Files | Manifest |
| ---- | ----- | -------- |
| Agent runtime | `main.py`, the Python package, `pyproject.toml`, `config.schema.json` | `[agent]`, `[config]` |

| Path | Contents |
| ---- | -------- |
| `main.py` | Entry point: app mode, or one request from the shell |
| `zelos_extension_uds/actions.py` | The actions, registered as `UDS/<action>` |
| `zelos_extension_uds/services.py` | One function per UDS service, shared by the actions and the CLI |
| `zelos_extension_uds/client.py` | ECU connections: shared CAN buses with ISO-TP, DoIP, reopen with backoff |
| `zelos_extension_uds/cli/` | App mode (`app.py`) and one module per subcommand |
| `zelos_extension_uds/demo/` | The demo ECU and its seed/key file |
| `tests/` | Tests against the demo ECU; `doip_entity.py` is the DoIP entity simulator |
| `docs/behavior.md` | Behavior and limits |

## Commands

| Command                | Description                                        |
| ---------------------- | -------------------------------------------------- |
| `just install`         | Install dependencies and the pre-commit hooks      |
| `just format`          | Format code with ruff                              |
| `just check`           | Check formatting and lint with ruff                |
| `just test`            | Run tests (pytest)                                 |
| `just package`         | Package for the Zelos marketplace                  |
| `just release VERSION` | Bump version, check, test, commit, tag             |
| `just clean`           | Remove build output, caches and packages           |
| `just run`             | Run the agent runtime locally                      |
| `just sim`             | Run the demo ECU on vcan0 (Linux)                  |
| `just sim-doip`        | Run the DoIP entity simulator on 127.0.0.1:13400   |

`just --list` shows every recipe. `just install` installs the pre-commit hooks in
`.pre-commit-config.yaml`.

## Testing

`just test` runs the extension against its demo ECU, on the zelos-can virtual bus and behind
the DoIP entity simulator. It needs no CAN hardware.

## Run it in Zelos

```bash
zelos extensions install-local .
```

A local install runs from your project directory, so you do not install again after a code
change:

- Agent runtime: stop and start the extension. After a dependency change, stop it and run
  `zelos extensions reinstall <id>`.
- `extension.toml`: run `zelos extensions install-local .` again.

## Packaging

```bash
just package
```

The archive lands next to `extension.toml` as `<name>-<version>.tar.gz`, where `<name>` is the
manifest name in lowercase with every other run of characters turned into one hyphen. It holds
`extension.toml`, the README, the icon, the config schema and the paths listed in
`[package] paths`. With an agent runtime it also holds `pyproject.toml`, `uv.lock` and
`actions.json`, the list of actions that run while the extension is stopped.

## Release

```bash
just release 1.0.0
git push --follow-tags
```

The release workflow checks, tests and packages the extension, then attaches the archive to a
GitHub release.
