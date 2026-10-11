# Contributing

## Prerequisites

- [Zelos CLI](https://docs.zeloscloud.io/cli)
- Python 3.11+
- [uv](https://docs.astral.sh/uv/)
- [just](https://github.com/casey/just)

## Setup

```bash
git clone https://github.com/zeloscloud/zelos-extension-uds
just install
```

## Commands

| Command                | Description                                 |
| ---------------------- | ------------------------------------------- |
| `just install`         | Install dependencies and pre-commit hooks   |
| `just dev`             | Run extension locally                       |
| `just sim`             | Run the demo ECU on vcan0                   |
| `just format`          | Format code with ruff                       |
| `just check`           | Lint with ruff                              |
| `just test`            | Run tests with pytest                       |
| `just package`         | Package for Zelos marketplace               |
| `just release VERSION` | Bump version, check, test, commit, and tag  |
| `just clean`           | Remove build artifacts                      |

## Configuration

Edit `config.schema.json` to define your extension's configuration options. The schema drives the configuration UI in the Zelos desktop app. See the [configuration docs](https://docs.zeloscloud.io/sdk/how-to/develop-extensions/#configuration) for the full widget reference.

## Packaging

```bash
just package
```

The archive lands next to `extension.toml` as `{name}-{version}.tar.gz`.
