# Zelos UDS

A Zelos extension for UDS (ISO 14229) diagnostics over CAN with ISO-TP (ISO 15765-2). Sessions, DIDs, routines, DTCs, security access and firmware download, from the Zelos App, app extensions or the shell.

## Features

- **ECUs in parallel**: One entry per UDS server (request/response CAN id pair). ECUs on one interface and channel share one bus
- **CAN adapters**: Classic CAN and CAN FD through the CAN extension's adapters (SocketCAN, SocketCAN over SSH, PCAN, Kvaser, Vector, slcan, any python-can interface)
- **Persistent session**: The bus opens at start and stays open; requests to one ECU are serialized; periodic tester present holds non-default sessions
- **Typed payloads**: Writes and options as hex or packed integers/floats; reads decoded as every fitting integer/float type
- **Demo ECU**: A built-in simulated ECU to try every action without hardware

## Quick Start

```bash
git clone https://github.com/zeloscloud/zelos-extension-uds
cd zelos-extension-uds
just install
uv run main.py --demo
```

## Configuration

All configuration is managed through the Zelos App settings interface.

### Per-ECU Settings

| Setting | Default | Description |
|---|---|---|
| **Interface** | | SocketCAN (Linux), SocketCAN over SSH, PCAN, Kvaser, Vector, slcan (serial), Other (python-can: any interface, python-can's own `socketcan` included), Demo |
| **Name** | CAN channel (the remote one over SSH) or `demo` | Name the actions take as `ecu`, and the trace segment. Letters, digits, space, `_`, `-` only |
| **Channel**, **Bitrate**, **CAN-FD Mode**, **Advanced Configuration (JSON)** | as the CAN extension | The adapter, with the CAN extension's fields and defaults. The SocketCAN channel picker lists this machine's interfaces |
| **Request CAN ID** / **Response CAN ID** | `0x7E0` / `0x7E8` | Tester-to-ECU and ECU-to-tester ids, hex. Physical addressing |
| **Extended IDs** | off | The two ids are 29-bit |
| **Seed/Key File** | none | A Python file on the agent's host defining `key(level: int, seed: bytes) -> bytes`, loaded at start. Answers seeds in `security_access` (no key given) and `flash_firmware`. It runs in the extension's process. Keys are never logged |

ECUs on one interface and channel share one bus: their bitrate, CAN-FD and SSH settings must match, and no CAN id may be used by two of them. Behaviour and limits: [docs/behaviour.md](docs/behaviour.md).

### Advanced Settings

One value each, applied to every ECU.

| Setting | Default | Description |
|---|---|---|
| `prefix` | `UDS` | Trace source every ECU publishes under |
| `log_level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `request_timeout` | `5.0` | Seconds a request may take in total, response-pending included |
| `p2_timeout` | `1.0` | Seconds to the start of the response (its first frame); the rest of a multi-frame response follows at the ECU's pace |
| `p2_star_timeout` | `5.0` | Seconds after each response-pending (NRC 0x78) |
| `isotp_stmin` | `0` | STmin (ms) in our flow control frames |
| `isotp_blocksize` | `0` | Block size in our flow control frames; 0: all, one flow control per message |
| `isotp_padding` | none | Pad sent frames to 8 bytes with this byte; none: unpadded |
| `tester_present_s` | none | Periodic tester present to every ECU from the start; none: off |
| `debug_frames` | off | Log every request, response and ISO-TP frame at `DEBUG` |

Settings from 0.1.x (one flat ECU with lowercase interface names) are read as one ECU, with a warning; save the settings to update them.

### Trace layout

| What | Prefix `UDS` | Prefix cleared |
|---|---|---|
| Requests | `UDS/<ecu>/tx` | `<ecu>/tx` |
| Responses | `UDS/<ecu>/rx` | `<ecu>/rx` |
| Extension logs | `UDS/log` | `uds_log/log` |

| Field | Event | Meaning |
|---|---|---|
| `service_id`, `service_name` | tx, rx | Service, e.g. `0x22` `ReadDataByIdentifier` |
| `parameter` | tx, rx | What the request addresses: DID (0x22, 0x2E, 0x2F), routine id (0x31), memory address (0x23, 0x3D, 0x34, 0x35), block sequence (0x36), DTC group (0x14), else the sub-function (0x10, 0x11, 0x19, 0x27, 0x28, 0x3E, 0x85); 0 for 0x37 |
| `data` | tx, rx | tx: the whole request after the SID. rx: the whole response after the SID (for a negative one, after 0x7F: the SID and the NRC) |
| `success`, `nrc` | rx | Positive response; the negative response code, 0 when positive |
| `elapsed_ms` | rx | Request to final response, response-pending included |

A timed-out or suppressed request has a `tx` row and no `rx` row.

## Actions

Available from the Zelos App and to app extensions as `UDS/<action>`, whatever the trace prefix. Each takes `ecu`; fields with a default are optional. A negative response returns `status: error` with `nrc` and `nrc_name`.

| Action | Service | Description |
|---|---|---|
| `list_ecus` | | Configured ECUs: name, interface, endpoint, ids, state |
| `get_status` | | State, last error, ids, periodic tester present, counters (`requests` sent, `responses` = `positive` + `negative`, `timeouts`, `errors`). Sends nothing |
| `session_control` | 0x10 | Default, programming, extended, safety system |
| `read_did` | 0x22 | Hex, and integer/float readings of 1, 2, 4 and 8-byte values |
| `write_did` | 0x2E | Hex or a typed number, big or little endian |
| `ecu_reset` | 0x11 | Hard, soft, key off/on |
| `routine_control` | 0x31 | Start, stop, request results; optional typed data |
| `io_control` | 0x2F | Return control, reset to default, freeze, short-term adjustment |
| `tester_present` | 0x3E | Once, optionally with suppressed response |
| `periodic_tester_present` | 0x3E | Start or stop, suppressed response, 0.5 to 10 s; `state` started, stopped or inactive |
| `read_dtc` | 0x19 | `report`: by status mask (02), number by mask (01), snapshot ids (03), snapshot by DTC (04) and extended data by DTC (06) as raw hex records, supported (0A) |
| `clear_dtc` | 0x14 | One group, `FFFFFF` for all |
| `control_dtc_setting` | 0x85 | On or off |
| `communication_control` | 0x28 | Enable/disable Rx and Tx; normal, network management or both |
| `security_access` | 0x27 | Level as the odd requestSeed sub-function (`0x01`, `0x11`). Key given: sent. Empty: the seed is requested, and answered with the key file when set |
| `read_memory`, `write_memory` | 0x23, 0x3D | 4-byte address, size in 1, 2 or 4 bytes (ALFID 0x14, 0x24, 0x44) |
| `request_download`, `request_upload` | 0x34, 0x35 | Address and size; returns the ECU's block length |
| `transfer_data` | 0x36 | One block: sends data, or (empty) returns an upload block |
| `request_transfer_exit` | 0x37 | Ends a transfer |
| `upload_memory` | 0x35 0x36 0x37 | Whole upload; written to a file path on the agent's host, else returned as hex up to 4096 bytes |
| `flash_firmware` | | Image from a file on the agent's host or hex. Extended then programming session, security (level `0x11`, key or key file; skipped with neither), optional erase routine (off by default; e.g. `0xFF00`, record ALFID 0x44 + address + size), download, exit, check routine (`0xFF01`, record CRC32 of the image; a non-zero first result byte fails), optional reset. Each step in `steps`; the first failure ends it, named in `failed_step`. Nothing else is sent to the ECU meanwhile |
| `auto_config` | | One demo ECU with its seed/key file, for the config form's Auto-configure. Runs with the extension stopped |
| `list_interfaces` | | This machine's SocketCAN interfaces, for the Channel picker. Runs with the extension stopped |

## CLI Usage

```bash
uv run main.py                     # app mode with the config from the Zelos App
uv run main.py --demo              # add a demo ECU
uv run main.py --demo --file       # record to a UTC-stamped .trz

# One request from the shell; prints the result as JSON, exit 1 on error
uv run main.py read --txid 7E0 --rxid 7E8 --id F190
uv run main.py read --interface zelos-socketcan --channel can0 --txid 7E0 --rxid 7E8 --id F190
uv run main.py read --interface demo --txid 7E0 --rxid 7E8 --id F190
uv run main.py flash --interface pcan --channel PCAN_USBBUS1 --bitrate 500000 \
    --txid 7E0 --rxid 7E8 --file fw.bin --address 08000000
```

| Subcommand | Service |
|---|---|
| `session`, `reset`, `tp` | 0x10, 0x11, 0x3E |
| `read`, `write` | 0x22, 0x2E (`--type`, `--endian`) |
| `routine`, `io` | 0x31, 0x2F |
| `dtc`, `clear` | 0x19 (`--report`), 0x14 |
| `dtc-setting`, `comm` | 0x85, 0x28 |
| `read-mem`, `write-mem`, `upload` | 0x23, 0x3D, 0x35 0x36 0x37 |
| `security` | 0x27 (`--seed`, `--key`, `--key-file`) |
| `flash` | As `flash_firmware`, erase and check opt-in (`--key-file`, `--erase-routine`, `--check-routine`, `--reset`) |
| `demo-ecu` | Runs the demo ECU on any python-can bus |

Every subcommand takes `--interface` (a settings label or `socketcan` (same as `zelos-socketcan`), `zelos-ssh-socketcan`, `pcan`, `kvaser`, `vector`, `slcan`, `other`, `demo`; any other name is passed to python-can, e.g. `ixxat`, `gs_usb`), `--channel`, `--bitrate`, `--fd`, `--data-bitrate`, `--txid`, `--rxid`, `--extended`. `zelos-ssh-socketcan` needs `--remote-host` (`--ssh-user`, `--ssh-port` optional; `--channel` is the remote interface); `other` takes `--config-json`. `--interface demo` runs the demo ECU inside the command.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

### Demo ECU

`zelos_extension_uds/demo/` is the bench DC-DC's UDS server in Python, to its firmware's contract, with its seed/key file. It backs the Demo interface and the tests: [docs/behaviour.md](docs/behaviour.md#demo-ecu).

The zelos-examples UDS conformance suite is vendored in `tests/conformance` and runs against the demo in `just test`. Update it with `just sync-conformance ~/zelos/zelos-examples`; `ZELOS_EXAMPLES=<checkout> just test` also checks the copy against upstream.

```bash
just sim                                           # vcan0, Linux
uv run main.py demo-ecu --help                     # --interface, --channel, --fd, --extended, --rx-id, --tx-id, --stmin
```

## Links

- **Repository**: [github.com/zeloscloud/zelos-extension-uds](https://github.com/zeloscloud/zelos-extension-uds)
- **Issues**: [Report bugs or request features](https://github.com/zeloscloud/zelos-extension-uds/issues)
- [Zelos Documentation](https://docs.zeloscloud.io)

## License

MIT License - see [LICENSE](LICENSE) for details.
