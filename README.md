# Zelos UDS

A Zelos extension for UDS (ISO 14229) diagnostics over CAN with ISO-TP (ISO 15765-2) or over DoIP (ISO 13400-2). Sessions, DIDs, routines, DTCs, security access and firmware download, from the Zelos App, app extensions or the shell.

## Features

- **ECUs in parallel**: One entry per UDS server (request/response CAN id pair). ECUs on one interface and channel share one bus
- **CAN adapters**: Classic CAN and CAN FD through the CAN extension's adapters (SocketCAN, SocketCAN over SSH, PCAN, Kvaser, Vector, slcan, any python-can interface)
- **DoIP**: UDS over TCP/IP to a DoIP entity, with vehicle identification; same actions, trace and CLI output as on CAN ([DoIP](#doip))
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
| **Interface** | | SocketCAN (Linux), SocketCAN over SSH, PCAN, Kvaser, Vector, slcan (serial), Other (python-can: any interface, python-can's own `socketcan` included), Demo, DoIP ([below](#doip)) |
| **Name** | CAN channel (the remote one over SSH), `demo` or `doip` | Name the actions take as `ecu`, and the trace segment. Letters, digits, space, `_`, `-` only |
| **Channel**, **Bitrate**, **CAN-FD Mode**, **Advanced Configuration (JSON)** | as the CAN extension | The adapter, with the CAN extension's fields and defaults. The SocketCAN channel picker lists this machine's interfaces |
| **Request CAN ID** / **Response CAN ID** | `0x7E0` / `0x7E8` | Tester-to-ECU and ECU-to-tester ids, hex. Physical addressing |
| **Extended IDs** | off | The two ids are 29-bit |
| **Seed/Key File** | none | A Python file on the agent's host defining `key(level: int, seed: bytes) -> bytes`, loaded at start. Answers seeds in `security_access` (no key given) and `flash_firmware`. It runs in the extension's process. Keys are never logged |

ECUs on one interface and channel share one bus: their bitrate, CAN-FD and SSH settings must match, and no CAN id may be used by two of them. Behavior and limits: [docs/behavior.md](docs/behavior.md).

### DoIP

UDS over TCP/IP (ISO 13400-2) to a DoIP entity: an ECU on Ethernet, or a gateway in front of ECUs. Interface **DoIP**, settings under `doip`. Actions, trace layout and CLI JSON are the CAN transport's.

| Setting | Default | Description |
|---|---|---|
| `host` | | IP or hostname of the entity. Empty with Discover: broadcast |
| `port` | `13400` | TCP port |
| `tester_address` | `0x0E80` | Our logical address (source address). The entity must accept it |
| `ecu_address` | | The ECU's logical address (target address). Empty with Discover: the entity's own; behind a gateway set the ECU's |
| `activation_type` | `0x00` | Routing activation type: `0x00` default, `0x01` WWH-OBD, `0xE0` central security, `0xE1` to `0xFF` OEM |
| `tcp_timeout` | `2.0` | Seconds for the TCP connect and for the entity to acknowledge each request |
| `discover` | off | Vehicle identification (UDP 13400) before each connect: to `host`, or broadcast, where exactly one entity must answer (else set `host`). IP, logical address, VIN, EID and GID show in `get_status` as `vehicle` |

```json
{"interface": "DoIP", "name": "dcdc", "doip": {"host": "192.168.77.2", "ecu_address": "0x1001"}}
```

| Item | DoIP, unlike CAN |
|---|---|
| Transport | No ISO-TP: a request or response is one diagnostic message of any size (CAN: 4095 bytes); the `isotp_*` settings do not apply |
| Acknowledgement | The entity acknowledges each request (0x8002); `tx` is traced then. A NACK (0x8003) or no acknowledgement within `tcp_timeout` fails the request, code named, with no `tx` row |
| Routing activation | A refusal stops the ECU with the code named, e.g. `0x00 unknown source address`. 0x00, 0x02, 0x04, 0x06, 0x07 are not retried; other codes are, with backoff |
| Connection | One TCP connection per ECU, opened at start and held for the session (sessions and security access survive between requests; one of the entity's tester sockets stays in use), reopened with backoff (3 s doubling to 60 s). An ECU reset closes it (the ECU reboots): a request before the reconnect fails |
| Sessions | Requests one at a time per ECU. Two ECUs on one host and port need their own tester addresses |
| Addressing | Physical only: functional group addresses are not sent |
| OBD port | DoIP on the OBD connector (ISO 13400-3) needs its activation line (pin 8) driven; the extension does not drive it |
| TLS | Not supported (TCP 3496) |

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
| `isotp_padding` | `204` (0xCC) | Pad sent frames to 8 bytes with this byte (ISO 15765-4 wants DLC 8 on OBD ids); empty: unpadded |
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
uv run main.py read --interface doip --host 192.168.77.2 --ecu-address 1001 --id F190
uv run main.py read --interface doip --discover --id F190      # broadcast vehicle identification
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

Every subcommand takes `--interface` (a settings label or `socketcan` (same as `zelos-socketcan`), `zelos-ssh-socketcan`, `pcan`, `kvaser`, `vector`, `slcan`, `other`, `demo`, `doip`; any other name is passed to python-can, e.g. `ixxat`, `gs_usb`), `--channel`, `--bitrate`, `--fd`, `--data-bitrate`, `--txid`, `--rxid`, `--extended`. `zelos-ssh-socketcan` needs `--remote-host` (`--ssh-user`, `--ssh-port` optional; `--channel` is the remote interface); `other` takes `--config-json`. `--interface demo` runs the demo ECU inside the command. `--interface doip` takes `--host`, `--port`, `--tester-address`, `--ecu-address`, `--activation-type` and `--discover` instead of the CAN options.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

### Demo ECU

`zelos_extension_uds/demo/` is the bench DC-DC's UDS server in Python, to its firmware's contract, with its seed/key file. It backs the Demo interface and the tests: [docs/behavior.md](docs/behavior.md#demo-ecu).

`just test` runs integration sanity checks against the demo, on CAN and over DoIP through the DoIP entity simulator (`tests/doip_entity.py`: tester 0x0E80, ECU 0x1001).

```bash
just sim                                           # vcan0, Linux
just sim-doip                                      # DoIP entity on 127.0.0.1:13400 (TCP, UDP)
uv run main.py demo-ecu --help                     # --interface, --channel, --fd, --extended, --rx-id, --tx-id, --stmin
```

## Links

- **Repository**: [github.com/zeloscloud/zelos-extension-uds](https://github.com/zeloscloud/zelos-extension-uds)
- **Issues**: [Report bugs or request features](https://github.com/zeloscloud/zelos-extension-uds/issues)
- [Zelos Documentation](https://docs.zeloscloud.io)

## License

MIT License - see [LICENSE](LICENSE) for details.
