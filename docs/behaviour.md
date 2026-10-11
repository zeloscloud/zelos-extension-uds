# Behaviour and limits

## Bus and session

| Situation | What happens |
|---|---|
| Start | Each bus opens when the extension starts and stays open. Every ECU on it gets its own ISO-TP stack on the bus's one receive thread |
| Shared bus | ECUs with the same interface and channel (remote host, channel, user and port over SSH; the whole JSON for Other) share one bus. Different bitrate, CAN-FD Mode, data bitrate, Advanced Configuration (JSON) or other SSH settings between them, or a CAN id (request or response) used by two of them, refuses to start, naming both ECUs |
| Requests | One at a time per ECU; others wait up to 20 s, then fail with `busy: <service> in progress`, so nothing is sent after its caller gave up. ECUs on one bus run in parallel. `flash_firmware` holds its ECU for the whole download |
| Bus failure | A receive error, a failed open, or an ISO-TP stack stopped by a send error: every ECU on that bus goes to `error` with the reason, and the bus is reopened with backoff, 3 s doubling to 60 s, back to 3 s after it stayed up 10 s. Meanwhile actions fail at once with the reason. Open errors no retry fixes are not retried: an SSH error an operator must fix (e.g. host key), an interface or driver library missing, SocketCAN off Linux, an invalid configuration. A transient send error on a shared bus reopens the whole bus, every ECU on it included |
| ECU silent | A request times out (`Timeout waiting for response`); the bus stays open, the ECU stays `connected` |
| Timing | `p2_timeout` bounds the start of the response: its first frame (single or first frame) after the request's last frame is sent; `p2_star_timeout` the same after each response-pending (0x78). A multi-frame response then completes at the ECU's pace, bounded by ISO-TP's consecutive-frame timeout (1 s per frame) instead of P2. `request_timeout` bounds the whole request from its send, so it also bounds a long run of response-pending answers: raise it under Advanced for slow erases. The P2 values an ECU reports in its session response are not used: they leave no margin for the network |
| Periodic tester present | `0x3E 0x80` (no positive response) per ECU, from `tester_present_s` or the action. A beat that finds a request in progress is skipped: that request keeps the session |
| Stop | Within 3 s: periodic tester present and every bus are signalled first, then each bus closes its ISO-TP stacks, receive thread and bus; the demo ECUs last. A request in progress fails. A bus still opening (an adapter retrying) is logged as late and closed once its open returns |
| Over SSH | The edge echoes our own frames; ISO-TP ignores them. Each request and flow control crosses the network: allow for its round trip in `p2_timeout` |

## Requests

| Item | Handling |
|---|---|
| Addressing | Physical only: one request and one response id per ECU. Functional (0x7DF) is not sent |
| CAN FD | ISO-TP frames up to 64 bytes, padded to FD lengths, bit rate switch on |
| Padding | `isotp_padding` set: classic frames padded to 8 bytes with that byte; else unpadded |
| Flow control | `isotp_blocksize` (default 0: one flow control per message) and `isotp_stmin` go in our flow control frames; the ECU's are followed. Over SSH each of our flow controls costs a round trip: a non-zero block size slows long responses accordingly. An ECU flow control WAIT fails the transfer (no WAIT frames accepted). Messages up to 4095 bytes |
| Typed payloads | `int8` to `uint64`, `float`, `double`, big or little endian, packed to the type's width. `hex` takes bytes as written |
| Reads | `representations`: every unsigned, signed and float reading of a 1, 2, 4 or 8-byte value, both byte orders |
| Flash | Block size 0: the ECU's maxNumberOfBlockLength less SID and sequence. Sequence starts at 1 and wraps 0xFF to 0x00 |
| DTC | 3-byte DTCs. 0x01, 0x02, 0x0A decoded; 0x03 as DTC and record number; 0x04 and 0x06 records as raw hex (their layout is the ECU's) |
| NRC | `status: error`, `nrc`, `nrc_name`; logged once at `WARNING`, traced in `rx` |
| Seed/key | The key file loads at start; a missing file, a load error or no `key` function refuses to start, naming the file. A key that is not bytes fails that request. A zero seed (already unlocked) sends no key |
| Memory | Addresses in 4 bytes (5 above 32 bits), sizes in the fewest of 1, 2, 4 bytes |
| Flash | Holds the ECU for the whole sequence; `steps` lists each with its status. The check routine passes on a first result byte of 0x00 |

## Names and settings

| Item | Handling |
|---|---|
| Names | Rejected, not renamed, when they hold anything but letters, digits, space, `_`, `-`. `log` and `uds_log` are reserved ECU names |
| CAN ids | Hex, with or without `0x`. Over 0x7FF without Extended IDs: refused at start |
| 0.1.x settings | No `ecus` but a top-level `interface`: one ECU. `demo`, `socketcan` (to SocketCAN: the same kernel SocketCAN through zelos-can), `pcan`, `kvaser`, `vector`, `other` map to their labels; ids default to 0x7E0/0x7E8 as before; timeouts, `isotp_stmin`, `isotp_blocksize`, `isotp_tx_padding` and `log_level` move to Advanced; `extended_id`, or an id over 0x7FF, sets Extended IDs. Logged once |
| Action paths | `UDS/<action>` (0.1.x: `uds/uds_client/<method>`); per-action TX/RX id overrides are gone: add an ECU per id pair |

## Demo ECU

The bench DC-DC's UDS server, ported to Python: the contract is the firmware's (zelos-examples `nodes/dcdc/src/uds.c`, `lib/uds/core/uds_core.c`; the server contract in the UDS design), not repeated here. The zelos-examples conformance suite, vendored in `tests/conformance`, runs against it in CI: 55 pass, 8 skip (they need the DC-DC node's own frames).

| Item | Demo |
|---|---|
| Ids | Requests 0x7E0, functional 0x7DF, responses 0x7E8, padding 0xCC, flow control BS 0 STmin 0 (`demo-ecu --stmin` sets it) |
| Seed/key | `zelos_extension_uds/demo/key.py`, shipped; Auto-configure, `--demo` and a Demo ECU without a key file use it. Key = seed XOR 0x5A5AA5A5 (level 0x01) or 0xC3A53C5A (0x11) |
| Power-up | Seeds answer 0x37 for 10 s after start and after each ECUReset, as the firmware's |
| Model | The DC-DC's model, every 50 ms, without its DCDC_Status broadcast. No BMS on the bus: the demo plays one granting 20 A at 374 V (`DemoEcu.bms`; None for none) |
| DTC causes | Overcurrent and then overtemperature by calibration (demand 20 A at 0x00020000); undervoltage and BMS lost through `bms`; any test result forced through `DemoEcu.force[i]` |
| Bus | The in-process zelos-can virtual bus by default, for the extension and tests, not other programs; `demo-ecu --interface` takes any python-can bus. The conformance suite runs on python-can's `virtual`: it times frames by receive timestamp, which zelos-virtual leaves at 0 |
| Linux | `uv run main.py demo-ecu --interface socketcan --channel vcan0`, then any subcommand with `--interface socketcan --channel vcan0` |
