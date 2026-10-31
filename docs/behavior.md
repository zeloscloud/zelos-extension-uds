# Behavior and limits

## Bus and session

| Situation | What happens |
|---|---|
| Start | Each bus opens when the extension starts and stays open. Every ECU on it gets its own ISO-TP stack on the bus's one receive thread |
| Shared bus | ECUs with the same interface and channel (remote host, channel, user and port over SSH; the whole JSON for Other) share one bus. Different bitrate, CAN-FD Mode, data bitrate, Advanced Configuration (JSON) or other SSH settings between them, or a CAN id (request or response) used by two of them, refuses to start, naming both ECUs |
| Requests | One at a time per ECU; others wait up to 20 s, then fail with `busy: <service> in progress`, so nothing is sent after its caller gave up. ECUs on one bus run in parallel. `flash_firmware` holds its ECU for the whole download |
| Bus failure | A receive error, a failed open, or an ISO-TP stack stopped by a send error: every ECU on that bus goes to `error` with the reason, and the bus is reopened with backoff, 3 s doubling to 60 s, back to 3 s after it stayed up 10 s. Meanwhile actions fail at once with the reason. Open errors no retry fixes are not retried: an SSH error an operator must fix (e.g. host key), an interface or driver library missing, SocketCAN off Linux, an invalid configuration. A transient send error on a shared bus reopens the whole bus, every ECU on it included |
| Idle | Nothing is sent on CAN unless a request runs (periodic tester present counts). Between requests an ECU's stack ignores its response id, so another tester's transfer with that ECU gets no flow control from us; a response that starts after the request timed out is ignored too |
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
| Padding | classic frames padded to 8 bytes with `isotp_padding` (default 0xCC); null: unpadded |
| Flow control | `isotp_blocksize` (default 0: one flow control per message) and `isotp_stmin` go in our flow control frames; the ECU's are followed. Over SSH each of our flow controls costs a round trip: a non-zero block size slows long responses accordingly. An ECU flow control WAIT fails the transfer (no WAIT frames accepted). Messages up to 4095 bytes |
| Typed payloads | `int8` to `uint64`, `float`, `double`, big or little endian, packed to the type's width. `hex` takes bytes as written |
| Reads | `representations`: every unsigned, signed and float reading of a 1, 2, 4 or 8-byte value, both byte orders |
| Flash | Block size 0: the ECU's maxNumberOfBlockLength less SID and sequence. Sequence starts at 1 and wraps 0xFF to 0x00 |
| DTC | 3-byte DTCs. 0x01, 0x02, 0x0A decoded; 0x03 as DTC and record number; 0x04 and 0x06 records as raw hex (their layout is the ECU's) |
| NRC | `status: error`, `nrc`, `nrc_name`; logged once at `WARNING`, traced in `rx` |
| Seed/key | The key file loads at start; a missing file, a load error or no `key` function refuses to start, naming the file. A key that is not bytes fails that request. A zero seed (already unlocked) sends no key |
| Memory | Addresses in 4 bytes (5 above 32 bits), sizes in the fewest of 1, 2, 4 bytes |
| Flash | Holds the ECU for the whole sequence; `steps` lists each with its status. The check routine passes on a first result byte of 0x00 |

## DoIP

| Situation | What happens |
|---|---|
| Start | Discover on: vehicle identification on UDP 13400 (2 s). Then TCP connect (`tcp_timeout`) and routing activation (2 s for the answer). The ECU is `connected` once routing is active |
| Refused | Routing activation refused, or more than one entity answered a broadcast: `error` with the reason. Activation codes 0x00, 0x02, 0x04, 0x06, 0x07 and the broadcast ambiguity are not retried; other failures (no answer, connection refused, other codes) are retried like a bus open |
| Idle | Every 0.25 s while no request runs: the entity's alive check requests are answered, unasked messages dropped, a closed connection noticed |
| Entity closes | `error` with `DoIP connection closed by the entity` (or `connection lost` with the socket error), reconnected with the bus's backoff. Within 5 s of an ECU reset it is the reset: logged at INFO, `connecting`, not counted as an error |
| Requests | One at a time per ECU. Sent as one diagnostic message; the entity's acknowledgement (or NACK) awaited for `tcp_timeout`, then `p2_timeout`, `p2_star_timeout` and `request_timeout` as on CAN. A response after its request timed out is dropped before the next request |
| Errors | NACKs are named: diagnostic message (0x8003) `DoIP diagnostic message refused: NACK 0x03 unknown target address`, generic header `DoIP header refused: NACK 0x01 unknown payload type` |
| Stop | The TCP connection is shut down: a request in progress fails at once |
| Protocol | ISO 13400-2:2012 headers (version 0x02). A VIN the entity reports as not configured (all 0x00 or 0xFF) is empty |

## Names and settings

| Item | Handling |
|---|---|
| Names | Rejected, not renamed, when they hold anything but letters, digits, space, `_`, `-`. `log` and `uds_log` are reserved ECU names |
| CAN ids | Hex, with or without `0x`. Over 0x7FF without Extended IDs: refused at start |

## Demo ECU

The bench DC-DC's UDS server, ported to Python: the contract is the firmware's (zelos-examples `nodes/dcdc/src/uds.c`, `lib/uds/core/uds_core.c`), not repeated here. The extension's tests run against it on CAN and over DoIP behind the DoIP entity simulator (`tests/doip_entity.py`).

| Item | Demo |
|---|---|
| Ids | Requests 0x7E0, functional 0x7DF, responses 0x7E8, padding 0xCC, flow control BS 0 STmin 0 (`demo-ecu --stmin` sets it) |
| Seed/key | `zelos_extension_uds/demo/key.py`, shipped; Auto-configure, `--demo` and a Demo ECU without a key file use it. Key = seed XOR 0x5A5AA5A5 (level 0x01) or 0xC3A53C5A (0x11) |
| Power-up | Seeds answer 0x37 for 10 s after start and after each ECUReset, as the firmware's |
| Model | The DC-DC's model, every 50 ms, without its DCDC_Status broadcast. No BMS on the bus: the demo plays one granting 20 A at 374 V (`DemoEcu.bms`; None for none) |
| DTCs | The node's OBD-II lifecycle: pending at the first failed cycle, confirmed with warningIndicatorRequested at the second; the indicator goes after 3 passed cycles, confirmed after 40 more. An ECUReset ends a cycle. Snapshot records 0x00 and 0xF0 (first and latest frame, DIDs 0xF400 + PID) beside 0x01 |
| ReadDataByIdentifier | Several DIDs: the supported ones answer, 0x31 only if none is |
| DTC causes | Overcurrent and then overtemperature by calibration (demand 20 A at 0x00020000); undervoltage and BMS lost through `bms`; any test result forced through `DemoEcu.force[i]` |
| Bus | The in-process zelos-can virtual bus by default, for the extension and tests, not other programs; `demo-ecu --interface` takes any python-can bus |
| Linux | `uv run main.py demo-ecu --interface socketcan --channel vcan0`, then any subcommand with `--interface zelos-socketcan --channel vcan0` |
