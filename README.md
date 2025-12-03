# Zelos Unified Diagnostic Services (UDS) Extension

A Zelos extension implementing UDS (ISO 14229) diagnostic protocol over CAN with ISO-TP transport, built with the [Zelos SDK](https://docs.zeloscloud.io/sdk).

## Features

- **UDS Services**: Session Control, Read/Write Data By Identifier, ECU Reset, Routine Control, I/O Control, Tester Present, DTC Reading/Clearing, Security Access, Firmware Flashing
- **CAN Integration**: ISO-TP transport, configurable interfaces (socketcan, PCAN, Kvaser, Vector)
- **Zelos Integration**: Interactive actions via Zelos App
- **CLI**: Execute UDS transactions programmatically from the CLI

## Configuration

Configure via Zelos App settings or `config.json`:

| Setting | Default | Description |
|---------|---------|-------------|
| `interface` | `socketcan` | CAN interface (socketcan, pcan, kvaser, vector) |
| `channel` | `can0` | CAN channel/device |
| `bitrate` | `500000` | CAN bitrate (bps) |
| `tx_id` | `0x7E0` | Tester CAN ID |
| `rx_id` | `0x7E8` | ECU CAN ID |

Advanced settings (optional):
- `request_timeout`, `p2_timeout`, `p2_star_timeout` - UDS timeouts
- `isotp_stmin`, `isotp_blocksize` - ISO-TP flow control
- `isotp_tx_padding`, `isotp_rx_padding`, `isotp_padding_value` - Frame padding

See [config.schema.json](config.schema.json) for complete schema.

## UDS Protocol Reference

Supported services per ISO 14229:

| Service | ID | Description |
|---------|-----|-------------|
| DiagnosticSessionControl | 0x10 | Change diagnostic session |
| ECUReset | 0x11 | Reset ECU |
| ClearDiagnosticInformation | 0x14 | Clear diagnostic trouble codes |
| ReadDTCInformation | 0x19 | Read diagnostic trouble codes |
| ReadDataByIdentifier | 0x22 | Read data by DID |
| SecurityAccess | 0x27 | Request security access (seed/key) |
| WriteDataByIdentifier | 0x2E | Write data by DID |
| InputOutputControlByIdentifier | 0x2F | Control I/O signals |
| RoutineControl | 0x31 | Control diagnostic routines |
| RequestDownload | 0x34 | Initiate firmware download |
| TransferData | 0x36 | Transfer firmware data blocks |
| RequestTransferExit | 0x37 | Finalize firmware transfer |
| TesterPresent | 0x3E | Keep session alive |

### Standard CAN IDs

| ID Range | Purpose |
|----------|---------|
| 0x7DF | Functional (broadcast) request |
| 0x7E0-0x7E7 | Physical request IDs |
| 0x7E8-0x7EF | Physical response IDs |

### Common Negative Response Codes

| Code | Name | Description |
|------|------|-------------|
| 0x11 | serviceNotSupported | Service not supported in current session |
| 0x13 | incorrectMessageLengthOrInvalidFormat | Invalid message format |
| 0x22 | conditionsNotCorrect | Preconditions not met |
| 0x31 | requestOutOfRange | Parameter out of range |
| 0x33 | securityAccessDenied | Security access required |
| 0x78 | requestCorrectlyReceived-ResponsePending | Request pending |

## Links

- [Zelos Documentation](https://docs.zeloscloud.io)
- [Zelos SDK Guide](https://docs.zeloscloud.io/sdk)
- [ISO 14229 Specification](https://www.iso.org/standard/72439.html)
- [udsoncan Library](https://github.com/pylessard/python-udsoncan)
- [python-can Documentation](https://python-can.readthedocs.io/)

## CLI Usage

The extension includes a command-line interface for executing UDS transactions. No installation required - just use `uv run`:

> **Tip:** Run `pip install .` to install and use `zelos-extension-uds <args>` from anywhere.

```bash
# Change to extended diagnostic session
uv run main.py session --txid 7E0 --rxid 7E8 --type extended

# Read VIN (DID 0xF190)
uv run main.py read --txid 7E0 --rxid 7E8 --id F190

# Write data
uv run main.py write --txid 7E0 --rxid 7E8 --id 1234 --data 01020304

# Read DTCs
uv run main.py dtc --txid 7E0 --rxid 7E8

# Clear DTCs
uv run main.py clear --txid 7E0 --rxid 7E8

# Request security seed
uv run main.py security --txid 7E0 --rxid 7E8 --level 1 --seed

# Send security key
uv run main.py security --txid 7E0 --rxid 7E8 --level 1 --key 01020304

# ECU reset
uv run main.py reset --txid 7E0 --rxid 7E8 --response-required --type hard

# Flash firmware
uv run main.py flash --txid 7E0 --rxid 7E8 --file firmware.bin --address 08000000

# Start routine
uv run main.py routine --txid 7E0 --rxid 7E8 --id 0203 --control start --data 0102

# I/O control
uv run main.py io --txid 7E0 --rxid 7E8 --id 1234 --control freeze

# Tester present
uv run main.py tp --txid 7E0 --rxid 7E8
```

**Available subcommands:** `session`, `read`, `write`, `reset`, `routine`, `io`, `tp`, `dtc`, `clear`, `security`, `flash`

All hex values accept formats: `7E0`, `0x7E0`, `01020304`, `0x01020304`

## License

MIT License - see [LICENSE](LICENSE) for details.
