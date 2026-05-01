"""End-to-end verification of typed payload + endianness across both surfaces.

Drives the DemoUDSServer used in unit tests via:

  - Agent path: the @action methods on UDSClient (what Zelos App invokes).
  - CLI path:   the click subcommands' callbacks (what users run on the
                shell). Same-process invocation is required: python-can's
                ``virtual`` interface is per-process so cross-process
                testing is not viable.

Asserts the bytes that hit the wire after typed encoding and the
``representations`` field surfaced by the read action.
"""

from __future__ import annotations

import json
import struct

import pytest

from zelos_extension_uds.cli.io import io as io_cmd
from zelos_extension_uds.cli.routine import routine as routine_cmd
from zelos_extension_uds.cli.write import write as write_cmd
from zelos_extension_uds.demo_server import DemoUDSServer
from zelos_extension_uds.extension import UDSClient


@pytest.fixture
def channel() -> str:
    return f"test_e2e_{id(object())}"


@pytest.fixture
def demo_server(channel: str):
    server = DemoUDSServer(
        channel=channel,
        tx_id=0x7E8,  # Server TX (ECU response) = client RX
        rx_id=0x7E0,  # Server RX (tester request) = client TX
    )
    server.start()
    yield server
    server.stop()


@pytest.fixture
def uds_client(channel: str):
    config = {
        "interface": "virtual",
        "channel": channel,
        "tx_id": "0x7E0",
        "rx_id": "0x7E8",
    }
    client = UDSClient(config)
    client.start()
    yield client
    client.stop()


# ---------------------------------------------------------------------------
# Agent path: @action methods
# ---------------------------------------------------------------------------


def test_agent_write_uint16_big_endian(demo_server: DemoUDSServer, uds_client: UDSClient) -> None:
    result = uds_client.write_data_by_identifier(
        did="0x0100", data="0x1234", data_type="uint16", endianness="big"
    )
    assert result.get("status") == "success", result
    # Bytes that hit the wire = 12 34
    assert demo_server.last_write == (0x0100, b"\x12\x34")


def test_agent_write_uint16_little_endian(
    demo_server: DemoUDSServer, uds_client: UDSClient
) -> None:
    result = uds_client.write_data_by_identifier(
        did="0x0100", data="0x1234", data_type="uint16", endianness="little"
    )
    assert result.get("status") == "success", result
    assert demo_server.last_write == (0x0100, b"\x34\x12")


def test_agent_write_int16_negative(demo_server: DemoUDSServer, uds_client: UDSClient) -> None:
    result = uds_client.write_data_by_identifier(
        did="0x0100", data="-1", data_type="int16", endianness="big"
    )
    assert result.get("status") == "success", result
    assert demo_server.last_write == (0x0100, b"\xff\xff")


def test_agent_write_float_be(demo_server: DemoUDSServer, uds_client: UDSClient) -> None:
    result = uds_client.write_data_by_identifier(
        did="0x0100", data="3.14", data_type="float", endianness="big"
    )
    assert result.get("status") == "success", result
    assert demo_server.last_write == (0x0100, struct.pack(">f", 3.14))


def test_agent_write_float_le(demo_server: DemoUDSServer, uds_client: UDSClient) -> None:
    result = uds_client.write_data_by_identifier(
        did="0x0100", data="3.14", data_type="float", endianness="little"
    )
    assert result.get("status") == "success", result
    assert demo_server.last_write == (0x0100, struct.pack("<f", 3.14))


def test_agent_write_then_read_includes_representations(
    demo_server: DemoUDSServer, uds_client: UDSClient
) -> None:
    # Write a uint32 BE
    write = uds_client.write_data_by_identifier(
        did="0x0100", data="0xCAFEBABE", data_type="uint32", endianness="big"
    )
    assert write.get("status") == "success", write

    read = uds_client.read_data_by_identifier(did="0x0100")
    assert read.get("status") == "success", read
    assert read["data"] == "0xCAFEBABE"
    assert read["length"] == 4
    reps = read["representations"]
    assert reps["uint32_be"] == 0xCAFEBABE
    assert reps["uint32_le"] == int.from_bytes(b"\xca\xfe\xba\xbe", "little")
    # 0xCAFEBABE as int32_be is negative
    assert reps["int32_be"] == struct.unpack(">i", b"\xca\xfe\xba\xbe")[0]
    assert "float_be" in reps and "float_le" in reps


def test_agent_routine_control_uint16_le(demo_server: DemoUDSServer, uds_client: UDSClient) -> None:
    result = uds_client.routine_control(
        routine_id="0x0203",
        control_type="Start Routine",
        data="0x00FF",
        data_type="uint16",
        endianness="little",
    )
    assert result.get("status") == "success", result
    # Routine data captured by demo server = bytes after 4-byte header
    assert demo_server.last_routine_data == b"\xff\x00"


def test_agent_io_control_int8(demo_server: DemoUDSServer, uds_client: UDSClient) -> None:
    result = uds_client.input_output_control(
        did="0x0100",
        control_parameter="Short Term Adjustment",
        control_option="-1",
        control_option_type="int8",
        endianness="big",
    )
    assert result.get("status") == "success", result
    # int8 -1 = 0xFF
    assert demo_server.last_io_payload == b"\xff"


def test_agent_hex_path_unchanged(demo_server: DemoUDSServer, uds_client: UDSClient) -> None:
    # Default path: data_type='hex', endianness ignored
    result = uds_client.write_data_by_identifier(did="0x0100", data="DE AD BE EF")
    assert result.get("status") == "success", result
    assert demo_server.last_write == (0x0100, b"\xde\xad\xbe\xef")


# ---------------------------------------------------------------------------
# CLI path: click subcommand callbacks
# ---------------------------------------------------------------------------
#
# Tests invoke each ``cmd.callback(**kwargs)`` directly rather than via
# click.testing.CliRunner: rich-click's global Console captures streams
# at module import, and CliRunner's stream-redirection sandbox then
# raises ``ValueError: I/O operation on closed file`` after the command
# body completes. The CLI parsing is plain ``@click.option`` decorators,
# so calling the callback with the kwargs click would produce fully
# exercises the typed-payload + endianness code path.


def test_cli_write_uint16_be(channel: str, demo_server: DemoUDSServer) -> None:
    write_cmd.callback(
        txid="7E0",
        rxid="7E8",
        did="0100",
        data="0x1234",
        data_type="uint16",
        endianness="big",
        interface="virtual",
        channel=channel,
        bitrate=None,
    )
    assert demo_server.last_write == (0x0100, b"\x12\x34")


def test_cli_write_int32_le(channel: str, demo_server: DemoUDSServer) -> None:
    write_cmd.callback(
        txid="7E0",
        rxid="7E8",
        did="0100",
        data="-1",
        data_type="int32",
        endianness="little",
        interface="virtual",
        channel=channel,
        bitrate=None,
    )
    assert demo_server.last_write == (0x0100, b"\xff\xff\xff\xff")


def test_cli_write_float_le(channel: str, demo_server: DemoUDSServer) -> None:
    write_cmd.callback(
        txid="7E0",
        rxid="7E8",
        did="0100",
        data="3.14",
        data_type="float",
        endianness="little",
        interface="virtual",
        channel=channel,
        bitrate=None,
    )
    assert demo_server.last_write == (0x0100, struct.pack("<f", 3.14))


def test_cli_write_hex_default(channel: str, demo_server: DemoUDSServer) -> None:
    """Backwards-compat: hex is the default and bytes hit the wire unchanged."""
    write_cmd.callback(
        txid="7E0",
        rxid="7E8",
        did="0100",
        data="DEADBEEF",
        data_type="hex",
        endianness="big",
        interface="virtual",
        channel=channel,
        bitrate=None,
    )
    assert demo_server.last_write == (0x0100, b"\xde\xad\xbe\xef")


def test_cli_routine_with_uint16(channel: str, demo_server: DemoUDSServer) -> None:
    routine_cmd.callback(
        txid="7E0",
        rxid="7E8",
        routine_id="0203",
        control="start",
        data="0x00FF",
        data_type="uint16",
        endianness="little",
        interface="virtual",
        channel=channel,
        bitrate=None,
    )
    assert demo_server.last_routine_data == b"\xff\x00"


def test_cli_io_with_int8(channel: str, demo_server: DemoUDSServer) -> None:
    io_cmd.callback(
        txid="7E0",
        rxid="7E8",
        did="0100",
        control="adjust",
        option="-1",
        option_type="int8",
        endianness="big",
        interface="virtual",
        channel=channel,
        bitrate=None,
    )
    assert demo_server.last_io_payload == b"\xff"


# ---------------------------------------------------------------------------
# UDSClient demo interface (embedded demo server)
# ---------------------------------------------------------------------------


def test_uds_client_demo_interface_round_trip() -> None:
    """When interface='demo', the extension hosts its own demo ECU."""
    config = {
        "interface": "demo",
        "tx_id": "0x7E0",
        "rx_id": "0x7E8",
    }
    client = UDSClient(config)
    client.start()
    try:
        assert client.demo_server is not None
        # config stays untouched — interface translation happens at use
        # time via _resolve_can_transport() so start/stop cycles are
        # idempotent.
        assert client.config["interface"] == "demo"
        assert client._resolve_can_transport() == ("virtual", "zelos_uds_demo")

        # Write a typed value, read it back, verify representations
        wrote = client.write_data_by_identifier(
            did="0x0100", data="0x1234", data_type="uint16", endianness="big"
        )
        assert wrote.get("status") == "success", wrote

        read = client.read_data_by_identifier(did="0x0100")
        assert read.get("status") == "success", read
        assert read["data"] == "0x1234"
        assert read["representations"]["uint16_be"] == 0x1234
        assert read["representations"]["uint16_le"] == 0x3412

        # And the JSON payload Zelos App would render is well-formed
        json.dumps(read)
    finally:
        client.stop()
        assert client.demo_server is None


def test_uds_client_demo_restart_cycle() -> None:
    """Stop+start must respawn the demo server (config-mutation regression)."""
    config = {"interface": "demo", "tx_id": "0x7E0", "rx_id": "0x7E8"}
    client = UDSClient(config)
    try:
        client.start()
        first = client.demo_server
        assert first is not None
        client.stop()
        assert client.demo_server is None

        client.start()
        second = client.demo_server
        assert second is not None
        assert second is not first  # new instance after restart
    finally:
        client.stop()
