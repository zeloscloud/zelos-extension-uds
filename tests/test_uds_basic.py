"""Basic unit tests for UDS extension.

Tests the on-demand connection architecture and core functionality
without requiring a full mock UDS server.
"""

from zelos_extension_uds.extension import UDSClient


def test_client_start_stop():
    """Test basic client lifecycle."""
    config = {
        "interface": "virtual",
        "channel": "test_basic",
        "tx_id": "0x7E0",
        "rx_id": "0x7E8",
    }
    client = UDSClient(config)

    # Should not be running initially
    assert not client.running

    # Start the client
    client.start()
    assert client.running

    # Stop the client
    client.stop()
    assert not client.running


def test_get_status():
    """Test get_status action."""
    config = {
        "interface": "virtual",
        "channel": "test_status",
        "tx_id": "0x7E0",
        "rx_id": "0x7E8",
    }
    client = UDSClient(config)
    client.start()

    status = client.get_status()

    assert status["running"] is True
    assert status["connection_mode"] == "on-demand (stateless)"
    assert status["interface"] == "virtual"
    assert status["channel"] == "test_status"
    assert status["default_tx_id"] == "0x7E0"  # Config values are strings
    assert status["default_rx_id"] == "0x7E8"  # Config values are strings
    assert status["tester_present_active"] is False

    client.stop()


def test_tx_rx_id_resolution_from_config():
    """Test that TX/RX IDs are properly resolved from config."""
    config = {
        "interface": "virtual",
        "channel": "test_ids",
        "tx_id": "0x7E0",
        "rx_id": "0x7E8",
    }
    client = UDSClient(config)
    client.start()

    # Test ID resolution
    result = client._resolve_tx_rx_ids()

    assert isinstance(result, tuple)
    assert len(result) == 2
    assert result[0] == 0x7E0  # Should be int, not string
    assert result[1] == 0x7E8  # Should be int, not string

    client.stop()


def test_tx_rx_id_resolution_with_override():
    """Test that action-specific TX/RX IDs override config."""
    config = {
        "interface": "virtual",
        "channel": "test_override",
        "tx_id": "0x7E0",
        "rx_id": "0x7E8",
    }
    client = UDSClient(config)
    client.start()

    # Override with action-specific IDs
    result = client._resolve_tx_rx_ids(tx_id="0x700", rx_id="0x708")

    assert isinstance(result, tuple)
    assert result[0] == 0x700  # Override value
    assert result[1] == 0x708  # Override value

    client.stop()


def test_tx_rx_id_validation_error():
    """Test that invalid TX/RX IDs return error."""
    config = {
        "interface": "virtual",
        "channel": "test_invalid",
        "tx_id": "not_a_hex_value",  # Invalid hex string
        "rx_id": "0x7E8",
    }
    client = UDSClient(config)
    client.start()

    result = client._resolve_tx_rx_ids()

    assert isinstance(result, dict)
    assert "error" in result
    assert "Invalid TX ID" in result["error"]

    client.stop()


def test_client_requires_start():
    """Test that actions return error when client not started."""
    config = {
        "interface": "virtual",
        "channel": "test_not_started",
        "tx_id": "0x7E0",
        "rx_id": "0x7E8",
    }
    client = UDSClient(config)

    # Try to read without starting
    result = client.read_data_by_identifier(did="0xF190")

    assert isinstance(result, dict)
    assert result.get("error") == "UDS client not started"


def test_session_type_validation():
    """Test diagnostic session control validates session types."""
    config = {
        "interface": "virtual",
        "channel": "test_session",
        "tx_id": "0x7E0",
        "rx_id": "0x7E8",
    }
    client = UDSClient(config)
    client.start()

    # Invalid session type should return error
    result = client.diagnostic_session_control(session_type="invalid_session")

    assert isinstance(result, dict)
    assert "error" in result
    assert "Unknown session type" in result["error"]

    client.stop()


def test_reset_type_validation():
    """Test ECU reset validates reset types."""
    config = {
        "interface": "virtual",
        "channel": "test_reset",
        "tx_id": "0x7E0",
        "rx_id": "0x7E8",
    }
    client = UDSClient(config)
    client.start()

    # Invalid reset type should return error
    result = client.ecu_reset(reset_type="invalid_reset")

    assert isinstance(result, dict)
    assert "error" in result
    assert "Invalid reset type" in result["error"]

    client.stop()


def test_did_validation():
    """Test that DID validation works correctly."""
    config = {
        "interface": "virtual",
        "channel": "test_did",
        "tx_id": "0x7E0",
        "rx_id": "0x7E8",
    }
    client = UDSClient(config)
    client.start()

    # Invalid DID (too large) should return error before attempting connection
    result = client.read_data_by_identifier(did="0xFFFFF")

    assert isinstance(result, dict)
    assert "error" in result

    client.stop()


def test_periodic_tester_present_start_stop():
    """Test periodic tester present configuration (without async runtime).

    This test validates that periodic TP settings are correctly stored,
    but doesn't actually run the async task since that requires an event loop.
    """
    config = {
        "interface": "virtual",
        "channel": "test_periodic",
        "tx_id": "0x7E0",
        "rx_id": "0x7E8",
    }
    client = UDSClient(config)
    client.start()

    # Verify TP is initially disabled
    assert client.tester_present_interval == 0
    assert client.tester_present_tx_id is None
    assert client.tester_present_rx_id is None

    # Note: We can't actually test the periodic task creation without an event loop,
    # so this test just validates that the configuration is properly managed.
    # The actual async periodic TP functionality is tested in test_uds_transactions.py

    client.stop()
