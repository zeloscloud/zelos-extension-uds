"""App-based configuration mode for UDS diagnostics."""

import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

import zelos_sdk
from zelos_sdk.extensions import load_config

from ..utils import validate_hex_id
from .utils import setup_shutdown_handler

logger = logging.getLogger(__name__)


def run_app_mode(file: Path | None) -> None:
    """Run UDS extension in app-based configuration mode.

    :param file: Optional output file for trace recording
    """
    # Load and validate configuration
    config = load_config()

    # Apply log level from config
    log_level_str = config.get("log_level", "INFO")
    try:
        log_level = getattr(logging, log_level_str)
        logging.getLogger().setLevel(log_level)
        logger.info(f"Log level set to: {log_level_str}")
    except AttributeError:
        logger.warning(f"Invalid log level '{log_level_str}', using INFO")
        logging.getLogger().setLevel(logging.INFO)

    # Parse hex IDs from config (stored as strings)
    tx_id_str = config.get("tx_id", "0x7E0")
    rx_id_str = config.get("rx_id", "0x7E8")

    tx_id = validate_hex_id(tx_id_str, max_value=0x7FF)
    rx_id = validate_hex_id(rx_id_str, max_value=0x7FF)

    if isinstance(tx_id, dict):
        logger.error(f"Invalid TX ID: {tx_id['error']}")
        sys.exit(1)

    if isinstance(rx_id, dict):
        logger.error(f"Invalid RX ID: {rx_id['error']}")
        sys.exit(1)

    # Update config with parsed IDs
    config["tx_id"] = tx_id
    config["rx_id"] = rx_id

    # Determine output file if --file was specified
    output_file = None
    if file is not None:
        if file == Path("."):
            # Default filename using UTC timestamp
            output_file = Path(f"{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}_uds.trz")
        else:
            output_file = file

        logger.info(f"Recording trace to: {output_file}")

    # Initialize SDK with actions enabled
    zelos_sdk.init(name="uds", log_level=log_level_str.lower(), actions=True)

    # Create UDS client (lazy import to avoid action decorator issues)
    from ..extension import UDSClient

    logger.info("Creating UDS client")
    client = UDSClient(config)

    # Register actions for Zelos App
    zelos_sdk.actions_registry.register(client, "uds_client")

    # Setup graceful shutdown
    setup_shutdown_handler(client)

    # Run with optional trace recording
    try:
        if output_file:
            with zelos_sdk.TraceWriter(str(output_file)):
                logger.info("Starting UDS client with trace recording")
                client.start()
                client.run()
        else:
            logger.info("Starting UDS client")
            client.start()
            client.run()

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Error running UDS client: {e}", exc_info=True)
        sys.exit(1)
    finally:
        client.stop()
        logger.info("UDS client stopped")
