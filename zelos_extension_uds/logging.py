"""Logging configuration for zelos-extension-uds.

This module owns the TraceLoggingHandler setup and provides a single point
for configuring log levels across the extension.
"""

import logging
import time

from zelos_sdk.hooks.logging import TraceLoggingHandler

# Create and configure the TraceLoggingHandler
# Handler level is set to DEBUG to allow all logs through;
# the root logger level controls actual filtering
_trace_handler = TraceLoggingHandler("uds_log")
_trace_handler.setLevel(logging.DEBUG)

# UTC ISO 8601 with ms, matching the SDK's Rust tracing lines in the same log stream
logging.Formatter.converter = time.gmtime
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03dZ %(levelname)5s %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logging.getLogger().addHandler(_trace_handler)


def set_log_level(level: int) -> None:
    """Set the log level for the extension.

    Updates the root logger and enables library debug logging when appropriate.

    :param level: logging level (e.g., logging.DEBUG, logging.INFO)
    """
    logger = logging.getLogger()
    logger.setLevel(level)

    # Enable library loggers for DEBUG level to get ISOTP frame-level logging
    if level == logging.DEBUG:
        logging.getLogger("udsoncan").setLevel(logging.DEBUG)
        logging.getLogger("isotp").setLevel(logging.DEBUG)
        logging.getLogger("can").setLevel(logging.DEBUG)
