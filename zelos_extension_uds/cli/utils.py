"""CLI utility functions for UDS extension."""

import logging
import signal
import sys
from types import FrameType

logger = logging.getLogger(__name__)


def setup_shutdown_handler(client) -> None:
    """Setup graceful shutdown handler for SIGTERM and SIGINT.

    :param client: UDS client instance to stop on shutdown
    """

    def shutdown_handler(signum: int, frame: FrameType | None) -> None:
        """Handle shutdown signal.

        :param signum: Signal number (SIGTERM=15, SIGINT=2)
        :param frame: Current stack frame
        """
        logger.info("Shutting down UDS client...")
        client.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)
