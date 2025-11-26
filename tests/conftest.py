"""Pytest configuration for UDS extension tests."""


def pytest_configure(config):
    """Configure pytest for Zelos SDK."""
    # Set up Zelos SDK configuration attributes
    config.zelos_local_artifacts_dir = None
    config.zelos_remote_artifacts_dir = None
    config.zelos_device_id = None
