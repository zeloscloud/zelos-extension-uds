"""Zelos SDK pytest plugin attributes."""


def pytest_configure(config):
    config.zelos_local_artifacts_dir = None
    config.zelos_remote_artifacts_dir = None
    config.zelos_device_id = None
