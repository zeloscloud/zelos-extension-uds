"""CAN ids, extended ids, CAN FD and bus sharing keys."""

import pytest

from zelos_extension_uds import link


def test_ids_standard_and_extended():
    assert link.ids({"tx_id": "0x7E0", "rx_id": "7e8"}) == (0x7E0, 0x7E8, False)
    ext = {"tx_id": "18DA10F1", "rx_id": "0x18DAF110", "extended_ids": True}
    assert link.ids(ext) == (0x18DA10F1, 0x18DAF110, True)
    assert link.id_text(0x18DA10F1, True) == "0x18DA10F1"
    assert link.address(0x18DA10F1, 0x18DAF110, True).is_tx_29bits


@pytest.mark.parametrize(
    "ecu, why",
    [
        ({"tx_id": "0x800", "rx_id": "0x7E8"}, "turn on Extended IDs"),
        ({"tx_id": "0x20000000", "rx_id": "1", "extended_ids": True}, "extended CAN id"),
        ({"tx_id": "zz", "rx_id": "0x7E8"}, "not a hex CAN id"),
        ({"rx_id": "0x7E8"}, "no Request CAN ID"),
        ({"tx_id": "0x7E0", "rx_id": "0x7E0"}, "must differ"),
    ],
)
def test_ids_refused(ecu, why):
    with pytest.raises(ValueError, match=why):
        link.ids(ecu)


def test_isotp_params_fd():
    classic = link.isotp_params({"isotp_blocksize": 8, "isotp_padding": 0xCC}, fd=False)
    assert classic["tx_data_length"] == 8 and not classic["can_fd"]
    assert classic["tx_padding"] == 0xCC and classic["blocksize"] == 8
    fd = link.isotp_params({}, fd=True)
    assert fd["tx_data_length"] == 64 and fd["can_fd"] and "tx_padding" not in fd


def test_bus_key_and_settings():
    a = {"interface": "pcan", "channel": "PCAN_USBBUS1", "bitrate": 500000, "tx_id": "0x7E0"}
    b = {**a, "tx_id": "0x7E1", "fd_mode": False, "data_bitrate": 2000000}
    assert link.bus_key(a) == link.bus_key(b)
    assert link.bus_settings(a) == link.bus_settings(b)  # data_bitrate counts with FD only
    assert link.bus_settings(a) != link.bus_settings({**a, "bitrate": 250000})
    ssh = {"interface": "zelos-ssh-socketcan", "remote_host": "edge", "remote_channel": "can1"}
    assert link.bus_key(ssh) == ("zelos-ssh-socketcan", "edge", "can1", None, 22)
    other_user = {**ssh, "ssh_user": "root"}
    assert link.bus_key(other_user) != link.bus_key(ssh)
    assert link.bus_settings({**ssh, "ssh_key_path": "k"}) != link.bus_settings(ssh)
