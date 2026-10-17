"""UDS conformance: the bench's ISO 14229-1 server contract, tested as a tester sees it.

Runs against any server on any python-can bus: the DC-DC node (`-S uds`) on
SocketCAN, under Renode or on hardware, or the UDS extension's demo ECU in the
test process (`--interface zelos-virtual`, with a conftest.py overriding the
`uds_server` fixture). Requests on 0x7E0, functional on 0x7DF, responses on
0x7E8. The contract is nodes/dcdc/src/uds.c; seed to key is
zelos_testing.uds_keys. What only the DC-DC node itself shows is
test_dcdc_node.py.

Timing checks run in real time only, with a 2 % margin: the node's clock runs
about 0.5 % fast.
"""

import os
import struct
import time
import zlib

import pytest
from udsoncan.services import ECUReset

from zelos_testing import frames, uds_keys
from zelos_testing.frames import bound, collect
from zelos_testing.uds import (
    ACTIVE_SESSION,
    ADJUST,
    BLOCK_LENGTH,
    CALIBRATION,
    CALIBRATION_ADDRESS,
    CDTC,
    CHECK,
    CURRENT,
    DEFAULT,
    DOWNLOAD_ADDRESS,
    DOWNLOAD_SIZE,
    DTC_OVERTEMPERATURE,
    DTCS,
    ERASE,
    EXTENDED,
    FREEZE,
    IDENTIFICATION,
    INPUT_A,
    INPUT_V,
    LEVEL_EXTENDED,
    LEVEL_PROGRAMMING,
    MARGIN,
    OUTPUT,
    PDTC,
    PROGRAMMING,
    RESET,
    RESPONSE,
    RETURN,
    S3_S,
    SECURITY_DELAY_S,
    SELF_TEST,
    SELF_TEST_S,
    SETPOINT,
    SETPOINT_V,
    STATE,
    STATE_ADDRESS,
    TEMPERATURE,
    TF,
    TFSLC,
    UPTIME,
    VIN,
    VOLTAGE,
    NegativeResponseException,
    dtcs,
    location,
    reset,
    transfer_block,
)

pytestmark = pytest.mark.usefixtures("bus_health")


def nrc(call, *args, **kwargs) -> int:
    """The negative response code call raises."""
    with pytest.raises(NegativeResponseException) as e:
        call(*args, **kwargs)
    return e.value.response.code


def real_time():
    if frames.SIMULATED:
        pytest.skip("timing is the server's, and only hardware runs in real time")



# --- Identification and data ---------------------------------------------------


def test_identification(ecu):
    values = ecu.client.read_data_by_identifier([ACTIVE_SESSION, *IDENTIFICATION]).service_data.values
    assert values == {ACTIVE_SESSION: DEFAULT, **IDENTIFICATION}


def test_live_values_are_typed(ecu):
    values = ecu.client.read_data_by_identifier([VOLTAGE, CURRENT, TEMPERATURE, UPTIME, INPUT_V, INPUT_A, SETPOINT]).service_data.values
    assert values[SETPOINT] == SETPOINT_V
    assert 0 < values[VOLTAGE] <= 16.0
    assert -40 <= values[TEMPERATURE] <= 127
    first = values[UPTIME]
    time.sleep(1.0)
    elapsed_ms = ecu.read(UPTIME) - first
    assert elapsed_ms > 0
    if not frames.SIMULATED:
        assert elapsed_ms == pytest.approx(1000, rel=MARGIN, abs=20)


def test_unknown_identifiers_are_left_out_of_the_read(ecu):
    # ISO 14229-1: the supported DIDs answer; 0x31 only when none is supported.
    assert ecu.raw(b"\x22\xf1\x86\x12\x34") == b"\x62\xf1\x86\x01"
    assert ecu.raw(b"\x22\x12\x34\x56\x78") == b"\x7f\x22\x31"


def test_setpoint_and_vin_are_written_in_extended_with_level_1(ecu):
    assert nrc(ecu.client.write_data_by_identifier, SETPOINT, 12.0) == 0x7F
    ecu.enter(EXTENDED, PROGRAMMING)
    assert nrc(ecu.client.write_data_by_identifier, SETPOINT, 12.0) == 0x31
    ecu.enter(EXTENDED)
    assert nrc(ecu.client.write_data_by_identifier, SETPOINT, 12.0) == 0x33
    assert nrc(ecu.client.write_data_by_identifier, 0xF187, "X" * 13) == 0x31  # read-only
    ecu.unlock(LEVEL_EXTENDED)
    assert ecu.raw(b"\x2e\x02\x00\x04") == b"\x7f\x2e\x13"
    assert nrc(ecu.client.write_data_by_identifier, SETPOINT, 16.01) == 0x31
    assert nrc(ecu.client.write_data_by_identifier, VIN, "TAB\tNOT\tPRINTABLE") == 0x31
    ecu.client.write_data_by_identifier(SETPOINT, 12.34)
    ecu.client.write_data_by_identifier(VIN, "WZL0000000TESTVIN")
    try:
        assert ecu.read(SETPOINT) == 12.34
        assert ecu.read(VIN) == "WZL0000000TESTVIN"
    finally:
        ecu.client.write_data_by_identifier(SETPOINT, SETPOINT_V)
        ecu.client.write_data_by_identifier(VIN, IDENTIFICATION[VIN])


def test_memory_by_address(ecu):
    state = STATE.unpack(ecu.client.read_memory_by_address(location(STATE_ADDRESS, STATE.size)).service_data.memory_block)
    assert state[5] == pytest.approx(SETPOINT_V)  # setpoint_v
    # 1- and 2-byte sizes too; nothing outside a window, nothing straddling one.
    assert len(ecu.client.read_memory_by_address(location(STATE_ADDRESS + 4, 4, 8)).service_data.memory_block) == 4
    assert len(ecu.client.read_memory_by_address(location(STATE_ADDRESS, 8, 16)).service_data.memory_block) == 8
    assert nrc(ecu.client.read_memory_by_address, location(STATE_ADDRESS + STATE.size - 2, 4)) == 0x31
    assert nrc(ecu.client.read_memory_by_address, location(0x00030000, 4)) == 0x31
    assert ecu.raw(b"\x23\x22\x00\x01\x00\x04") == b"\x7f\x23\x31"  # 2-byte address

    assert nrc(ecu.client.write_memory_by_address, location(CALIBRATION_ADDRESS, 4), b"\x00" * 4) == 0x7F
    ecu.enter(EXTENDED)
    assert nrc(ecu.client.write_memory_by_address, location(STATE_ADDRESS, 4), b"\x00" * 4) == 0x31
    assert nrc(ecu.client.write_memory_by_address, location(CALIBRATION_ADDRESS, 4), b"\x00" * 4) == 0x33
    ecu.unlock(LEVEL_EXTENDED)
    original = ecu.client.read_memory_by_address(location(CALIBRATION_ADDRESS, CALIBRATION.size)).service_data.memory_block
    ecu.client.write_memory_by_address(location(CALIBRATION_ADDRESS, 4), struct.pack("<f", 3.0))
    try:
        assert CALIBRATION.unpack(ecu.client.read_memory_by_address(location(CALIBRATION_ADDRESS, 8)).service_data.memory_block)[0] == 3.0
    finally:
        ecu.client.write_memory_by_address(location(CALIBRATION_ADDRESS, CALIBRATION.size), original)


# --- Negative responses and addressing ------------------------------------------


@pytest.mark.parametrize(
    ("request_", "code"),
    [
        *(pytest.param(bytes([sid, 0x01]), 0x11, id=f"tier B {sid:#04x}") for sid in (0x24, 0x29, 0x2A, 0x2C, 0x38, 0x83, 0x84, 0x86, 0x87)),
        pytest.param(b"\x3e\x05", 0x12, id="no such sub-function"),
        pytest.param(b"\x3e\x00\x00", 0x13, id="a byte too many"),
        pytest.param(b"\x10", 0x13, id="minimum length before sub-function"),
        pytest.param(b"\x10\x02", 0x22, id="programming only from extended"),
        pytest.param(b"\x19\x82\xff", 0x12, id="no suppressPosRsp on ReadDTCInformation"),
        pytest.param(b"\x19\x05\xff", 0x12, id="unsupported ReadDTCInformation"),
        pytest.param(b"\x2e\x02\x00\x05\x14", 0x7F, id="write needs a non-default session"),
        pytest.param(b"\x27\x01", 0x7F, id="security access needs a non-default session"),
        pytest.param(b"\x28\x00\x01", 0x7F, id="communication control"),
        pytest.param(b"\x85\x02", 0x7F, id="DTC setting"),
        pytest.param(b"\x2f\x03\x00\x03\x05\x14", 0x7F, id="io control needs extended"),
        pytest.param(b"\x31\x01\x02\x01", 0x7F, id="routines need a non-default session"),
        pytest.param(b"\x3d\x14\x00\x02\x00\x00\x01\x00", 0x7F, id="memory write needs extended"),
        pytest.param(b"\x34\x00\x44\x00\x10\x00\x00\x00\x00\x01\x00", 0x7F, id="download needs programming"),
        pytest.param(b"\x35\x00\x44\x00\x10\x00\x00\x00\x00\x01\x00", 0x7F, id="upload needs programming"),
    ],
)
def test_negative_responses(ecu, request_, code):
    assert ecu.raw(request_) == bytes([0x7F, request_[0], code])


@pytest.mark.parametrize(
    ("request_", "code"),
    [
        pytest.param(b"\x27\x11", 0x7E, id="level 0x11 is programming's"),
        pytest.param(b"\x2e\x12\x34\x00", 0x31, id="identifier before security"),
        pytest.param(b"\x2e\x02\x00\x00", 0x33, id="security before exact length"),
        pytest.param(b"\x2f\x03\x00\x07", 0x31, id="control parameter before security"),
        pytest.param(b"\x28\x00\x02", 0x31, id="communication type before security"),
        pytest.param(b"\x28\x02\x01", 0x12, id="enableTxDisableRx not supported"),
        pytest.param(b"\x28\x00\x01", 0x33, id="communication control needs security"),
        pytest.param(b"\x85\x02", 0x33, id="DTC setting needs security"),
        pytest.param(b"\x31\x01\xff\x00", 0x31, id="erase is programming's"),
    ],
)
def test_negative_responses_in_extended(ecu, request_, code):
    ecu.enter(EXTENDED)
    assert ecu.raw(request_) == bytes([0x7F, request_[0], code])


def test_functional_requests(ecu):
    # Every ECU hears a functional request; not one it does not support.
    silent_s = bound(0.3)
    for request_ in (b"\x29\x01", b"\x3e\x05", b"\x22\x12\x34", b"\x2e\x02\x00\x05\x14"):
        assert ecu.raw(request_, functional=True, timeout_s=silent_s) is None, request_.hex()
    ecu.enter(EXTENDED)
    assert ecu.raw(b"\x27\x11", functional=True, timeout_s=silent_s) is None  # 0x7E
    # A suppressed keep-alive gets nothing; the rest are answered.
    assert ecu.raw(b"\x3e\x80", functional=True, timeout_s=silent_s) is None
    assert ecu.raw(b"\x3e\x00", functional=True) == b"\x7e\x00"
    assert ecu.raw(b"\x3e\x00\x00", functional=True) == b"\x7f\x3e\x13"
    with ecu.functional() as everyone:
        assert everyone.read_data_by_identifier(ACTIVE_SESSION).service_data.values[ACTIVE_SESSION] == EXTENDED


# --- Sessions and timing ------------------------------------------------------


def test_session_control(ecu):
    timing = ecu.client.change_session(EXTENDED).service_data
    assert (timing.p2_server_max, timing.p2_star_server_max) == (0.05, 5.0)
    for session in (PROGRAMMING, EXTENDED, DEFAULT, EXTENDED, PROGRAMMING, PROGRAMMING, DEFAULT):
        ecu.client.change_session(session)
        assert ecu.session() == session
    # Suppressed: nothing back. The wait also spaces the next request, which
    # Zephyr's ISO-TP drops if it lands before this one is handed off.
    assert ecu.raw(b"\x10\x83", timeout_s=bound(0.3)) is None
    assert ecu.session() == EXTENDED


def test_responds_within_p2(ecu):
    real_time()
    worst = 0.0
    for _ in range(20):
        start = time.monotonic()
        ecu.client.tester_present()
        worst = max(worst, time.monotonic() - start)
    assert worst < 0.05, f"slowest response {worst * 1000:.1f} ms, P2 is 50 ms"


def test_s3_returns_to_default(ecu):
    real_time()
    ecu.enter(EXTENDED)
    time.sleep(S3_S * (1 - MARGIN))
    assert ecu.session() == EXTENDED  # this request restarts S3
    time.sleep(S3_S * (1 + MARGIN))
    assert ecu.session() == DEFAULT


def test_tester_present_keeps_the_session(ecu):
    ecu.enter(EXTENDED)
    # Functional and suppressed, every 2 s, as a tester keeps a session alive.
    end = time.monotonic() + 3 * S3_S
    with ecu.functional() as everyone:
        while time.monotonic() < end:
            with everyone.suppress_positive_response:
                assert everyone.tester_present() is None
            time.sleep(2.0)
    assert ecu.session() == EXTENDED


def test_session_change_returns_the_output_and_locks(ecu):
    ecu.enter(EXTENDED)
    ecu.unlock(LEVEL_EXTENDED)
    assert ecu.client.io_control(OUTPUT, control_param=ADJUST, values=[12.0]).service_data.decoded_data == 12.0
    ecu.enter(EXTENDED)
    assert ecu.client.request_seed(LEVEL_EXTENDED).service_data.seed != bytes(4)
    ecu.unlock(LEVEL_EXTENDED)
    assert ecu.client.io_control(OUTPUT, control_param=FREEZE).service_data.decoded_data == SETPOINT_V
    ecu.client.io_control(OUTPUT, control_param=RETURN)


# --- Security -----------------------------------------------------------------


def test_security_levels(ecu):
    ecu.enter(EXTENDED)
    assert nrc(ecu.client.send_key, 2, bytes(4)) == 0x24  # no seed asked for
    ecu.unlock(LEVEL_EXTENDED)
    assert ecu.client.request_seed(LEVEL_EXTENDED).service_data.seed == bytes(4)  # unlocked
    # Programming relocks; its own level, its own key.
    ecu.enter(PROGRAMMING)
    assert ecu.raw(b"\x27\x01") == b"\x7f\x27\x7e"
    seed = ecu.client.request_seed(LEVEL_PROGRAMMING).service_data.seed
    assert nrc(ecu.client.send_key, 0x12, uds_keys.key(LEVEL_EXTENDED, seed)) == 0x35
    ecu.unlock(LEVEL_PROGRAMMING)
    assert ecu.client.request_seed(LEVEL_PROGRAMMING).service_data.seed == bytes(4)


def test_security_lockout(ecu):
    real_time()
    ecu.enter(EXTENDED)
    ecu.unlock(LEVEL_EXTENDED)  # past any power-up delay
    ecu.enter(EXTENDED)
    codes = []
    for _ in range(3):
        seed = ecu.client.request_seed(LEVEL_EXTENDED).service_data.seed
        wrong = bytes(b ^ 0xFF for b in uds_keys.key(LEVEL_EXTENDED, seed))
        codes.append(nrc(ecu.client.send_key, 2, wrong))
    locked_at = time.monotonic()
    assert codes == [0x35, 0x35, 0x36]
    assert nrc(ecu.client.request_seed, LEVEL_EXTENDED) == 0x37
    # Neither a session change nor waiting less than the delay ends it.
    time.sleep(SECURITY_DELAY_S * (1 - MARGIN) - (time.monotonic() - locked_at))
    ecu.enter(EXTENDED)
    assert nrc(ecu.client.request_seed, LEVEL_EXTENDED) == 0x37
    time.sleep(SECURITY_DELAY_S * (1 + MARGIN) - (time.monotonic() - locked_at))
    ecu.enter(EXTENDED)
    ecu.unlock(LEVEL_EXTENDED, delay_s=0)


def test_security_delay_after_power_up(ecu):
    real_time()
    reset(ecu)
    up_at = time.monotonic()
    ecu.enter(EXTENDED)
    assert nrc(ecu.client.request_seed, LEVEL_EXTENDED) == 0x37
    time.sleep(SECURITY_DELAY_S * (1 + MARGIN) - (time.monotonic() - up_at))
    ecu.enter(EXTENDED)  # S3 ended the last
    ecu.unlock(LEVEL_EXTENDED, delay_s=0)


# --- Control services -----------------------------------------------------------


def test_io_control(ecu):
    ecu.enter(EXTENDED)
    assert nrc(ecu.client.io_control, OUTPUT, control_param=ADJUST, values=[12.0]) == 0x33
    ecu.unlock(LEVEL_EXTENDED)

    def control(param, *values):
        return ecu.client.io_control(OUTPUT, control_param=param, values=list(values) or None).service_data.decoded_data

    assert control(ADJUST, 12.0) == 12.0
    assert control(FREEZE) == 12.0
    assert control(RESET) == SETPOINT_V
    assert control(ADJUST, 15.5) == 15.5
    assert control(RETURN) == SETPOINT_V
    assert nrc(control, ADJUST, 9.99) == 0x31
    assert ecu.raw(b"\x2f\x03\x00\x03\x05") == b"\x7f\x2f\x13"  # half a state
    assert ecu.raw(b"\x2f\x12\x34\x00") == b"\x7f\x2f\x31"


def test_communication_and_dtc_setting_control(ecu):
    ecu.enter(EXTENDED)
    ecu.unlock(LEVEL_EXTENDED)
    for sub in (0x01, 0x03, 0x00):
        assert ecu.raw(bytes([0x28, sub, 0x01])) == bytes([0x68, sub])
    assert ecu.raw(b"\x28\x81\x01", timeout_s=bound(0.3)) is None  # suppressed
    assert ecu.raw(b"\x28\x01\x01\x00") == b"\x7f\x28\x13"
    assert ecu.client.control_dtc_setting(2).service_data.setting_type_echo == 2
    assert ecu.client.control_dtc_setting(1).service_data.setting_type_echo == 1
    assert ecu.raw(b"\x85\x03") == b"\x7f\x85\x12"


# --- DTCs -----------------------------------------------------------------------


def test_dtc_reports(ecu):
    supported = ecu.client.get_supported_dtc().service_data
    assert supported.status_availability.get_byte_as_int() == 0xFF
    assert [d.id for d in supported.dtcs] == list(DTCS)
    ecu.client.clear_dtc(0xFFFFFF)
    # Cleared: none failed since. Untested or passed since, by the model.
    assert dtcs(ecu, TF | TFSLC | CDTC | PDTC) == {}
    count_ = ecu.client.get_number_of_dtc_by_status_mask(0xFF).service_data
    assert count_.dtc_format == 0x01 and count_.dtc_count == len([s for s in dtcs(ecu).values() if s])
    assert nrc(ecu.client.clear_dtc, 0x000001) == 0x31
    ecu.client.clear_dtc(DTC_OVERTEMPERATURE)
    # Extended data 0x01 occurrences, 0x02 aging; snapshot record 0x01 only.
    assert ecu.raw(b"\x19\x06\x0a\x94\x00\x01")[6:] == b"\x01\x00"
    assert ecu.raw(b"\x19\x06\x0a\x94\x00\xff")[6:] == b"\x01\x00\x02\x00"
    assert ecu.raw(b"\x19\x06\x0a\x94\x00\x03") == b"\x7f\x19\x31"
    assert ecu.raw(b"\x19\x04\x12\x34\x56\x01") == b"\x7f\x19\x31"
    assert ecu.raw(b"\x19\x04\x0a\x94\x00\x02") == b"\x7f\x19\x31"
    assert ecu.raw(b"\x19\x04\x0a\x94\x00\xff")[:5] == b"\x59\x04\x0a\x94\x00"
    assert ecu.raw(b"\x19\x02") == b"\x7f\x19\x13"



# --- Routines and programming -----------------------------------------------------


def test_self_test_answers_pending_then_its_result(ecu, bus):
    ecu.enter(EXTENDED)
    assert nrc(ecu.client.stop_routine, SELF_TEST) == 0x24
    started_at = time.time()
    # udsoncan waits out the pending response; the bus shows what the server sent.
    with frames.reading(bus) as seen:
        result = ecu.client.start_routine(SELF_TEST).service_data.routine_status_record
    assert len(result) == 1
    responses = [m for m in seen if m.arbitration_id == RESPONSE and not m.is_error_frame and m.timestamp >= started_at]
    payloads = [bytes(m.data[1 : 1 + m.data[0]]) for m in responses]
    assert payloads == [b"\x7f\x31\x78", b"\x71\x01\x02\x01" + result]
    if not frames.SIMULATED:
        took = responses[1].timestamp - responses[0].timestamp
        assert SELF_TEST_S * (1 - MARGIN) < took < SELF_TEST_S * (1 + MARGIN), f"{took:.3f} s"
    assert ecu.client.get_routine_result(SELF_TEST).service_data.routine_status_record == result
    ecu.enter(EXTENDED, PROGRAMMING)
    assert nrc(ecu.client.start_routine, SELF_TEST) == 0x31


def test_busy_while_pending(ecu):
    # 0x21 while a 0x78 is outstanding; functionally, only where an idle server would answer.
    ecu.enter(EXTENDED)
    assert ecu.raw(b"\x31\x01\x02\x01") == b"\x7f\x31\x78"
    assert ecu.raw(b"\x22\xf1\x86") == b"\x7f\x22\x21"
    assert ecu.raw(b"\x3e\x00", functional=True) == b"\x7f\x3e\x21"
    # suppressPosRsp hides positive responses only.
    assert ecu.raw(b"\x10\x83", functional=True) == b"\x7f\x10\x21"
    with ecu.functional() as everyone:
        everyone.conn.empty_rxqueue()
        for request_ in (b"\x29\x01", b"\x3e\x80"):
            everyone.conn.send(request_)
        # Nothing for these: the next response is the routine's result.
        assert everyone.conn.wait_frame(timeout=bound(SELF_TEST_S))[:4] == b"\x71\x01\x02\x01"


def test_programming_sequence(ecu):
    image = os.urandom(DOWNLOAD_SIZE)
    whole = location(DOWNLOAD_ADDRESS, DOWNLOAD_SIZE)
    ecu.enter(EXTENDED, PROGRAMMING)
    assert nrc(ecu.client.request_download, whole) == 0x33
    assert nrc(ecu.client.start_routine, ERASE) == 0x33
    ecu.unlock(LEVEL_PROGRAMMING)
    assert nrc(ecu.client.request_download, location(DOWNLOAD_ADDRESS + 1, DOWNLOAD_SIZE)) == 0x31
    assert nrc(ecu.client.request_download, location(0x00200000, 16)) == 0x31
    assert ecu.raw(b"\x34\x11\x44\x00\x10\x00\x00\x00\x00\x00\x10") == b"\x7f\x34\x31"  # compressed
    assert nrc(ecu.client.start_routine, CHECK, zlib.crc32(image).to_bytes(4, "big")) == 0x24  # nothing downloaded
    assert nrc(ecu.client.start_routine, ERASE, b"\x44" + (DOWNLOAD_ADDRESS + DOWNLOAD_SIZE).to_bytes(4, "big") + (1).to_bytes(4, "big")) == 0x31

    # Erase answers pending; downloading needs it.
    assert ecu.client.start_routine(ERASE, b"\x44" + DOWNLOAD_ADDRESS.to_bytes(4, "big") + (16).to_bytes(4, "big")).service_data.routine_status_record == b"\x00"
    assert nrc(ecu.client.request_download, whole) == 0x70  # not all of it erased
    assert ecu.client.start_routine(ERASE).service_data.routine_status_record == b"\x00"

    max_length = ecu.client.request_download(whole).service_data.max_length
    assert max_length == BLOCK_LENGTH
    block = transfer_block(max_length)
    assert nrc(ecu.client.request_download, whole) == 0x22  # one at a time
    assert ecu.raw(b"\x34\x11\x44\x00\x10\x00\x00\x00\x01\x00\x00") == b"\x7f\x34\x31"  # format before 0x22
    assert nrc(ecu.client.start_routine, ERASE) == 0x22
    assert ecu.raw(b"\x36\x02\x00") == b"\x7f\x36\x73"  # counter starts at 1
    chunks = [image[i : i + block] for i in range(0, DOWNLOAD_SIZE, block)]
    for n, chunk in enumerate(chunks, start=1):
        ecu.client.transfer_data(n & 0xFF, chunk)
        if n == 1:
            ecu.client.transfer_data(1, b"\x00" * block)  # a repeat, as after a lost response: not written
            assert ecu.raw(b"\x37") == b"\x7f\x37\x24"  # not all there yet
    assert ecu.raw(bytes([0x36, (len(chunks) + 1) & 0xFF, 0])) == b"\x7f\x36\x71"  # past the end
    ecu.client.request_transfer_exit()
    assert nrc(ecu.client.request_download, whole) == 0x70  # written: no longer erased

    crc = zlib.crc32(image).to_bytes(4, "big")
    assert ecu.client.start_routine(CHECK, crc).service_data.routine_status_record == b"\x00" + crc
    wrong = bytes(b ^ 0xFF for b in crc)
    assert ecu.client.start_routine(CHECK, wrong).service_data.routine_status_record == b"\x01" + crc

    # Read back by upload.
    assert ecu.client.request_upload(whole).service_data.max_length == BLOCK_LENGTH
    read = b""
    blocks = -(-DOWNLOAD_SIZE // (BLOCK_LENGTH - 2))  # the node's, full size
    for n in range(1, blocks + 1):
        read += ecu.client.transfer_data(n & 0xFF).service_data.parameter_records
        if n == 1:
            assert ecu.client.transfer_data(1).service_data.parameter_records == read  # a repeat
    assert ecu.raw(bytes([0x36, (blocks + 1) & 0xFF])) == b"\x7f\x36\x24"  # nothing left
    ecu.client.request_transfer_exit()
    assert read == image

    # A session change ends a transfer.
    ecu.client.request_upload(location(DOWNLOAD_ADDRESS, 16))
    ecu.enter(PROGRAMMING)
    assert nrc(ecu.client.transfer_data, 1) == 0x24


@pytest.mark.parametrize("kind", [ECUReset.ResetType.hardReset, ECUReset.ResetType.keyOffOnReset, ECUReset.ResetType.softReset], ids=["hard", "key off-on", "soft"])
def test_ecu_reset_restores_power_on_state(ecu, kind):
    ecu.enter(EXTENDED)
    ecu.unlock(LEVEL_EXTENDED)
    ecu.client.write_data_by_identifier(SETPOINT, 12.0)
    ecu.client.write_data_by_identifier(VIN, "WZL0000000TESTVIN")
    reset(ecu, kind)
    assert ecu.session() == DEFAULT
    assert ecu.read(SETPOINT) == SETPOINT_V
    assert ecu.read(VIN) == IDENTIFICATION[VIN]
    ecu.enter(EXTENDED)
    assert nrc(ecu.client.request_seed, LEVEL_EXTENDED) == 0x37  # the power-up delay
