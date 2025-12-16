"""Shared UDS operations for CLI commands."""

import logging
from typing import Any

import can
from udsoncan.client import Client
from udsoncan.connections import PythonIsoTpConnection
from udsoncan.exceptions import NegativeResponseException, TimeoutException
from udsoncan.services import ECUReset, InputOutputControlByIdentifier, RoutineControl

from ..extension import HexDidCodec
from ..utils import format_hex_id, format_hex_string

logger = logging.getLogger(__name__)


def create_uds_client(
    tx_id: int,
    rx_id: int,
    interface: str = "socketcan",
    channel: str = "can0",
    bitrate: int | None = None,
    **kwargs: Any,
) -> tuple[can.BusABC, Client]:
    """Create a UDS client connection.

    :param tx_id: Transmit CAN ID (tester to ECU)
    :param rx_id: Receive CAN ID (ECU to tester)
    :param interface: CAN interface type
    :param channel: CAN channel/device
    :param bitrate: CAN bus bitrate (if required by interface)
    :param kwargs: Additional python-can Bus() kwargs
    :return: Tuple of (bus, client)
    """
    # Build CAN bus config
    bus_config = {
        "interface": interface,
        "channel": channel,
    }

    # Add bitrate if provided
    if bitrate is not None:
        bus_config["bitrate"] = bitrate

    # Merge additional kwargs
    bus_config.update(kwargs)

    logger.debug(f"Creating CAN bus with config: {bus_config}")

    # Create CAN bus
    bus = can.Bus(**bus_config)

    # Create ISO-TP connection
    connection = PythonIsoTpConnection(bus, rxid=rx_id, txid=tx_id)

    # Configure UDS client with HexDidCodec as default
    from udsoncan.configs import default_client_config

    config = default_client_config.copy()
    config["data_identifiers"] = {"default": HexDidCodec}
    config["input_output"] = {"default": {"codec": HexDidCodec}}

    # Create UDS client
    client = Client(connection, config=config)

    return bus, client


def read_data_by_identifier(
    tx_id: int,
    rx_id: int,
    did: int,
    interface: str = "socketcan",
    channel: str = "can0",
    bitrate: int | None = None,
) -> dict[str, Any]:
    """Read data by identifier.

    :param tx_id: Transmit CAN ID
    :param rx_id: Receive CAN ID
    :param did: Data Identifier (0x0000-0xFFFF)
    :param interface: CAN interface type
    :param channel: CAN channel
    :param bitrate: CAN bitrate
    :return: Result dictionary
    """
    bus, client = create_uds_client(tx_id, rx_id, interface, channel, bitrate)

    try:
        logger.info(
            f"Reading DID {format_hex_id(did, width=4)} "
            f"(TX: {format_hex_id(tx_id, width=3)}, "
            f"RX: {format_hex_id(rx_id, width=3)})"
        )

        # HexDidCodec is registered as default in client config
        response = client.read_data_by_identifier([did])

        # Extract decoded data from response.service_data.values
        if did in response.service_data.values:
            data = response.service_data.values[did]
            hex_data = format_hex_string(data)

            logger.info(f"Read {len(data)} bytes: {hex_data}")

            return {
                "status": "success",
                "did": format_hex_id(did, width=4),
                "data": hex_data,
                "length": len(data),
            }
        else:
            logger.error(f"DID {format_hex_id(did, width=4)} not in response")
            return {"status": "error", "error": "DID not in response"}

    except NegativeResponseException as e:
        logger.error(f"Negative response: {e.response.code_name} (0x{e.response.code:02X})")
        return {
            "status": "error",
            "error": f"NRC: {e.response.code_name} (0x{e.response.code:02X})",
        }
    except TimeoutException:
        logger.error("Request timeout")
        return {"status": "error", "error": "Timeout"}
    except Exception as e:
        logger.error(f"Error reading DID: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}
    finally:
        client.close()
        bus.shutdown()


def write_data_by_identifier(
    tx_id: int,
    rx_id: int,
    did: int,
    data: bytes,
    interface: str = "socketcan",
    channel: str = "can0",
    bitrate: int | None = None,
) -> dict[str, Any]:
    """Write data by identifier.

    :param tx_id: Transmit CAN ID
    :param rx_id: Receive CAN ID
    :param did: Data Identifier (0x0000-0xFFFF)
    :param data: Data bytes to write
    :param interface: CAN interface type
    :param channel: CAN channel
    :param bitrate: CAN bitrate
    :return: Result dictionary
    """
    bus, client = create_uds_client(tx_id, rx_id, interface, channel, bitrate)

    try:
        logger.info(
            f"Writing DID {format_hex_id(did, width=4)} "
            f"with {len(data)} bytes: {format_hex_string(data)}"
        )

        # HexDidCodec is registered as default in client config
        client.write_data_by_identifier(did, data)

        logger.info("Write successful")

        return {
            "status": "success",
            "did": format_hex_id(did, width=4),
            "data": format_hex_string(data),
            "length": len(data),
        }

    except NegativeResponseException as e:
        logger.error(f"Negative response: {e.response.code_name} (0x{e.response.code:02X})")
        return {
            "status": "error",
            "error": f"NRC: {e.response.code_name} (0x{e.response.code:02X})",
        }
    except TimeoutException:
        logger.error("Request timeout")
        return {"status": "error", "error": "Timeout"}
    except Exception as e:
        logger.error(f"Error writing DID: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}
    finally:
        client.close()
        bus.shutdown()


def ecu_reset(
    tx_id: int,
    rx_id: int | None,
    reset_type: int,
    interface: str = "socketcan",
    channel: str = "can0",
    bitrate: int | None = None,
) -> dict[str, Any]:
    """Perform ECU reset.

    :param tx_id: Transmit CAN ID
    :param rx_id: Receive CAN ID (None if no response required)
    :param reset_type: Reset type (1=hard, 2=key off/on, 3=soft)
    :param interface: CAN interface type
    :param channel: CAN channel
    :param bitrate: CAN bitrate
    :return: Result dictionary
    """
    # If no response required, use functional addressing or suppress response
    if rx_id is None:
        # For no response, we'll use the tx_id as both tx and rx,
        # and the request will be sent but we won't wait for response
        rx_id = tx_id

    bus, client = create_uds_client(tx_id, rx_id, interface, channel, bitrate)

    try:
        reset_names = {
            ECUReset.ResetType.hardReset: "Hard Reset",
            ECUReset.ResetType.keyOffOnReset: "Key Off/On Reset",
            ECUReset.ResetType.softReset: "Soft Reset",
        }

        reset_name = reset_names.get(reset_type, f"Unknown (0x{reset_type:02X})")

        logger.info(
            f"Sending ECU reset: {reset_name} (TX: {format_hex_id(tx_id, width=3)}"
            + (f", RX: {format_hex_id(rx_id, width=3)})" if rx_id != tx_id else ", no response)")
        )

        client.ecu_reset(reset_type)

        logger.info("Reset successful")

        return {
            "status": "success",
            "reset_type": reset_name,
        }

    except NegativeResponseException as e:
        logger.error(f"Negative response: {e.response.code_name} (0x{e.response.code:02X})")
        return {
            "status": "error",
            "error": f"NRC: {e.response.code_name} (0x{e.response.code:02X})",
        }
    except TimeoutException:
        logger.error("Request timeout")
        return {"status": "error", "error": "Timeout"}
    except Exception as e:
        logger.error(f"Error performing reset: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}
    finally:
        client.close()
        bus.shutdown()


def routine_control(
    tx_id: int,
    rx_id: int,
    control_type: int,
    routine_id: int,
    data: bytes | None,
    interface: str = "socketcan",
    channel: str = "can0",
    bitrate: int | None = None,
) -> dict[str, Any]:
    """Control diagnostic routine.

    :param tx_id: Transmit CAN ID
    :param rx_id: Receive CAN ID
    :param control_type: Control type (1=start, 2=stop, 3=request results)
    :param routine_id: Routine identifier (0x0000-0xFFFF)
    :param data: Optional routine data
    :param interface: CAN interface type
    :param channel: CAN channel
    :param bitrate: CAN bitrate
    :return: Result dictionary
    """
    bus, client = create_uds_client(tx_id, rx_id, interface, channel, bitrate)

    try:
        control_names = {
            RoutineControl.ControlType.startRoutine: "Start Routine",
            RoutineControl.ControlType.stopRoutine: "Stop Routine",
            RoutineControl.ControlType.requestRoutineResults: "Request Results",
        }

        control_name = control_names.get(control_type, f"Unknown (0x{control_type:02X})")

        logger.info(
            f"Routine control: {control_name}, ID: {format_hex_id(routine_id, width=4)}"
            + (f", data: {format_hex_string(data)}" if data else "")
        )

        response = client.routine_control(routine_id, control_type, data)

        response_data = format_hex_string(response.data) if response.data else ""

        logger.info(f"Routine control successful, response: {response_data}")

        return {
            "status": "success",
            "control_type": control_name,
            "routine_id": format_hex_id(routine_id, width=4),
            "response_data": response_data,
        }

    except NegativeResponseException as e:
        logger.error(f"Negative response: {e.response.code_name} (0x{e.response.code:02X})")
        return {
            "status": "error",
            "error": f"NRC: {e.response.code_name} (0x{e.response.code:02X})",
        }
    except TimeoutException:
        logger.error("Request timeout")
        return {"status": "error", "error": "Timeout"}
    except Exception as e:
        logger.error(f"Error controlling routine: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}
    finally:
        client.close()
        bus.shutdown()


def input_output_control(
    tx_id: int,
    rx_id: int,
    did: int,
    control_param: int,
    control_option: bytes | None,
    interface: str = "socketcan",
    channel: str = "can0",
    bitrate: int | None = None,
) -> dict[str, Any]:
    """Control input/output by identifier.

    :param tx_id: Transmit CAN ID
    :param rx_id: Receive CAN ID
    :param did: Data Identifier (0x0000-0xFFFF)
    :param control_param: Control parameter value
    :param control_option: Optional control option data
    :param interface: CAN interface type
    :param channel: CAN channel
    :param bitrate: CAN bitrate
    :return: Result dictionary
    """
    bus, client = create_uds_client(tx_id, rx_id, interface, channel, bitrate)

    try:
        control_names = {
            InputOutputControlByIdentifier.ControlParam.returnControlToECU: (
                "Return Control To ECU"
            ),
            InputOutputControlByIdentifier.ControlParam.resetToDefault: ("Reset To Default"),
            InputOutputControlByIdentifier.ControlParam.freezeCurrentState: (
                "Freeze Current State"
            ),
            InputOutputControlByIdentifier.ControlParam.shortTermAdjustment: (
                "Short Term Adjustment"
            ),
        }

        control_name = control_names.get(control_param, f"Unknown (0x{control_param:02X})")

        logger.info(
            f"I/O control: DID {format_hex_id(did, width=4)}, param: {control_name}"
            + (f", option: {format_hex_string(control_option)}" if control_option else "")
        )

        client.io_control(
            did,
            control_param,
            values=list(control_option) if control_option else None,
        )

        logger.info("I/O control successful")

        return {
            "status": "success",
            "did": format_hex_id(did, width=4),
            "control_parameter": control_name,
        }

    except NegativeResponseException as e:
        logger.error(f"Negative response: {e.response.code_name} (0x{e.response.code:02X})")
        return {
            "status": "error",
            "error": f"NRC: {e.response.code_name} (0x{e.response.code:02X})",
        }
    except TimeoutException:
        logger.error("Request timeout")
        return {"status": "error", "error": "Timeout"}
    except Exception as e:
        logger.error(f"Error controlling I/O: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}
    finally:
        client.close()
        bus.shutdown()


def tester_present(
    tx_id: int,
    rx_id: int | None,
    suppress_response: bool,
    interface: str = "socketcan",
    channel: str = "can0",
    bitrate: int | None = None,
) -> dict[str, Any]:
    """Send tester present.

    :param tx_id: Transmit CAN ID
    :param rx_id: Receive CAN ID (None if response suppressed)
    :param suppress_response: Whether to suppress ECU response
    :param interface: CAN interface type
    :param channel: CAN channel
    :param bitrate: CAN bitrate
    :return: Result dictionary
    """
    # If suppressing response, use tx_id for both
    if rx_id is None or suppress_response:
        rx_id = tx_id

    bus, client = create_uds_client(tx_id, rx_id, interface, channel, bitrate)

    try:
        logger.info(
            f"Sending tester present (TX: {format_hex_id(tx_id, width=3)}, "
            f"suppress response: {suppress_response})"
        )

        client.tester_present(suppress_positive_response=suppress_response)

        logger.info("Tester present sent")

        return {
            "status": "success",
            "suppress_response": suppress_response,
        }

    except NegativeResponseException as e:
        logger.error(f"Negative response: {e.response.code_name} (0x{e.response.code:02X})")
        return {
            "status": "error",
            "error": f"NRC: {e.response.code_name} (0x{e.response.code:02X})",
        }
    except TimeoutException:
        if suppress_response:
            # Timeout is expected when suppressing response
            logger.info("Tester present sent (timeout expected with suppressed response)")
            return {
                "status": "success",
                "suppress_response": suppress_response,
            }
        logger.error("Request timeout")
        return {"status": "error", "error": "Timeout"}
    except Exception as e:
        logger.error(f"Error sending tester present: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}
    finally:
        client.close()
        bus.shutdown()


def diagnostic_session_control(
    tx_id: int,
    rx_id: int,
    session_type: int,
    interface: str = "socketcan",
    channel: str = "can0",
    bitrate: int | None = None,
) -> dict[str, Any]:
    """Change diagnostic session.

    :param tx_id: Transmit CAN ID
    :param rx_id: Receive CAN ID
    :param session_type: Session type (1=default, 2=programming, 3=extended, 4=safety)
    :param interface: CAN interface type
    :param channel: CAN channel
    :param bitrate: CAN bitrate
    :return: Result dictionary
    """
    from udsoncan.services import DiagnosticSessionControl

    bus, client = create_uds_client(tx_id, rx_id, interface, channel, bitrate)

    try:
        session_names = {
            DiagnosticSessionControl.Session.defaultSession: "Default Session",
            DiagnosticSessionControl.Session.programmingSession: ("Programming Session"),
            DiagnosticSessionControl.Session.extendedDiagnosticSession: (
                "Extended Diagnostic Session"
            ),
            DiagnosticSessionControl.Session.safetySystemDiagnosticSession: (
                "Safety System Diagnostic Session"
            ),
        }

        session_name = session_names.get(session_type, f"Unknown (0x{session_type:02X})")

        logger.info(f"Changing session to: {session_name}")

        client.change_session(session_type)

        logger.info("Session changed successfully")

        return {
            "status": "success",
            "session_type": session_name,
        }

    except NegativeResponseException as e:
        logger.error(f"Negative response: {e.response.code_name} (0x{e.response.code:02X})")
        return {
            "status": "error",
            "error": f"NRC: {e.response.code_name} (0x{e.response.code:02X})",
        }
    except TimeoutException:
        logger.error("Request timeout")
        return {"status": "error", "error": "Timeout"}
    except Exception as e:
        logger.error(f"Error changing session: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}
    finally:
        client.close()
        bus.shutdown()


def read_dtc_information(
    tx_id: int,
    rx_id: int,
    status_mask: int,
    interface: str = "socketcan",
    channel: str = "can0",
    bitrate: int | None = None,
) -> dict[str, Any]:
    """Read diagnostic trouble codes.

    :param tx_id: Transmit CAN ID
    :param rx_id: Receive CAN ID
    :param status_mask: DTC status mask (0xFF = all)
    :param interface: CAN interface type
    :param channel: CAN channel
    :param bitrate: CAN bitrate
    :return: Result dictionary
    """
    bus, client = create_uds_client(tx_id, rx_id, interface, channel, bitrate)

    try:
        logger.info(f"Reading DTCs with status mask: 0x{status_mask:02X}")

        response = client.get_dtc_by_status_mask(status_mask)

        # Parse DTCs
        dtcs = []
        if hasattr(response, "dtcs") and response.dtcs:
            for dtc in response.dtcs:
                dtc_id = f"0x{dtc.id:06X}" if hasattr(dtc, "id") else "Unknown"
                status = (
                    f"0x{dtc.status.get_byte_as_int():02X}" if hasattr(dtc, "status") else "Unknown"
                )
                dtcs.append(f"{dtc_id} (status: {status})")
                logger.info(f"  DTC: {dtc_id}, Status: {status}")

        logger.info(f"Found {len(dtcs)} DTCs")

        return {
            "status": "success",
            "dtc_count": len(dtcs),
            "dtcs": dtcs,
        }

    except NegativeResponseException as e:
        logger.error(f"Negative response: {e.response.code_name} (0x{e.response.code:02X})")
        return {
            "status": "error",
            "error": f"NRC: {e.response.code_name} (0x{e.response.code:02X})",
        }
    except TimeoutException:
        logger.error("Request timeout")
        return {"status": "error", "error": "Timeout"}
    except Exception as e:
        logger.error(f"Error reading DTCs: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}
    finally:
        client.close()
        bus.shutdown()


def security_access_request_seed(
    tx_id: int,
    rx_id: int,
    level: int,
    interface: str = "socketcan",
    channel: str = "can0",
    bitrate: int | None = None,
) -> dict[str, Any]:
    """Request security seed.

    :param tx_id: Transmit CAN ID
    :param rx_id: Receive CAN ID
    :param level: Security level (odd number: 1, 3, 5, 7...)
    :param interface: CAN interface type
    :param channel: CAN channel
    :param bitrate: CAN bitrate
    :return: Result dictionary with seed
    """
    bus, client = create_uds_client(tx_id, rx_id, interface, channel, bitrate)

    try:
        logger.info(f"Requesting security seed for level {level}")

        response = client.request_seed(level)

        # Extract seed
        seed = (
            format_hex_string(response.service_data.seed)
            if hasattr(response.service_data, "seed")
            else ""
        )

        logger.info(f"Received seed: {seed}")

        return {
            "status": "success",
            "operation": "request_seed",
            "level": level,
            "seed": seed,
        }

    except NegativeResponseException as e:
        logger.error(f"Negative response: {e.response.code_name} (0x{e.response.code:02X})")
        return {
            "status": "error",
            "error": f"NRC: {e.response.code_name} (0x{e.response.code:02X})",
        }
    except TimeoutException:
        logger.error("Request timeout")
        return {"status": "error", "error": "Timeout"}
    except Exception as e:
        logger.error(f"Error requesting seed: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}
    finally:
        client.close()
        bus.shutdown()


def security_access_send_key(
    tx_id: int,
    rx_id: int,
    level: int,
    key: bytes,
    interface: str = "socketcan",
    channel: str = "can0",
    bitrate: int | None = None,
) -> dict[str, Any]:
    """Send security key.

    :param tx_id: Transmit CAN ID
    :param rx_id: Receive CAN ID
    :param level: Security level (even number: 2, 4, 6, 8...)
    :param key: Security key bytes
    :param interface: CAN interface type
    :param channel: CAN channel
    :param bitrate: CAN bitrate
    :return: Result dictionary
    """
    bus, client = create_uds_client(tx_id, rx_id, interface, channel, bitrate)

    try:
        logger.info(f"Sending security key for level {level}")

        client.send_key(level, key)

        logger.info("Security access granted")

        return {
            "status": "success",
            "operation": "send_key",
            "level": level,
            "access_granted": True,
        }

    except NegativeResponseException as e:
        logger.error(f"Negative response: {e.response.code_name} (0x{e.response.code:02X})")
        return {
            "status": "error",
            "error": f"NRC: {e.response.code_name} (0x{e.response.code:02X})",
        }
    except TimeoutException:
        logger.error("Request timeout")
        return {"status": "error", "error": "Timeout"}
    except Exception as e:
        logger.error(f"Error sending key: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}
    finally:
        client.close()
        bus.shutdown()


def clear_diagnostic_information(
    tx_id: int,
    rx_id: int,
    group: int = 0xFFFFFF,
    interface: str = "socketcan",
    channel: str = "can0",
    bitrate: int | None = None,
) -> dict[str, Any]:
    """Clear diagnostic trouble codes.

    :param tx_id: Transmit CAN ID
    :param rx_id: Receive CAN ID
    :param group: DTC group mask (3 bytes, 0xFFFFFF = all DTCs)
    :param interface: CAN interface type
    :param channel: CAN channel/device
    :param bitrate: CAN bitrate
    :return: Result dictionary
    """
    from udsoncan.exceptions import NegativeResponseException, TimeoutException

    bus, client = create_uds_client(tx_id, rx_id, interface, channel, bitrate)

    try:
        logger.info(f"Clearing DTCs for group: 0x{group:06X}")
        client.clear_dtc(group)
        return {"status": "success", "group": f"0x{group:06X}"}
    except NegativeResponseException as e:
        nrc_name = e.response.code_name if hasattr(e.response, "code_name") else "Unknown"
        logger.error(f"Clear DTC NRC: {nrc_name}")
        return {"status": "error", "error": f"NRC: {nrc_name}"}
    except TimeoutException:
        logger.error("Request timeout")
        return {"status": "error", "error": "Timeout"}
    except Exception as e:
        logger.error(f"Error clearing DTCs: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}
    finally:
        client.close()
        bus.shutdown()


def request_download(
    tx_id: int,
    rx_id: int,
    address: int,
    size: int,
    interface: str = "socketcan",
    channel: str = "can0",
    bitrate: int | None = None,
) -> dict[str, Any]:
    """Request download (initiate firmware transfer).

    :param tx_id: Transmit CAN ID
    :param rx_id: Receive CAN ID
    :param address: Memory address to write to
    :param size: Data size in bytes
    :param interface: CAN interface type
    :param channel: CAN channel/device
    :param bitrate: CAN bitrate
    :return: Result dictionary with max_block_size
    """
    from udsoncan.common.MemoryLocation import MemoryLocation
    from udsoncan.exceptions import NegativeResponseException, TimeoutException

    bus, client = create_uds_client(tx_id, rx_id, interface, channel, bitrate)

    try:
        location = MemoryLocation(address=address, memorysize=size, address_format=32)
        logger.info(f"Requesting download: address=0x{address:08X}, size={size}")
        response = client.request_download(location)

        max_length = (
            response.service_data.max_length if hasattr(response.service_data, "max_length") else 0
        )

        return {
            "status": "success",
            "address": f"0x{address:08X}",
            "size": size,
            "max_block_size": max_length,
        }
    except NegativeResponseException as e:
        nrc_name = e.response.code_name if hasattr(e.response, "code_name") else "Unknown"
        logger.error(f"Request download NRC: {nrc_name}")
        return {"status": "error", "error": f"NRC: {nrc_name}"}
    except TimeoutException:
        logger.error("Request timeout")
        return {"status": "error", "error": "Timeout"}
    except Exception as e:
        logger.error(f"Error requesting download: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}
    finally:
        client.close()
        bus.shutdown()


def transfer_data(
    tx_id: int,
    rx_id: int,
    sequence: int,
    data: bytes,
    interface: str = "socketcan",
    channel: str = "can0",
    bitrate: int | None = None,
) -> dict[str, Any]:
    """Transfer data block.

    :param tx_id: Transmit CAN ID
    :param rx_id: Receive CAN ID
    :param sequence: Sequence number (0-255)
    :param data: Data block to transfer
    :param interface: CAN interface type
    :param channel: CAN channel/device
    :param bitrate: CAN bitrate
    :return: Result dictionary
    """
    from udsoncan.exceptions import NegativeResponseException, TimeoutException

    bus, client = create_uds_client(tx_id, rx_id, interface, channel, bitrate)

    try:
        logger.info(f"Transferring data block: sequence={sequence}, size={len(data)}")
        client.transfer_data(sequence, data)
        return {"status": "success", "sequence": sequence, "bytes": len(data)}
    except NegativeResponseException as e:
        nrc_name = e.response.code_name if hasattr(e.response, "code_name") else "Unknown"
        logger.error(f"Transfer data NRC: {nrc_name}")
        return {"status": "error", "error": f"NRC: {nrc_name}"}
    except TimeoutException:
        logger.error("Request timeout")
        return {"status": "error", "error": "Timeout"}
    except Exception as e:
        logger.error(f"Error transferring data: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}
    finally:
        client.close()
        bus.shutdown()


def request_transfer_exit(
    tx_id: int,
    rx_id: int,
    interface: str = "socketcan",
    channel: str = "can0",
    bitrate: int | None = None,
) -> dict[str, Any]:
    """Request transfer exit (finalize firmware transfer).

    :param tx_id: Transmit CAN ID
    :param rx_id: Receive CAN ID
    :param interface: CAN interface type
    :param channel: CAN channel/device
    :param bitrate: CAN bitrate
    :return: Result dictionary
    """
    from udsoncan.exceptions import NegativeResponseException, TimeoutException

    bus, client = create_uds_client(tx_id, rx_id, interface, channel, bitrate)

    try:
        logger.info("Requesting transfer exit")
        client.request_transfer_exit()
        return {"status": "success"}
    except NegativeResponseException as e:
        nrc_name = e.response.code_name if hasattr(e.response, "code_name") else "Unknown"
        logger.error(f"Transfer exit NRC: {nrc_name}")
        return {"status": "error", "error": f"NRC: {nrc_name}"}
    except TimeoutException:
        logger.error("Request timeout")
        return {"status": "error", "error": "Timeout"}
    except Exception as e:
        logger.error(f"Error requesting transfer exit: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}
    finally:
        client.close()
        bus.shutdown()


def flash_firmware(
    tx_id: int,
    rx_id: int,
    firmware_data: bytes,
    base_address: int,
    block_size: int | None = None,
    enable_tp: bool = False,
    enable_security: bool = False,
    security_level: int = 1,
    security_key: bytes | None = None,
    session_type: int = 2,  # programming session
    interface: str = "socketcan",
    channel: str = "can0",
    bitrate: int | None = None,
) -> dict[str, Any]:
    """Flash firmware using a persistent UDS client connection.

    This operation maintains a single client connection throughout the entire
    flash sequence to preserve session state and security access.

    :param tx_id: Transmit CAN ID
    :param rx_id: Receive CAN ID
    :param firmware_data: Firmware bytes to flash
    :param base_address: Memory address to write to
    :param block_size: Block size for transfer (auto-negotiated if None)
    :param enable_tp: Send tester present every 32 blocks
    :param enable_security: Perform security access before flashing
    :param security_level: Security access level (odd number for seed request)
    :param security_key: Security key bytes
    :param session_type: Diagnostic session (1=default, 2=programming, 3=extended)
    :param interface: CAN interface type
    :param channel: CAN channel/device
    :param bitrate: CAN bitrate
    :return: Result dictionary with progress info
    """
    from udsoncan.common.MemoryLocation import MemoryLocation
    from udsoncan.exceptions import NegativeResponseException, TimeoutException

    bus, client = create_uds_client(tx_id, rx_id, interface, channel, bitrate)

    try:
        # Step 1: Change session
        if session_type != 1:
            logger.info(f"Changing to session type {session_type}")
            client.change_session(session_type)

        # Step 2: Security access (if enabled)
        if enable_security:
            if not security_key:
                return {
                    "status": "error",
                    "error": "Security key required when enable_security is True",
                }

            logger.info(f"Requesting security seed (level {security_level})")
            seed_response = client.request_seed(security_level)
            seed = (
                seed_response.service_data.seed
                if hasattr(seed_response.service_data, "seed")
                else b""
            )
            logger.info(f"Received seed: {format_hex_string(seed)}")

            logger.info(f"Sending security key (level {security_level + 1})")
            client.send_key(security_level + 1, security_key)
            logger.info("Security access granted")

        # Step 3: Request download
        location = MemoryLocation(
            address=base_address, memorysize=len(firmware_data), address_format=32
        )
        logger.info(f"Requesting download: address=0x{base_address:08X}, size={len(firmware_data)}")
        download_response = client.request_download(location)

        max_block_size = (
            download_response.service_data.max_length
            if hasattr(download_response.service_data, "max_length")
            else (block_size or 256)
        )
        logger.info(f"Download accepted. Max block size: {max_block_size}")

        # Step 4: Transfer data
        total_blocks = (len(firmware_data) + max_block_size - 1) // max_block_size
        logger.info(f"Transferring {len(firmware_data)} bytes in {total_blocks} blocks")

        sequence = 1
        offset = 0
        while offset < len(firmware_data):
            block = firmware_data[offset : offset + max_block_size]

            # Send tester present every 32 blocks (if enabled)
            if enable_tp and sequence % 32 == 0:
                with client.suppress_positive_response(wait_nrc=False):
                    client.tester_present()

            client.transfer_data(sequence, block)

            sequence = (sequence + 1) % 256  # Wrap at 256
            offset += max_block_size

        logger.info(f"All {total_blocks} blocks transferred")

        # Step 5: Request transfer exit
        logger.info("Requesting transfer exit")
        client.request_transfer_exit()

        return {
            "status": "success",
            "address": f"0x{base_address:08X}",
            "size": len(firmware_data),
            "blocks": total_blocks,
            "block_size": max_block_size,
        }

    except NegativeResponseException as e:
        nrc_name = e.response.code_name if hasattr(e.response, "code_name") else "Unknown"
        logger.error(f"Flash firmware NRC: {nrc_name}")
        return {"status": "error", "error": f"NRC: {nrc_name}"}
    except TimeoutException:
        logger.error("Flash firmware timeout")
        return {"status": "error", "error": "Timeout"}
    except Exception as e:
        logger.error(f"Error flashing firmware: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}
    finally:
        client.close()
        bus.shutdown()
