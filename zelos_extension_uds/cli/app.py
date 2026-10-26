"""App-based configuration mode: every configured ECU, its actions and trace."""

import contextlib
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import zelos_sdk
from zelos_can import isotp as uds_link
from zelos_sdk.extensions import load_config
from zelos_sdk.hooks.logging import TraceLoggingHandler

from .. import ACTION_PREFIX
from .. import actions as uds_actions
from ..client import DoipLink, SharedBus, UdsEcu
from ..constants import (
    DEFAULT_PREFIX,
    INTERFACES,
    LEGACY_INTERFACES,
    LOG_SOURCE_NAME,
    RESERVED_ECU_NAMES,
    Interface,
    demo_ecu,
    name_error,
    trace_layout,
)
from ..keys import load_key_file
from .utils import run_until_stopped, start_all

logger = logging.getLogger(__name__)

#: `advanced` settings and their defaults. One value applies to every ECU.
ADVANCED_DEFAULTS: dict[str, Any] = {
    "prefix": DEFAULT_PREFIX,
    "log_level": "INFO",
    "request_timeout": 5.0,
    "p2_timeout": 1.0,
    "p2_star_timeout": 5.0,
    "isotp_stmin": 0,
    "isotp_blocksize": 0,  # one flow control per message: over a slow link each costs an RTT
    "isotp_padding": 0xCC,  # ISO 15765-4 DLC 8; None: unpadded
    "tester_present_s": None,  # off
    "debug_frames": False,
}

#: 0.1.x top-level keys -> `advanced` keys.
LEGACY_ADVANCED = {
    "log_level": "log_level",
    "request_timeout": "request_timeout",
    "p2_timeout": "p2_timeout",
    "p2_star_timeout": "p2_star_timeout",
    "isotp_stmin": "isotp_stmin",
    "isotp_blocksize": "isotp_blocksize",
    "isotp_tx_padding": "isotp_padding",
}


def migrate_legacy(config: dict[str, Any]) -> dict[str, Any]:
    """A 0.1.x config (one flat ECU, top-level `interface`) as one ECU plus `advanced`."""
    if config.get("ecus") or "interface" not in config:
        return config
    logger.warning("Single-ECU settings from 0.1.x read as one ECU; save the settings to update")
    ecu = {k: config[k] for k in ("channel", "bitrate", "config_json") if k in config}
    ecu["interface"] = LEGACY_INTERFACES.get(config["interface"], config["interface"])
    ecu["tx_id"] = config.get("tx_id", "0x7E0")  # 0.1.x defaults
    ecu["rx_id"] = config.get("rx_id", "0x7E8")
    # 0.1.x took 29-bit ids from `extended_id`, or from an id over 0x7FF.
    ecu["extended_ids"] = bool(config.get("extended_id")) or any(
        _over_11_bits(ecu[k]) for k in ("tx_id", "rx_id")
    )
    advanced = {new: config[old] for old, new in LEGACY_ADVANCED.items() if old in config}
    # A flat config has no user-set `advanced`: any there are schema defaults, so legacy wins.
    return {"ecus": [ecu], "advanced": {**(config.get("advanced") or {}), **advanced}}


def _over_11_bits(text: Any) -> bool:
    try:
        return int(str(text), 16) > 0x7FF
    except ValueError:
        return False  # refused with its reason when the ECU is created


def resolve_advanced(config: dict[str, Any]) -> dict[str, Any]:
    """Merge the `advanced` object over its defaults.

    An absent `prefix` takes the default; a present-but-empty one clears it.
    """
    return {**ADVANCED_DEFAULTS, **(config.get("advanced") or {})}


def _exit_on(error: str | None) -> None:
    """Exit with a one-line reason when `error` is set."""
    if error:
        logger.error("%s", error)
        sys.exit(1)


def _ecu_name(ecu_config: dict[str, Any]) -> str:
    """The configured name, else `demo`, `doip`, or the sanitized remote or local CAN
    channel."""
    name = (ecu_config.get("name") or "").strip()
    if name:
        _exit_on(name_error(name, "ECU Name", RESERVED_ECU_NAMES))
        return name
    if INTERFACES.get(ecu_config.get("interface")) in (Interface.DEMO, Interface.DOIP):
        return str(INTERFACES[ecu_config["interface"]])
    default = next(
        (ecu_config[k] for k in ("remote_channel", "channel") if ecu_config.get(k)), "ecu"
    )
    return zelos_sdk.sanitize_name(str(default), kind="source")


def _interface(name: str, ecu_config: dict[str, Any]) -> Interface:
    value = ecu_config.get("interface")
    if value not in INTERFACES:
        choices = ", ".join(INTERFACES)
        _exit_on(f"ECU '{name}': interface {value!r} is not supported. Choose one of: {choices}")
    return INTERFACES[value]


def create_ecus(config: dict[str, Any], advanced: dict[str, Any]) -> list[UdsEcu]:
    """One UdsEcu per configured ECU. Names must be legal and unique."""
    ecus_config = config.get("ecus") or []
    if not ecus_config:
        _exit_on("No ECUs configured. Add at least one ECU to the 'ecus' array.")
    ecus: list[UdsEcu] = []
    for ecu_config in ecus_config:
        name = _ecu_name(ecu_config)
        if any(e.name == name for e in ecus):
            _exit_on(f"Duplicate ECU name '{name}'. Set Name on one of them.")
        interface = _interface(name, ecu_config)
        link = {k: v for k, v in ecu_config.items() if k not in ("name", "interface", "key_file")}
        try:
            ecu = UdsEcu(name, interface, link, advanced)
        except ValueError as e:
            _exit_on(f"ECU '{name}': {e}")
        key_file = (ecu_config.get("key_file") or "").strip()
        if not key_file and interface == Interface.DEMO:
            key_file = demo_ecu()["key_file"]
        if key_file:
            try:
                ecu.key_fn = load_key_file(key_file)
            except ValueError as e:
                _exit_on(f"ECU '{name}': {e}")
            logger.info("ECU %s: seed/key from %s", name, key_file)
        ecus.append(ecu)
        logger.info("Created ECU %s (%s)", name, ecu.endpoint)
    return ecus


def share_buses(ecus: list[UdsEcu]) -> list[SharedBus]:
    """One bus per (interface, channel). ECUs on one bus must agree on its settings.

    DoIP: a connection per ECU. Two on one entity need their own tester addresses: an
    entity takes one connection per tester address.
    """
    buses: dict[tuple, SharedBus] = {}
    for ecu in ecus:
        if ecu.doip is not None:
            key = ("doip", ecu.doip.host, ecu.doip.port, ecu.doip.tester)
            if key in buses:
                other = buses[key].ecus[0].name
                _exit_on(
                    f"ECUs '{other}' and '{ecu.name}' reach DoIP {ecu.doip.peer} with one tester "
                    f"address (0x{ecu.doip.tester:04X}): give each its own"
                )
            buses[key] = DoipLink(ecu)
            continue
        key = uds_link.bus_key(ecu.bus_link)
        shared = buses.get(key)
        if shared is None:
            shared = buses[key] = SharedBus(ecu.bus_link, uds_link.bus_text(ecu.bus_link))
        else:
            first = shared.ecus[0]
            ours, theirs = uds_link.bus_settings(ecu.bus_link), uds_link.bus_settings(first.link)
            if ours != theirs:
                _exit_on(
                    f"ECUs '{first.name}' and '{ecu.name}' share {shared.name} with different "
                    f"bus settings ({theirs} vs {ours}): make them match"
                )
            # One id, one owner: a response id another ECU also listens or sends on
            # would hand its frames to the wrong ISO-TP stack.
            ours = {(i, ecu.extended) for i in (ecu.tx_id, ecu.rx_id)}
            for other in shared.ecus:
                if ours & {(i, other.extended) for i in (other.tx_id, other.rx_id)}:
                    _exit_on(f"ECUs '{other.name}' and '{ecu.name}' share a CAN id on one bus")
        shared.add(ecu)
    return list(buses.values())


def set_library_logging(debug_frames: bool) -> None:
    """udsoncan, can-isotp and doipclient log every request and frame: on with
    `debug_frames`. Off, udsoncan is silent (the services log each NRC and timeout once),
    can-isotp warns, doipclient (which warns on each alive check it answers) errs."""
    for name, quiet in (("UdsClient", logging.CRITICAL), ("Connection", logging.CRITICAL),
                        ("isotp", logging.WARNING), ("doipclient", logging.ERROR)):  # fmt: skip
        logging.getLogger(name).setLevel(logging.DEBUG if debug_frames else quiet)


def run_app_mode(demo: bool, file: Path | None) -> None:
    """Run the UDS extension in app-based configuration mode.

    :param demo: Add a demo ECU to the configured ones
    :param file: Optional output file for trace recording
    """
    config = migrate_legacy(load_config())
    advanced = resolve_advanced(config)
    prefix = str(advanced.get("prefix") or "").strip()
    _exit_on(name_error(prefix, "Prefix"))

    log_level = advanced["log_level"]
    logging.getLogger().setLevel(getattr(logging, log_level, logging.INFO))
    set_library_logging(bool(advanced["debug_frames"]))
    logger.info("Log level set to: %s", log_level)

    if demo:
        logger.info("Demo mode enabled via --demo flag")
        config["ecus"] = [*(config.get("ecus") or []), demo_ecu()]

    output_file = None
    if file is not None:
        # --file without a value records to a UTC-stamped file.
        if str(file) == ".":
            file = Path(f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.trz")
        output_file = file
        logger.info("Recording trace to: %s", output_file)

    # Register actions BEFORE init: init advertises them to the agent.
    uds_actions.register_actions(zelos_sdk.actions_registry)

    # Log source first, so init below reuses it. Same layout rule as the data:
    # a prefix means one source for every ECU, cleared each ECU owns its own.
    log_source_name, _ = trace_layout(prefix, LOG_SOURCE_NAME)
    global_source = zelos_sdk.init_global_source(log_source_name)
    shared_source = global_source if prefix else None
    if prefix:
        logger.info("Trace prefix: %s", prefix)
    else:
        logger.info("Trace prefix cleared: one trace source per ECU")

    zelos_sdk.init(name=ACTION_PREFIX, log_level="info", actions=True)

    handler = TraceLoggingHandler(global_source)
    handler.setLevel(logging.INFO)
    logging.getLogger().addHandler(handler)

    with contextlib.ExitStack() as stack:
        if output_file:
            stack.enter_context(zelos_sdk.TraceWriter(str(output_file)))

        ecus = create_ecus(config, advanced)
        buses = share_buses(ecus)
        for ecu in ecus:
            ecu.trace_to(prefix, shared_source)
            uds_actions.UDS_ECUS[ecu.name] = ecu
        count = len(ecus)
        logger.info("Starting UDS extension with %d ECU%s", count, "s" if count > 1 else "")
        start_all(ecus, buses, advanced["tester_present_s"])
        run_until_stopped(ecus, buses)
