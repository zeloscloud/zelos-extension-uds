"""`read-mem`, `write-mem`, `upload`: ReadMemoryByAddress, WriteMemoryByAddress, upload."""

import rich_click as click

from .. import services
from ..utils import ENDIANNESS_BIG, ENDIANNESS_CHOICES, PAYLOAD_TYPE_CHOICES, PAYLOAD_TYPE_HEX
from .utils import command


@click.command("read-mem")
@click.option("--address", required=True, help="Memory address in hex")
@click.option("--size", required=True, help="Bytes to read")
@command
def read_mem(ecu, address: str, size: str) -> dict:
    """Read memory (0x23).

    \b
    Example:
        main.py read-mem --txid 7E0 --rxid 7E8 --address 20000000 --size 4
    """
    return services.read_memory(ecu, address, size)


@click.command("write-mem")
@click.option("--address", required=True, help="Memory address in hex")
@click.option("--data", required=True, help="Data to write, read as --type")
@click.option(
    "--type", "data_type", type=click.Choice(PAYLOAD_TYPE_CHOICES, case_sensitive=False),
    default=PAYLOAD_TYPE_HEX, show_default=True,
)  # fmt: skip
@click.option(
    "--endian", "endianness", type=click.Choice(ENDIANNESS_CHOICES, case_sensitive=False),
    default=ENDIANNESS_BIG, show_default=True,
)  # fmt: skip
@command
def write_mem(ecu, address: str, data: str, data_type: str, endianness: str) -> dict:
    """Write memory (0x3D).

    \b
    Example:
        main.py write-mem --txid 7E0 --rxid 7E8 --address 20000000 --data 01020304
    """
    return services.write_memory(ecu, address, data, data_type.lower(), endianness.lower())


@click.command()
@click.option("--address", required=True, help="Memory address in hex")
@click.option("--size", required=True, help="Bytes to upload")
@click.option("--out", "file_path", default="", help="Write to this file; else print hex")
@command
def upload(ecu, address: str, size: str, file_path: str) -> dict:
    """Upload memory: RequestUpload (0x35), TransferData, RequestTransferExit.

    \b
    Example:
        main.py upload --txid 7E0 --rxid 7E8 --address 08000000 --size 65536 --out fw.bin
    """
    return services.upload_memory(ecu, address, size, file_path)
