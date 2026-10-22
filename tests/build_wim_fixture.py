r"""Build the small WIM fixture from a real ``install.wim`` (stdlib only, Python >= 3.10).

The fixture is the real 208-byte MSWIM header followed by the real XML resource, with the
header's XML resource offset rewritten to 208 so it points into the small file. Every other
header field (resource sizes, the lookup-table and boot-metadata offsets) is copied unchanged;
those point past the end of the fixture, which the reader never follows.

Reproduce the committed fixture read-only on the node that holds the media (the script is
streamed over stdin, so nothing is copied to or written on the node):

    ssh root@<node> python3 - <media dir>/sources/install.wim \
        < tests/build_wim_fixture.py > tests/fixtures/install_wim_header_xml.bin

The committed fixture then has its image NAME replaced by a same-length generic one.

Why not commit the real file: it is ~10 GB; the header and XML are all the reader looks at.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

__all__ = ["assemble", "extract"]

HEADER_SIZE = 208
# rhXmlData is a RESHDR_DISK_SHORT at byte 72: 7-byte size + 1 flag byte, then a u64 offset.
XML_RESHDR = 72
XML_OFFSET_FIELD = XML_RESHDR + 8


def extract(wim: Path) -> tuple[bytes, bytes]:
    """Return the header bytes and the XML resource bytes of a real WIM.

    Args:
        wim: Path to an MSWIM image.

    Returns:
        The 208 header bytes and the XML resource's raw bytes.
    """
    with wim.open("rb") as handle:
        header = handle.read(HEADER_SIZE)
        size = int.from_bytes(header[XML_RESHDR : XML_RESHDR + 7], "little")
        (offset,) = struct.unpack_from("<Q", header, XML_OFFSET_FIELD)
        handle.seek(offset)
        return header, handle.read(size)


def assemble(header: bytes, xml: bytes) -> bytes:
    """Concatenate header and XML, pointing the XML offset at the byte after the header.

    Args:
        header: The real 208-byte WIM header.
        xml: The real XML resource bytes.

    Returns:
        The fixture bytes.
    """
    patched = bytearray(header)
    struct.pack_into("<Q", patched, XML_OFFSET_FIELD, len(header))
    return bytes(patched) + xml


def main(argv: list[str]) -> int:
    """Write the fixture for ``argv[0]`` to stdout."""
    header, xml = extract(Path(argv[0]))
    sys.stdout.buffer.write(assemble(header, xml))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
