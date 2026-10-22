"""Pure reader for the image metadata of a Windows Imaging (WIM) file.

Replaces ``Get-WindowsImage`` for the one question the repair asks of its media: which build,
servicing build (UBR) and language does each image carry. pwshpy has no Get-WindowsImage verb,
and the DISM cmdlets need a .NET runtime the guests do not have.

Only two structures are read, both documented in Microsoft's WIM format specification
(WIMHEADER_V1_PACKED and RESHDR_DISK_SHORT): the fixed 208-byte header at offset 0, and the XML
metadata resource it points to (an uncompressed UTF-16 document, normally at the end of the
file). Nothing else in the multi-GB file is touched.

Contents:
    * :func:`read` - parse a WIM file's header and XML into :class:`WimInfo`.
    * :class:`WimInfo`, :class:`WimImage` - the parsed metadata.
    * :class:`WimFormatError` - the file is not a readable WIM.
"""

from __future__ import annotations

import os
import re
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

__all__ = ["WimFormatError", "WimImage", "WimInfo", "read"]

MAGIC = b"MSWIM\0\0\0"
HEADER_SIZE = 208
_XML_RESHDR = 72
_FLAG_COMPRESSED = 0x04
# The real XML is a few KB per image. A cap keeps a corrupt size field from allocating GBs.
_MAX_XML_BYTES = 16 * 1024 * 1024
_DECIMAL = re.compile(r"[0-9]{1,10}")


class WimFormatError(ValueError):
    """The file is not a WIM this reader can trust (bad magic, short read, broken XML)."""


@dataclass(frozen=True)
class WimImage:
    """One image inside a WIM, as described by its XML metadata.

    Attributes:
        index: The image's 1-based INDEX attribute.
        name: The NAME element, or "" when absent.
        edition: WINDOWS/EDITIONID, or "" when absent.
        build: WINDOWS/VERSION/BUILD (e.g. 26200).
        spbuild: WINDOWS/VERSION/SPBUILD, the servicing build compared against a guest's UBR.
        languages: Every WINDOWS/LANGUAGES/LANGUAGE, in document order.
        default_language: WINDOWS/LANGUAGES/DEFAULT, or "" when absent.
    """

    index: int
    name: str
    edition: str
    build: int
    spbuild: int
    languages: tuple[str, ...]
    default_language: str


@dataclass(frozen=True)
class WimInfo:
    """The parsed metadata of a whole WIM file.

    Attributes:
        images: Every IMAGE element, in document order.
    """

    images: tuple[WimImage, ...]


@dataclass(frozen=True)
class _Resource:
    size: int
    flags: int
    offset: int


def read(path: str | os.PathLike[str]) -> WimInfo:
    """Read the image metadata of the WIM at ``path``.

    Args:
        path: The WIM file.

    Returns:
        The parsed metadata.

    Raises:
        WimFormatError: The header or the XML resource is malformed or truncated.
        OSError: The file cannot be opened or read (missing, locked, unreadable).

    Example:
        >>> read("missing.wim")  # doctest: +SKIP
    """
    with Path(path).open("rb") as handle:
        file_size = os.fstat(handle.fileno()).st_size
        resource = _parse_header(handle.read(HEADER_SIZE))
        raw = _read_resource(handle, resource, file_size)
    return _parse_xml(_decode(raw))


def _parse_header(header: bytes) -> _Resource:
    """Validate the fixed header and return the XML resource's location."""
    if len(header) < HEADER_SIZE:
        raise WimFormatError(f"header is {len(header)} bytes, a WIM header is {HEADER_SIZE}")
    if header[:8] != MAGIC:
        raise WimFormatError(f"bad magic {header[:8]!r}, expected {MAGIC!r}")
    (declared,) = struct.unpack_from("<I", header, 8)
    if declared < HEADER_SIZE:
        raise WimFormatError(f"header size field says {declared}, below the {HEADER_SIZE} minimum")
    size = int.from_bytes(header[_XML_RESHDR : _XML_RESHDR + 7], "little")
    (offset,) = struct.unpack_from("<Q", header, _XML_RESHDR + 8)
    return _Resource(size=size, flags=header[_XML_RESHDR + 7], offset=offset)


def _read_resource(handle: BinaryIO, resource: _Resource, file_size: int) -> bytes:
    """Read the XML resource after checking it lies inside the file."""
    if resource.size == 0:
        raise WimFormatError("the XML resource is empty")
    if resource.flags & _FLAG_COMPRESSED:
        raise WimFormatError("the XML resource is flagged compressed, which this reader cannot read")
    if resource.size > _MAX_XML_BYTES:
        raise WimFormatError(f"the XML resource claims {resource.size} bytes, over the sanity cap")
    if resource.offset + resource.size > file_size:
        raise WimFormatError(
            f"the XML resource ({resource.size} bytes at {resource.offset}) runs past the end "
            f"of the {file_size}-byte file - truncated or corrupt"
        )
    handle.seek(resource.offset)
    raw = handle.read(resource.size)
    if len(raw) != resource.size:
        raise WimFormatError(f"short read: {len(raw)} of {resource.size} XML bytes (the file changed while reading)")
    return raw


def _decode(raw: bytes) -> str:
    """Decode the UTF-16 XML (BOM-led in every WIM measured), refusing invalid code units."""
    try:
        return raw.decode("utf-16")
    except UnicodeDecodeError as exc:
        raise WimFormatError(f"the XML resource is not valid UTF-16: {exc}") from exc


def _parse_xml(text: str) -> WimInfo:
    """Parse the XML document into :class:`WimInfo`."""
    # stdlib expat, not defusedxml: the media is our own downloaded Microsoft image, expat never
    # fetches external entities, and the size cap above bounds what an entity bomb could expand.
    try:
        root = ET.fromstring(text)  # noqa: S314 - defusedxml would be a new guest dependency, see above
    except ET.ParseError as exc:
        raise WimFormatError(f"the XML resource does not parse: {exc}") from exc
    images = tuple(_parse_image(node) for node in root.findall("IMAGE"))
    if not images:
        raise WimFormatError("the XML resource lists no IMAGE")
    return WimInfo(images=images)


def _parse_image(node: ET.Element) -> WimImage:
    """Parse one IMAGE element; BUILD and SPBUILD are required, everything else optional."""
    return WimImage(
        index=_int(node.get("INDEX"), "IMAGE/@INDEX"),
        name=node.findtext("NAME", default="").strip(),
        edition=node.findtext("WINDOWS/EDITIONID", default="").strip(),
        build=_int(node.findtext("WINDOWS/VERSION/BUILD"), "WINDOWS/VERSION/BUILD"),
        spbuild=_int(node.findtext("WINDOWS/VERSION/SPBUILD"), "WINDOWS/VERSION/SPBUILD"),
        languages=tuple((lang.text or "").strip() for lang in node.findall("WINDOWS/LANGUAGES/LANGUAGE")),
        default_language=node.findtext("WINDOWS/LANGUAGES/DEFAULT", default="").strip(),
    )


def _int(text: str | None, where: str) -> int:
    """Parse a required decimal field, naming it when it is missing or not a number."""
    value = (text or "").strip()
    # ASCII digits only: int() alone would also accept non-ASCII digits and an underscore.
    if not _DECIMAL.fullmatch(value):
        raise WimFormatError(f"{where} is missing or not a number: {text!r}")
    return int(value)
