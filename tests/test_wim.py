"""Tests for the pure WIM reader.

The fixture ``fixtures/install_wim_header_xml.bin`` is the real 208-byte header plus the real
2378-byte XML resource of a Windows 11 Pro 25H2 (de-DE, 26200.8973) ``sources/install.wim``,
with only the XML offset field (bytes 80-87) rewritten to 208 so it points into the small file,
and the image NAME replaced by a same-length generic one. It was produced read-only by
streaming ``tests/build_wim_fixture.py`` to the node's python3 (the exact command is in that
script's docstring); the other header fields still describe the 10 GB original, which is why
the lookup-table offset points far past the end of the fixture.
"""

from __future__ import annotations

import codecs
import struct
from pathlib import Path

import pytest

from pve_winrepair_guest import wim

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "install_wim_header_xml.bin"
XML_SIZE_FIELD = 72
XML_OFFSET_FIELD = 80


def _write(tmp_path: Path, data: bytes) -> Path:
    target = tmp_path / "image.wim"
    target.write_bytes(data)
    return target


def _patched(offset: int, chunk: bytes) -> bytes:
    """Return the fixture with ``chunk`` written over it at ``offset``."""
    data = bytearray(FIXTURE.read_bytes())
    data[offset : offset + len(chunk)] = chunk
    return bytes(data)


def _with_xml(text: str) -> bytes:
    """Return the real header followed by ``text`` as a UTF-16LE XML resource with a BOM."""
    xml = codecs.BOM_UTF16_LE + text.encode("utf-16-le")
    header = bytearray(FIXTURE.read_bytes()[:208])
    header[XML_SIZE_FIELD : XML_SIZE_FIELD + 7] = len(xml).to_bytes(7, "little")
    return bytes(header) + xml


def test_reads_the_real_media_build_spbuild_and_language() -> None:
    info = wim.read(FIXTURE)

    assert len(info.images) == 1
    image = info.images[0]
    assert (image.index, image.build, image.spbuild) == (1, 26200, 8973)
    assert image.languages == ("de-DE",)
    assert image.default_language == "de-DE"
    assert image.name == "Windows-Image-0001"
    assert image.edition == "Professional"


def test_header_shorter_than_208_bytes_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, FIXTURE.read_bytes()[:100])

    with pytest.raises(wim.WimFormatError, match="header"):
        wim.read(path)


def test_bad_magic_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, _patched(0, b"NOTAWIM\0"))

    with pytest.raises(wim.WimFormatError, match="magic"):
        wim.read(path)


def test_header_size_field_below_208_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, _patched(8, struct.pack("<I", 100)))

    with pytest.raises(wim.WimFormatError, match="header size"):
        wim.read(path)


def test_truncated_xml_resource_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, FIXTURE.read_bytes()[:-500])

    with pytest.raises(wim.WimFormatError, match="runs past the end"):
        wim.read(path)


def test_xml_offset_past_eof_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, _patched(XML_OFFSET_FIELD, struct.pack("<Q", 10_468_125_531)))

    with pytest.raises(wim.WimFormatError, match="runs past the end"):
        wim.read(path)


def test_zero_size_xml_resource_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, _patched(XML_SIZE_FIELD, bytes(7)))

    with pytest.raises(wim.WimFormatError, match="empty"):
        wim.read(path)


def test_compressed_xml_resource_raises(tmp_path: Path) -> None:
    # Flag 0x04 is RESHDR_FLAG_COMPRESSED; a valid WIM never compresses its XML resource.
    path = _write(tmp_path, _patched(XML_SIZE_FIELD + 7, b"\x06"))

    with pytest.raises(wim.WimFormatError, match="compressed"):
        wim.read(path)


def test_unparsable_xml_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, _with_xml('<WIM><IMAGE INDEX="1">'))

    with pytest.raises(wim.WimFormatError, match="XML"):
        wim.read(path)


# The reader parses with stdlib expat instead of defusedxml; these two pin the protection that
# choice rests on, on every interpreter CI runs (expat 2.4 and later).
def test_an_entity_bomb_is_refused_by_expat_s_amplification_limit(tmp_path: Path) -> None:
    levels = "".join(f'<!ENTITY {chr(98 + i)} "{("&" + chr(97 + i) + ";") * 10}">' for i in range(8))
    bomb = f'<?xml version="1.0"?><!DOCTYPE WIM [<!ENTITY a "aaaaaaaaaa">{levels}]><WIM>&i;</WIM>'
    path = _write(tmp_path, _with_xml(bomb))  # a few hundred characters that would expand to 10**9

    with pytest.raises(wim.WimFormatError, match="amplification"):
        wim.read(path)


def test_an_external_entity_is_never_fetched(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("<IMAGE/>", encoding="utf-8")
    document = f'<?xml version="1.0"?><!DOCTYPE WIM [<!ENTITY e SYSTEM "{outside.as_uri()}">]><WIM>&e;</WIM>'
    path = _write(tmp_path, _with_xml(document))

    with pytest.raises(wim.WimFormatError, match="undefined entity"):
        wim.read(path)


def test_xml_that_is_not_utf16_raises(tmp_path: Path) -> None:
    data = bytearray(FIXTURE.read_bytes())
    data[208:] = b"\xff\xfe" + b"\x00\xd8" * ((len(data) - 210) // 2)  # lone surrogates

    with pytest.raises(wim.WimFormatError, match="UTF-16"):
        wim.read(_write(tmp_path, bytes(data)))


def test_image_without_build_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, _with_xml('<WIM><IMAGE INDEX="1"><NAME>x</NAME></IMAGE></WIM>'))

    with pytest.raises(wim.WimFormatError, match="BUILD"):
        wim.read(path)


def test_wim_without_images_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, _with_xml("<WIM><TOTALBYTES>1</TOTALBYTES></WIM>"))

    with pytest.raises(wim.WimFormatError, match="no IMAGE"):
        wim.read(path)


def test_missing_file_raises_oserror_not_format_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        wim.read(tmp_path / "absent.wim")
