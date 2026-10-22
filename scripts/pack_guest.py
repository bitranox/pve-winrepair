#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["pwshpy==1.5.0"]
# ///
"""Pack the guest tool into the node package's committed artefact, or check that it is fresh.

The guest tool is the package ``src/pve_winrepair_guest`` with the entry script
``winrepair_guest.py``. ``pwshpy pack`` turns it into one self-contained ``.ps1`` (a PowerShell
wrapper around a base64 zip of the sources), which the node CLI ships as package data and copies to
a guest. The artefact is committed, so the wheel never needs pwshpy to build.

    uv run --script scripts/pack_guest.py            # repack into the artefact
    uv run --script scripts/pack_guest.py --check    # exit 1 when the artefact is stale

``--check`` compares DECODED members plus the wrapper text, not raw bytes: the pack is
byte-deterministic on one host, but the compressed payload depends on the zlib build (Python on
Windows ships zlib-ng), so two hosts can pack identical code into different bytes.

Exit codes: 0 packed / up to date, 1 ``--check`` found a stale artefact, 2 error (pwshpy missing,
pack failed, unreadable artefact). An error never exits 1, so a caller cannot read it as drift.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import re
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "ARTEFACT",
    "ENTRY",
    "PROJECT",
    "PackError",
    "decode_payload",
    "main",
    "pack",
    "same_pack",
    "wrapper_without_payload",
]

PROJECT = Path(__file__).resolve().parents[1]
ENTRY = Path("src/pve_winrepair_guest/winrepair_guest.py")
ARTEFACT = Path("src/pve_winrepair/adapters/guest_tool/winrepair_guest.ps1")

# pwshpy's runner layout: a here-string holding the base64 zip, and the sha256 of the zip bytes.
_PAYLOAD = re.compile(r"^\$PwshPyPayload = @'\r?\n(.*?)^'@", re.S | re.M)
_SHA = re.compile(r"^\$PwshPySha = '([0-9a-f]{64})'", re.M)
_SHA_LINE = re.compile(r"^\$PwshPySha = '[0-9a-f]{64}'\r?\n?", re.M)


class PackError(Exception):
    """The pack cannot be made: pwshpy is missing, or packing or writing failed."""


def pack(project: Path, dest: Path) -> None:
    """Pack ``project``'s guest tool into ``dest``, replacing it atomically.

    The pack is written beside ``dest`` first and moved over it only when complete, so a failed pack
    leaves the previous artefact and no partial file.

    Args:
        project: A project root holding :data:`ENTRY`.
        dest: Where the packed ``.ps1`` goes; its directory must exist.

    Raises:
        PackError: pwshpy is not importable, or the pack or the write failed.
    """
    try:
        from pwshpy import PackOptions, PwshPyError, RunnerFormat, ps  # noqa: PLC0415 - optional dependency: --check must report a missing pwshpy as exit 2
    except ImportError as exc:
        msg = f"pwshpy is not importable ({exc}); run: uv run --script scripts/pack_guest.py"
        raise PackError(msg) from exc
    tmp = dest.with_name(dest.name + ".tmp")
    # The pack root is src, so members are named pve_winrepair_guest/<module>.py and the absolute
    # intra-guest imports resolve on the guest. PS1 is explicit: AUTO would pick by the temp name.
    options = PackOptions(root=project / "src", force=True, format=RunnerFormat.PS1)
    try:
        ps.pack_script(project / ENTRY, tmp, options=options)
        tmp.replace(dest)
    except (PwshPyError, OSError) as exc:
        tmp.unlink(missing_ok=True)
        raise PackError(f"pack failed: {exc}") from exc


def decode_payload(text: str) -> dict[str, bytes]:
    """The members of a packed ``.ps1``'s payload, after checking its sha256.

    Args:
        text: The packed script, decoded from UTF-8 bytes (never read in text mode, which folds CRLF).

    Returns:
        Each archive member name mapped to its bytes.

    Raises:
        ValueError: There is not exactly one payload and one sha line, the base64 is malformed,
            the sha256 of the payload does not match ``$PwshPySha``, or opening or reading the
            archive raised anything at all (not a zip, an encrypted member, a bad CRC). The message
            names the reason only, never the text or a member name, and carries no chained exception.
    """
    # pytest's long traceback prints a shown frame's arguments (and with -l its locals): ``text`` is
    # the whole artefact, cut to head and tail, so a refused block at its end would land in a test
    # log. The frame is hidden and every refusal raised "from None", which drops the chained frame.
    __tracebackhide__ = True
    # Exactly one of each: wrapper_without_payload strips EVERY block, so a second block decoded by
    # nobody would escape both the freshness check and the privacy scan of the decoded members.
    blobs = list(_PAYLOAD.finditer(text))
    shas = list(_SHA.finditer(text))
    if not blobs or not shas:
        raise ValueError("no pwshpy payload or $PwshPySha line found")
    if len(blobs) != 1 or len(shas) != 1:
        raise ValueError(
            f"expected exactly one pwshpy payload and one $PwshPySha line, found {len(blobs)} and {len(shas)}"
        )
    blob, sha = blobs[0], shas[0]
    try:
        raw = base64.b64decode("".join(blob.group(1).split()), validate=True)
    except binascii.Error as exc:
        raise ValueError(f"the payload is not base64: {exc}") from None
    if hashlib.sha256(raw).hexdigest() != sha.group(1):
        raise ValueError("the payload's sha256 does not match $PwshPySha")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            return {name: archive.read(name) for name in archive.namelist()}
    except Exception:
        # Any exception, not only BadZipFile: an encrypted member raises RuntimeError, an unknown
        # method NotImplementedError, corrupt data zlib.error or EOFError. zipfile's messages name the
        # member ("Bad CRC-32 for file %r") and a name can hold a token, so the message is fixed and
        # the chain is dropped: zipfile's own frames, unhidden, would print the name as an argument.
        raise ValueError("the payload is not a readable zip archive") from None


def wrapper_without_payload(text: str) -> str:
    """The packed script with the payload here-string and the ``$PwshPySha`` line removed.

    Args:
        text: The packed script.

    Returns:
        The wrapper code, which a change of the packed sources does not alter.
    """
    return _SHA_LINE.sub("", _PAYLOAD.sub("", text))


def same_pack(a: str, b: str) -> bool:
    """Whether two packed scripts carry the same members, byte for byte, and the same wrapper.

    Args:
        a: One packed script.
        b: The other.

    Returns:
        True when both decode to equal members and equal wrappers; False otherwise, including when
        either does not decode.
    """
    __tracebackhide__ = True  # ``a`` and ``b`` are whole artefacts: see decode_payload
    try:
        members_a, members_b = decode_payload(a), decode_payload(b)
    except ValueError:
        return False
    return members_a == members_b and wrapper_without_payload(a) == wrapper_without_payload(b)


def _say(stream: str, line: str) -> None:
    target = sys.stdout if stream == "out" else sys.stderr
    target.write(line + "\n")


def _write(project: Path) -> int:
    dest = project / ARTEFACT
    pack(project, dest)
    digest = hashlib.sha256(dest.read_bytes()).hexdigest()
    _say("out", f"packed {ARTEFACT.as_posix()} sha256={digest}")
    return 0


def _check(project: Path) -> int:
    with tempfile.TemporaryDirectory(prefix="pack-guest-") as workdir:
        fresh = Path(workdir) / ARTEFACT.name
        pack(project, fresh)
        fresh_text = fresh.read_bytes().decode("utf-8")
    try:
        committed = (project / ARTEFACT).read_bytes()
    except FileNotFoundError:
        _say("err", f"{ARTEFACT.as_posix()} is stale: it does not exist")
        return 1
    try:
        fresh_pack = same_pack(committed.decode("utf-8"), fresh_text)
    except UnicodeDecodeError:
        fresh_pack = False
    if not fresh_pack:
        _say("err", f"{ARTEFACT.as_posix()} is stale: it differs from a fresh pack of {ENTRY.as_posix()}")
        return 1
    _say("out", f"{ARTEFACT.as_posix()}: up to date")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Pack the guest tool into the node package's artefact.")
    parser.add_argument("--check", action="store_true", help="Exit 1 when the artefact is stale; write nothing.")
    return parser


def main(argv: Sequence[str] | None = None, *, project: Path = PROJECT) -> int:
    """Pack the artefact, or with ``--check`` report whether it is fresh.

    Args:
        argv: Command line arguments (default: ``sys.argv[1:]``).
        project: The project root (default: the checkout holding this script).

    Returns:
        0 packed or up to date, 1 ``--check`` found a stale artefact, 2 error.
    """
    args = _parser().parse_args(argv)
    try:
        return _check(project) if args.check else _write(project)
    except (PackError, OSError) as exc:
        # One line, no traceback: a multi-line compiler message would read as several errors.
        _say("err", " ".join(str(exc).split()))
        return 2


if __name__ == "__main__":
    sys.exit(main())
