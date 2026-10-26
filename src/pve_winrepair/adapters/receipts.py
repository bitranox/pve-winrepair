"""Repair receipts as files in the state directory, one per VM: ``<state_dir>/receipt-<vmid>.json``.

``repair --receipt FILE`` and ``apply --receipt FILE`` name one file instead, used for whichever VM
the run is for; a receipt read from it is still refused when it names another VM, and
:meth:`FileReceiptStore.other_vm` tells a repair which VM's receipt it would remove.

A receipt is written to a temporary file in the same directory and moved over the old one with
``os.replace``, so a reader sees the previous receipt or the new one, never a half-written file. The
file is readable by its owner only (0600) and a directory this store creates is 0700: the receipt
decides which build apply accepts, so nobody else may change it.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import ValidationError

from pve_winrepair.domain.envelope import describe_validation_error
from pve_winrepair.domain.receipt import ReceiptError, RepairReceipt

if TYPE_CHECKING:
    from pve_winrepair.application.ports import ReceiptStore

__all__ = ["FileReceiptStore", "ReceiptError"]

_DIR_MODE = 0o700


def _cause(error: OSError | UnicodeDecodeError) -> str:
    """The OS reason (``strerror``), or the exception's text when it carries none."""
    return (error.strerror if isinstance(error, OSError) else None) or str(error)


class FileReceiptStore:
    """The repair receipts of one node, as JSON files in ``state_dir`` or in the one ``file`` given."""

    def __init__(self, state_dir: Path, file: Path | None = None) -> None:
        """Keep receipts in ``state_dir`` (created 0700 on the first write when absent), or in ``file`` for every VM."""
        self._state_dir = state_dir
        self._file = file

    def path(self, vmid: int) -> Path:
        """Where the receipt of ``vmid`` is kept: ``file`` when one was given (``--receipt``)."""
        return self._file if self._file is not None else self._state_dir / f"receipt-{vmid}.json"

    def write(self, receipt: RepairReceipt) -> Path:
        """Replace the receipt of ``receipt.vmid`` atomically; return its path.

        Raises:
            ReceiptError: The directory or the file could not be created or replaced.
        """
        target = self.path(receipt.vmid)
        try:
            self._ensure_dir()
            self._replace(target, receipt.model_dump_json(indent=2) + "\n")
        except OSError as exc:
            raise ReceiptError(f"cannot write the repair receipt {target}: {_cause(exc)}") from exc
        return target

    def read(self, vmid: int) -> RepairReceipt | None:
        """The receipt of ``vmid``, or None when there is none.

        Raises:
            ReceiptError: The file exists but cannot be read, is not a valid receipt, or names
                another VM.
        """
        path = self.path(vmid)
        receipt = self._load(path)
        if receipt is not None and receipt.vmid != vmid:
            # A file copied or renamed from another VM's receipt: its build is not this VM's.
            raise ReceiptError(f"the repair receipt {path} is for VM {receipt.vmid}, not VM {vmid}")
        return receipt

    def other_vm(self, vmid: int) -> int | None:
        """The VM the receipt file of ``vmid`` names when that is another VM, else None.

        None as well when there is no file or it cannot be read or is not a valid receipt: such a
        file names no VM whose receipt could be lost, and a repair removes it later as before.
        """
        try:
            receipt = self._load(self.path(vmid))
        except ReceiptError:
            return None
        if receipt is None or receipt.vmid == vmid:
            return None
        return receipt.vmid

    def delete(self, vmid: int) -> None:
        """Remove the receipt of ``vmid``; a receipt that does not exist is fine.

        Raises:
            ReceiptError: The receipt exists and could not be removed.
        """
        path = self.path(vmid)
        try:
            path.unlink()
        except (FileNotFoundError, NotADirectoryError):
            return
        except OSError as exc:
            raise ReceiptError(f"cannot remove the repair receipt {path}: {_cause(exc)}") from exc

    @staticmethod
    def _load(path: Path) -> RepairReceipt | None:
        """The receipt in ``path`` whichever VM it names, or None when there is no file.

        Raises:
            ReceiptError: The file exists but cannot be read or is not a valid receipt.
        """
        try:
            text = path.read_text(encoding="utf-8")
        except (FileNotFoundError, NotADirectoryError):
            # NotADirectoryError: a component of the path is a regular file, so no receipt can exist.
            return None
        except (OSError, UnicodeDecodeError) as exc:
            raise ReceiptError(f"cannot read the repair receipt {path}: {_cause(exc)}") from exc
        try:
            # model_validate_json, never datetime.fromisoformat: the writer's trailing "Z" is
            # rejected by fromisoformat before Python 3.11.
            return RepairReceipt.model_validate_json(text)
        except ValidationError as exc:
            problems = describe_validation_error(exc, root="<document>")
            raise ReceiptError(f"the repair receipt {path} is not valid: {problems}") from exc

    def _ensure_dir(self) -> None:
        """Create the directory that holds the receipts 0700 when it is absent; an existing one keeps its mode.

        That is the state directory, or the receipt file's own directory when a file was given.
        """
        directory = self._state_dir if self._file is None else self._file.parent
        if directory.is_dir():
            return
        # Created 0700 so it is never wider, then set exactly: mkdir's mode passes through the umask.
        directory.mkdir(mode=_DIR_MODE, parents=True)
        directory.chmod(_DIR_MODE)

    @staticmethod
    def _replace(target: Path, text: str) -> None:
        """Write ``text`` to a 0600 temporary file beside ``target``, then move it over ``target``."""
        # mkstemp creates the file 0600 whatever the umask, so the receipt is never readable by others.
        handle, temporary = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            # Path.replace is os.replace: atomic within one directory, so a reader never sees half a file.
            Path(temporary).replace(target)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise


if TYPE_CHECKING:
    _assert_file_receipt_store: ReceiptStore = FileReceiptStore(Path())
