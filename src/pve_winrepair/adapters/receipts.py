"""Repair receipts as files in the node's state directory, one per VM: ``<state_dir>/receipt-<vmid>.json``.

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

from pve_winrepair.domain.receipt import ReceiptError, RepairReceipt

if TYPE_CHECKING:
    from pve_winrepair.application.ports import ReceiptStore

__all__ = ["FileReceiptStore", "ReceiptError"]

_DIR_MODE = 0o700


def _reasons(error: ValidationError) -> str:
    """One ``<field>: <reason>`` per problem, never the rejected value or the library's own rendering."""
    return "; ".join(
        f"{'.'.join(str(part) for part in detail['loc']) or '<document>'}: {detail['msg']}" for detail in error.errors()
    )


def _cause(error: OSError | UnicodeDecodeError) -> str:
    """The OS reason (``strerror``), or the exception's text when it carries none."""
    return (error.strerror if isinstance(error, OSError) else None) or str(error)


class FileReceiptStore:
    """The repair receipts of one node, as JSON files in ``state_dir``."""

    def __init__(self, state_dir: Path) -> None:
        """Keep receipts in ``state_dir`` (created 0700 on the first write when absent)."""
        self._state_dir = state_dir

    def path(self, vmid: int) -> Path:
        """Where the receipt of ``vmid`` is kept."""
        return self._state_dir / f"receipt-{vmid}.json"

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
            receipt = RepairReceipt.model_validate_json(text)
        except ValidationError as exc:
            raise ReceiptError(f"the repair receipt {path} is not valid: {_reasons(exc)}") from None
        if receipt.vmid != vmid:
            # A file copied or renamed from another VM's receipt: its build is not this VM's.
            raise ReceiptError(f"the repair receipt {path} is for VM {receipt.vmid}, not VM {vmid}")
        return receipt

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

    def _ensure_dir(self) -> None:
        """Create the state directory 0700 when it is absent; an existing one keeps its mode."""
        if self._state_dir.is_dir():
            return
        # Created 0700 so it is never wider, then set exactly: mkdir's mode passes through the umask.
        self._state_dir.mkdir(mode=_DIR_MODE, parents=True)
        self._state_dir.chmod(_DIR_MODE)

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
