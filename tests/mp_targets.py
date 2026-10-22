"""Module-level targets for the real ``multiprocessing`` tests of ``wu.run_bounded``.

They live in their own importable module because a spawned child imports its target by
module name; a function defined inside a test file's test body could not be found there.
"""

from __future__ import annotations

import os
import time


def answer(value: int) -> dict[str, int]:
    """Return a value the parent can receive."""
    return {"value": value}


def sleep_forever() -> None:
    """Never return on its own; only a kill ends it (the hung COM search's stand-in)."""
    while True:
        time.sleep(1)


def raise_error() -> None:
    """Raise inside the child (the COM search's HRESULT failure)."""
    raise RuntimeError("0x8024402c search failed")


def die_hard() -> None:
    """End the child without sending anything (a crash in native code)."""
    os._exit(7)
