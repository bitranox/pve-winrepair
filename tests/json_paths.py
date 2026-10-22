"""Typed reads of a parsed JSON envelope, so tests index into it without type suppressions.

``json.loads`` returns ``Any``; narrowing a nested value with ``isinstance`` still leaves its
members unknown to a strict checker. These helpers walk a path with runtime checks and hand back
``object`` (or a ``dict[str, object]`` / ``list[object]``), which an assertion can compare.
"""

from __future__ import annotations

from typing import cast

__all__ = ["at", "items", "obj"]


def obj(value: object) -> dict[str, object]:
    """``value`` as a JSON object; fails the test when it is not one."""
    assert isinstance(value, dict), f"not a JSON object: {value!r}"
    return cast("dict[str, object]", value)


def at(value: object, *path: str | int) -> object:
    """The value at ``path`` (object keys and list indices); fails the test on a wrong shape."""
    for step in path:
        if isinstance(step, int):
            assert isinstance(value, list), f"not a JSON list at {step!r}: {value!r}"
            value = cast("list[object]", value)[step]
        else:
            value = obj(value)[step]
    return value


def items(value: object, *path: str | int) -> list[object]:
    """The JSON list at ``path``; fails the test when it is not a list."""
    found = at(value, *path)
    assert isinstance(found, list), f"not a JSON list: {found!r}"
    return cast("list[object]", found)
