"""The module reference names both packages, and its settings tables match the models.

``docs/systemdesign/module_reference.md`` is where a reader learns which module does what and which
settings exist. Each settings section has a table under a ``### `[<section>]`  -  `<Model>``` heading;
its rows must name exactly the model's fields, each with the model's default (or, for a default
computed per OS, the public function computing it), so the document cannot drift from the code
without this test going red.
"""

from __future__ import annotations

import re
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

from pve_winrepair.domain import settings as settings_module
from pve_winrepair.domain.settings import GuestSettings, NodeSettings, RepairSettings, SshSettings

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydantic import BaseModel

_MODULE_REFERENCE = Path(__file__).parent.parent / "docs" / "systemdesign" / "module_reference.md"

_SECTION_MODELS: dict[str, type[BaseModel]] = {
    "ssh": SshSettings,
    "guest": GuestSettings,
    "repair": RepairSettings,
    "node": NodeSettings,
}


def _toml_literal(value: object) -> str:
    """The default as the shipped TOML spells it: a tuple is an array, a path or enum a string, None "" (no null)."""
    if isinstance(value, Enum):
        # The member's value, before the str branch: a str-Enum member's f-string is its value on 3.10
        # but "Class.MEMBER" on 3.11+.
        value = value.value
    if value is None:
        return '""'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Path):
        return f'"{value.as_posix()}"'
    if isinstance(value, str):
        return f'"{value}"'
    if isinstance(value, tuple):
        # isinstance narrows to tuple[Unknown, ...]; a settings default holds only literals.
        items = cast("tuple[object, ...]", value)
        return "[" + ", ".join(_toml_literal(item) for item in items) + "]"
    return str(value)


def _table_rows(text: str, section: str, model: type[BaseModel]) -> dict[str, str]:
    """``{field: default}`` from the table under the section's heading, backticks removed."""
    heading = f"### `[{section}]`  -  `{model.__name__}`"
    assert heading in text, f"no heading {heading!r}"
    rows: dict[str, str] = {}
    for line in text.split(heading, 1)[1].splitlines()[1:]:
        if line.startswith("#"):
            break
        cells = [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]
        if len(cells) < 3 or cells[0] in {"Field", ""} or re.fullmatch(r"-+", cells[0]):
            continue
        rows[cells[0]] = cells[2]
    return rows


@pytest.mark.os_agnostic
@pytest.mark.parametrize("package", ["src/pve_winrepair/", "src/pve_winrepair_guest/"])
def test_the_module_reference_names_the_package(package: str) -> None:
    assert package in _MODULE_REFERENCE.read_text(encoding="utf-8")


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("section", "model"), list(_SECTION_MODELS.items()), ids=list(_SECTION_MODELS))
def test_the_settings_table_matches_the_model(section: str, model: type[BaseModel]) -> None:
    rows = _table_rows(_MODULE_REFERENCE.read_text(encoding="utf-8"), section, model)
    computed = {name for name, field in model.model_fields.items() if field.default_factory is not None}
    expected = {
        name: _toml_literal(field.default) for name, field in model.model_fields.items() if name not in computed
    }

    assert set(rows) == set(model.model_fields)
    assert {name: default for name, default in rows.items() if name not in computed} == expected
    for name in computed:
        # A default computed per OS has no one literal: its cell names the public function that computes it.
        call = re.fullmatch(r"([a-z_]+)\(\)", rows[name])
        assert call is not None, f"{section}.{name}: {rows[name]!r} names no function"
        assert call.group(1) in settings_module.__all__, f"{section}.{name}: {call.group(1)} is not public"
        function: Callable[[], object] = getattr(settings_module, call.group(1))
        assert getattr(model(**{name: function()}), name) == getattr(model(), name), f"{section}.{name}"
