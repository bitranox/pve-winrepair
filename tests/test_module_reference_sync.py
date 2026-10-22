"""The module reference exists and names both packages it documents.

``docs/systemdesign/module_reference.md`` is where a reader learns which module does what. Until
the node CLI gains its configuration models, this pins only that the document is there and covers
the node CLI package and the guest tool package; the field-table check against the models comes
with them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_MODULE_REFERENCE = Path(__file__).parent.parent / "docs" / "systemdesign" / "module_reference.md"


@pytest.mark.os_agnostic
@pytest.mark.parametrize("package", ["src/pve_winrepair/", "src/pve_winrepair_guest/"])
def test_the_module_reference_names_the_package(package: str) -> None:
    assert package in _MODULE_REFERENCE.read_text(encoding="utf-8")
