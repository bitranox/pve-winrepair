"""What ``config-deploy`` leaves in force: the app file's winrepair settings survive a host or user deploy.

The settings for a site live in the app layer (``/etc/pve-winrepair/config.toml``). A deploy writes
the host or user layer, which lib_layered_config reads AFTER the app layer, so every key the
deployed files set hides the app file's value for that key. The deployed ``20-winrepair.toml``
therefore carries every winrepair key commented out: it documents the settings and sets none.
The package's own ``defaultconfig.d/20-winrepair.toml`` is the defaults layer and keeps its keys.

The tests run the real deploy and the real loader against a temporary ``/etc``, ``HOME`` and
``XDG_CONFIG_HOME`` (the ``isolated_layers`` fixture): nothing touches the real configuration.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import rtoml

from pve_winrepair.adapters.cli.main import main
from pve_winrepair.adapters.config.deploy import commented_settings
from pve_winrepair.adapters.config.loader import get_config, get_default_config_path
from pve_winrepair.adapters.config.settings import load_settings
from pve_winrepair.composition import build_production

if TYPE_CHECKING:
    from pathlib import Path

_APP_FILE_TEXT = '[repair]\nsystem_free_gb = 77.0\nmedia_dir = "/srv/media/win11"\n'
_SHIPPED = get_default_config_path().parent / "defaultconfig.d" / "20-winrepair.toml"


def _write_app_file(root: Path) -> None:
    app_file = root / "etc" / "pve-winrepair" / "config.toml"
    app_file.parent.mkdir(parents=True)
    app_file.write_text(_APP_FILE_TEXT, encoding="utf-8")


def _deployed_copies(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("20-winrepair.toml") if path.parent.name != "defaultconfig.d")


@pytest.mark.os_linux
@pytest.mark.parametrize("target", ["host", "user"])
def test_a_deploy_leaves_the_app_files_winrepair_settings_in_force(
    isolated_layers: Path, capsys: pytest.CaptureFixture[str], target: str
) -> None:
    _write_app_file(isolated_layers)
    # Arm A: before the deploy the app file decides, so a loader that never reads it cannot pass.
    before = get_config()
    assert load_settings(before).repair.system_free_gb == 77.0
    assert before.origin("repair.system_free_gb") is not None

    exit_code = main(["config-deploy", "--target", target], services_factory=build_production)
    capsys.readouterr()
    assert exit_code == 0
    # Liveness: the deploy wrote its copy of the winrepair file where the loader reads the layer.
    assert len(_deployed_copies(isolated_layers)) == 1

    get_config.cache_clear()
    after = get_config()
    repair = load_settings(after).repair
    assert repair.system_free_gb == 77.0
    assert repair.media_dir == "/srv/media/win11"
    for key in ("repair.system_free_gb", "repair.media_dir"):
        origin = after.origin(key)
        assert origin is not None
        assert origin["layer"] == "app", key


@pytest.mark.os_agnostic
def test_the_deployed_winrepair_file_sets_no_key_and_documents_every_one() -> None:
    shipped_text = _SHIPPED.read_text(encoding="utf-8")
    shipped = rtoml.loads(shipped_text)
    deployed_text = commented_settings(shipped_text)

    deployed = rtoml.loads(deployed_text)

    # Every section stays, so a user uncommenting a key finds it under its own table; none holds a key.
    assert deployed == {section: {} for section in shipped}
    # Every shipped key line is still there, commented, with its default as the example value.
    for section, values in shipped.items():
        assert values, section  # premise: the shipped defaults layer keeps its active keys
        for key in values:
            assert any(line.startswith(f"# {key} = ") for line in deployed_text.splitlines()), f"{section}.{key}"
    # Every explanatory comment is kept as written.
    shipped_comments = [line for line in shipped_text.splitlines() if line.startswith("#")]
    deployed_lines = deployed_text.splitlines()
    assert all(line in deployed_lines for line in shipped_comments)


@pytest.mark.os_agnostic
def test_a_user_deploy_writes_the_commented_copy_and_leaves_the_other_files_as_shipped(
    isolated_layers: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["config-deploy", "--target", "user"], services_factory=build_production)
    capsys.readouterr()
    assert exit_code == 0

    copies = _deployed_copies(isolated_layers)
    assert len(copies) == 1
    assert copies[0].read_text(encoding="utf-8") == commented_settings(_SHIPPED.read_text(encoding="utf-8"))
    for name in ("40-layered-config.toml", "90-logging.toml"):
        (deployed,) = [path for path in isolated_layers.rglob(name) if path.parent.name != "defaultconfig.d"]
        assert deployed.read_bytes() == (_SHIPPED.parent / name).read_bytes(), name
