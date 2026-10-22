"""The ``[ssh] [guest] [repair] [node]`` settings: shipped defaults, validation, and the env override.

The models live in ``pve_winrepair.domain.settings``; ``load_settings`` turns a loaded ``Config`` into
them and refuses a bad value with ``SettingsError``, one ``<section>.<field>: <reason>`` line per
problem. The end-to-end tests run the real loader against a real environment: the app layer in a
temporary ``/etc``, the user layer in ``tmp_path``, and the working directory in ``tmp_path`` so no
stray ``.env`` decides a result.
"""

from __future__ import annotations

import os
from ipaddress import IPv4Network
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import ValidationError

from pve_winrepair.adapters.cli.main import main
from pve_winrepair.adapters.config.loader import get_config
from pve_winrepair.adapters.config.settings import SettingsError, load_settings
from pve_winrepair.composition import build_production
from pve_winrepair.domain.settings import GuestSettings, NodeSettings, RepairSettings, Settings, SshSettings

if TYPE_CHECKING:
    from collections.abc import Callable

    from lib_layered_config import Config

#: The env prefix lib_layered_config reads for this application.
_ENV_PREFIX = "PVE_WINREPAIR___"


@pytest.fixture
def isolated_layers(monkeypatch: pytest.MonkeyPatch, user_layer_in_tmp_path: Path, clear_config_cache: None) -> Path:
    """Every configuration layer but the shipped defaults points into ``tmp_path``, which is the cwd.

    All three app roots are set because each platform reads its own (``/etc`` on Linux, the
    Application Support root on macOS, ProgramData on Windows); an inherited ``PVE_WINREPAIR___``
    variable would decide a result, so every one is removed.
    """
    root = user_layer_in_tmp_path
    monkeypatch.setenv("LIB_LAYERED_CONFIG_ETC", str(root / "etc"))
    monkeypatch.setenv("LIB_LAYERED_CONFIG_MAC_APP_ROOT", str(root / "macapp"))
    monkeypatch.setenv("LIB_LAYERED_CONFIG_PROGRAMDATA", str(root / "programdata"))
    for name in list(os.environ):
        if name.upper().startswith(_ENV_PREFIX):
            monkeypatch.delenv(name)
    monkeypatch.chdir(root)
    return root


def _refusal(config: Config) -> str:
    with pytest.raises(SettingsError) as caught:
        load_settings(config)
    return str(caught.value)


# --- shipped defaults --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_the_shipped_defaults_load_as_the_model_defaults(isolated_layers: Path) -> None:
    config = get_config()
    # Premise: every field comes from the shipped file, not from the models' own defaults.
    shipped = config.as_dict()
    for section, model in (
        ("ssh", SshSettings),
        ("guest", GuestSettings),
        ("repair", RepairSettings),
        ("node", NodeSettings),
    ):
        assert set(shipped[section]) == set(model.model_fields), section

    assert load_settings(config) == Settings()


@pytest.mark.os_agnostic
def test_the_model_defaults_are_the_documented_ones() -> None:
    settings = Settings()

    assert settings.ssh == SshSettings(
        key="", user="Administrator", strict_host_key_checking=True, known_hosts_file="~/.ssh/known_hosts"
    )
    assert settings.guest.subnet == ""
    assert settings.guest.runner_tasks == ()
    assert settings.guest.expected_runners == 0
    assert settings.repair == RepairSettings(
        media_dir="", snapshot_name="pre_winrepair", stage_free_gb=15.0, system_free_gb=25.0
    )
    assert settings.node.state_dir == Path("/var/lib/pve-winrepair")


@pytest.mark.os_agnostic
def test_an_absent_section_takes_its_defaults(config_factory: Callable[[dict[str, Any]], Config]) -> None:
    assert load_settings(config_factory({})) == Settings()


# --- refusals ----------------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_an_unknown_key_is_refused_by_name_without_its_value(
    config_factory: Callable[[dict[str, Any]], Config],
) -> None:
    text = _refusal(config_factory({"ssh": {"keyy": "x"}}))

    assert "ssh.keyy" in text
    # The QUOTED form: a bare "x" would match the letter in "Extra inputs are not permitted".
    assert "'x'" not in text


@pytest.mark.os_agnostic
def test_a_refusal_carries_one_line_per_problem(config_factory: Callable[[dict[str, Any]], Config]) -> None:
    config = config_factory({"ssh": {"user": "a b"}, "repair": {"stage_free_gb": 0}})

    with pytest.raises(SettingsError) as caught:
        load_settings(config)

    lines = caught.value.lines
    assert len(lines) == 2
    assert [line.split(":", 1)[0] for line in lines] == ["ssh.user", "repair.stage_free_gb"]
    assert str(caught.value) == "\n".join(lines)
    assert isinstance(caught.value, ValueError)


@pytest.mark.os_agnostic
def test_a_section_that_is_not_a_table_is_refused_naming_the_section(
    config_factory: Callable[[dict[str, Any]], Config],
) -> None:
    text = _refusal(config_factory({"node": "somewhere"}))

    assert text.startswith("node: ")
    assert "somewhere" not in text


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("section", "values", "field"),
    [
        ("ssh", {"user": ""}, "ssh.user"),
        ("ssh", {"user": "a b"}, "ssh.user"),
        ("ssh", {"user": "admin\n"}, "ssh.user"),
        ("ssh", {"user": "a" * 65}, "ssh.user"),
        ("ssh", {"user": "dom\\admin"}, "ssh.user"),
        ("ssh", {"strict_host_key_checking": "maybe"}, "ssh.strict_host_key_checking"),
        ("guest", {"expected_runners": -1}, "guest.expected_runners"),
        ("guest", {"expected_runners": 1_000_000}, "guest.expected_runners"),
        ("guest", {"runner_tasks": "runner-a"}, "guest.runner_tasks"),
        ("guest", {"runner_tasks": ["runner a"]}, "guest.runner_tasks.0"),
        ("repair", {"snapshot_name": "1st"}, "repair.snapshot_name"),
        ("repair", {"snapshot_name": "a" * 41}, "repair.snapshot_name"),
        ("repair", {"snapshot_name": "pre repair"}, "repair.snapshot_name"),
        ("repair", {"stage_free_gb": 0}, "repair.stage_free_gb"),
        ("repair", {"stage_free_gb": float("nan")}, "repair.stage_free_gb"),
        ("repair", {"system_free_gb": -1.0}, "repair.system_free_gb"),
        ("repair", {"system_free_gb": float("inf")}, "repair.system_free_gb"),
    ],
    ids=lambda value: str(value)[:24],
)
def test_a_bad_value_is_refused_naming_its_field(
    config_factory: Callable[[dict[str, Any]], Config], section: str, values: dict[str, Any], field: str
) -> None:
    text = _refusal(config_factory({section: values}))

    assert text.split(":", 1)[0] == field


@pytest.mark.os_agnostic
@pytest.mark.parametrize("field", ["key"])
def test_a_loaded_model_refuses_assignment(field: str) -> None:
    with pytest.raises(ValidationError):
        setattr(Settings().ssh, field, "/changed")


# --- accepted forms ----------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_digit_only_text_value_is_kept_as_its_text(config_factory: Callable[[dict[str, Any]], Config]) -> None:
    settings = load_settings(config_factory({"ssh": {"user": 4711}, "guest": {"runner_tasks": [17]}}))

    assert settings.ssh.user == "4711"
    assert settings.guest.runner_tasks == ("17",)


@pytest.mark.os_agnostic
def test_a_fleet_shaped_file_validates_and_keeps_every_value(
    config_factory: Callable[[dict[str, Any]], Config],
) -> None:
    config = config_factory(
        {
            "ssh": {
                "key": "/etc/pve-winrepair/id_guest",
                "user": "admin",
                "strict_host_key_checking": False,
                "known_hosts_file": "~/.ssh/known_hosts_guests",
            },
            "guest": {
                "subnet": "192.0.2.0/24",
                "runner_tasks": ["runner-a", "runner-b", "runner-c"],
                "expected_runners": 18,
            },
            "repair": {
                "media_dir": "/srv/media",
                "snapshot_name": "pre_repair",
                "stage_free_gb": 15.0,
                "system_free_gb": 25.0,
            },
            "node": {"state_dir": "/var/lib/x"},
        }
    )

    settings = load_settings(config)

    assert settings.ssh.key == "/etc/pve-winrepair/id_guest"
    assert settings.ssh.user == "admin"
    assert settings.ssh.strict_host_key_checking is False
    # The literal "~" is kept: ssh expands it itself.
    assert settings.ssh.known_hosts_file == "~/.ssh/known_hosts_guests"
    assert settings.guest.subnet == "192.0.2.0/24"
    assert settings.guest.runner_tasks == ("runner-a", "runner-b", "runner-c")
    assert settings.guest.expected_runners == 18
    assert settings.repair.media_dir == "/srv/media"
    assert settings.repair.snapshot_name == "pre_repair"
    assert settings.repair.stage_free_gb == 15.0
    assert settings.repair.system_free_gb == 25.0
    assert settings.node.state_dir == Path("/var/lib/x")


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("text", "expected"), [("false", False), ("true", True)])
def test_strict_host_key_checking_reads_the_env_layer_text(
    config_factory: Callable[[dict[str, Any]], Config], text: str, expected: bool
) -> None:
    settings = load_settings(config_factory({"ssh": {"strict_host_key_checking": text}}))

    assert settings.ssh.strict_host_key_checking is expected


# --- guest.subnet ------------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_subnet_is_an_ipv4_network_with_membership(config_factory: Callable[[dict[str, Any]], Config]) -> None:
    network = load_settings(config_factory({"guest": {"subnet": "192.0.2.0/24"}})).guest.network()

    assert network == IPv4Network("192.0.2.0/24")
    assert network is not None
    assert IPv4Network("192.0.2.77/32").subnet_of(network)
    assert not IPv4Network("198.51.100.7/32").subnet_of(network)


@pytest.mark.os_agnostic
def test_an_empty_subnet_is_no_network() -> None:
    assert GuestSettings().network() is None


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "subnet",
    ["192.0.2.1/24", "garbage", "2001:db8::/32", "192.0.2.0", "192.0.2.0/33", " 192.0.2.0/24"],
    ids=["host-bits", "garbage", "ipv6", "no-prefix", "prefix-too-long", "leading-space"],
)
def test_a_subnet_that_is_not_a_strict_ipv4_cidr_is_refused(
    config_factory: Callable[[dict[str, Any]], Config], subnet: str
) -> None:
    text = _refusal(config_factory({"guest": {"subnet": subnet}}))

    assert text.startswith("guest.subnet: ")
    assert "IPv4" in text


# --- env override, end to end ------------------------------------------------------------------


@pytest.mark.os_linux
def test_the_env_variable_overrides_the_app_file_key(
    isolated_layers: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    app_file = isolated_layers / "etc" / "pve-winrepair" / "config.toml"
    app_file.parent.mkdir(parents=True)
    app_file.write_text('[ssh]\nkey = "/file/key"\n', encoding="utf-8")

    # Arm A first: without the variable the app file decides, so a broken override cannot pass.
    exit_a = main(["config", "--section", "ssh"], services_factory=build_production)
    out_a = capsys.readouterr().out
    assert exit_a == 0
    assert "/file/key" in out_a
    assert "layer:app" in out_a
    assert load_settings(get_config()).ssh.key == "/file/key"

    get_config.cache_clear()
    monkeypatch.setenv(f"{_ENV_PREFIX}SSH__KEY", "/env/key")
    exit_b = main(["config", "--section", "ssh"], services_factory=build_production)
    out_b = capsys.readouterr().out
    assert exit_b == 0
    assert "/env/key" in out_b
    assert "layer:env" in out_b
    assert "/file/key" not in out_b
    assert load_settings(get_config()).ssh.key == "/env/key"
