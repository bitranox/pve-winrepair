"""The ``[ssh] [guest] [repair] [node]`` settings: shipped defaults, validation, and the env override.

The models live in ``pve_winrepair.domain.settings``; ``load_settings`` turns a loaded ``Config`` into
them and refuses a bad value with ``SettingsError``, one ``<section>.<field>: <reason>`` line per
problem. The end-to-end tests run the real loader against a real environment: the app layer in a
temporary ``/etc``, the user layer in ``tmp_path``, and the working directory in ``tmp_path`` so no
stray ``.env`` decides a result.
"""

from __future__ import annotations

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
    assert settings.guest.subnet is None
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
    assert settings.guest.subnet == IPv4Network("192.0.2.0/24")
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
    network = load_settings(config_factory({"guest": {"subnet": "192.0.2.0/24"}})).guest.subnet

    assert network == IPv4Network("192.0.2.0/24")
    assert network is not None
    assert IPv4Network("192.0.2.77/32").subnet_of(network)
    assert not IPv4Network("198.51.100.7/32").subnet_of(network)


@pytest.mark.os_agnostic
def test_an_empty_subnet_is_no_network(config_factory: Callable[[dict[str, Any]], Config]) -> None:
    assert load_settings(config_factory({"guest": {"subnet": ""}})).guest.subnet is None
    assert GuestSettings().subnet is None


_NO_PREFIX = "must be an IPv4 network in CIDR or netmask form (a.b.c.d/n or a.b.c.d/m.m.m.m), or empty"
_NOT_A_NETWORK = "must be an IPv4 network in CIDR or netmask form with no host bits set, or empty"


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("subnet", "reason"),
    [
        ("192.0.2.1/24", _NOT_A_NETWORK),
        ("garbage/24", _NOT_A_NETWORK),
        ("2001:db8::/32", _NOT_A_NETWORK),
        ("192.0.2.0/33", _NOT_A_NETWORK),
        (" 192.0.2.0/24", _NOT_A_NETWORK),
        ("192.0.2.0", _NO_PREFIX),
        ("garbage", _NO_PREFIX),
        (24, _NO_PREFIX),
        (1.5, _NO_PREFIX),
        (True, "Input should be a valid string"),
        (["192.0.2.0/24"], "Input should be a valid string"),
        ({"net": "192.0.2.0/24"}, "Input should be a valid string"),
    ],
    ids=[
        "host-bits",
        "garbage-with-prefix",
        "ipv6",
        "prefix-too-long",
        "leading-space",
        "no-prefix",
        "garbage",
        "an-int",
        "a-float",
        "a-boolean",
        "a-list",
        "a-table",
    ],
)
def test_a_refused_subnet_names_the_rule_never_the_value(
    config_factory: Callable[[dict[str, Any]], Config], subnet: object, reason: str
) -> None:
    assert _refusal(config_factory({"guest": {"subnet": subnet}})) == f"guest.subnet: {reason}"


@pytest.mark.os_agnostic
def test_a_subnet_in_netmask_form_is_accepted(config_factory: Callable[[dict[str, Any]], Config]) -> None:
    network = load_settings(config_factory({"guest": {"subnet": "192.0.2.0/255.255.255.0"}})).guest.subnet

    assert network == IPv4Network("192.0.2.0/24")


# --- repair.snapshot_name ----------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_one_character_snapshot_name_is_refused(config_factory: Callable[[dict[str, Any]], Config]) -> None:
    # Proxmox's CONFIGID_RE is [a-z][a-z0-9_-]+, so a snapshot name has at least two characters.
    text = _refusal(config_factory({"repair": {"snapshot_name": "a"}}))

    assert text == "repair.snapshot_name: String should match pattern '^[A-Za-z][A-Za-z0-9_-]{1,39}$'"


@pytest.mark.os_agnostic
@pytest.mark.parametrize("name", ["ab", "a" * 40])
def test_a_snapshot_name_of_two_to_forty_characters_is_accepted(
    config_factory: Callable[[dict[str, Any]], Config], name: str
) -> None:
    assert load_settings(config_factory({"repair": {"snapshot_name": name}})).repair.snapshot_name == name


# --- node.state_dir ----------------------------------------------------------------------------

#: The refusal reason for a state directory that is not an absolute POSIX path.
_STATE_DIR_REASON = "node.state_dir: must be an absolute path on the node (starting with /)"


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "state_dir",
    ["", "rel/dir", "~/x", "./receipts", 4711],
    ids=["empty", "relative", "tilde", "dot-relative", "digit-only"],
)
def test_a_state_dir_that_is_not_absolute_is_refused_without_its_value(
    config_factory: Callable[[dict[str, Any]], Config], state_dir: object
) -> None:
    text = _refusal(config_factory({"node": {"state_dir": state_dir}}))

    assert text == _STATE_DIR_REASON


@pytest.mark.os_agnostic
@pytest.mark.parametrize("state_dir", ["/var/lib/pve-winrepair", "/root/winrepair", "/"])
def test_an_absolute_posix_state_dir_is_accepted_on_every_os(
    config_factory: Callable[[dict[str, Any]], Config], state_dir: str
) -> None:
    settings = load_settings(config_factory({"node": {"state_dir": state_dir}}))

    assert settings.node.state_dir == Path(state_dir)


@pytest.mark.os_linux
def test_an_empty_state_dir_from_the_environment_is_refused(
    isolated_layers: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Linux only: an environment variable set to "" is removed on Windows, so it never reaches the loader.
    monkeypatch.setenv(f"{_ENV_PREFIX}NODE__STATE_DIR", "")
    config = get_config()
    # Premise: the empty text reaches the settings; without it the refusal below proves nothing.
    assert config.as_dict()["node"]["state_dir"] == ""

    assert _refusal(config) == _STATE_DIR_REASON


# --- node link: host, ssh_user, ssh_key --------------------------------------------------------


@pytest.mark.os_agnostic
def test_node_link_settings_default_to_this_machine(config_factory: Callable[[dict[str, Any]], Config]) -> None:
    node = load_settings(config_factory({})).node
    assert (node.host, node.ssh_user, node.ssh_key) == ("", "root", "")


@pytest.mark.os_agnostic
def test_the_node_known_hosts_file_defaults_to_the_users_own() -> None:
    assert NodeSettings().known_hosts_file == "~/.ssh/known_hosts"


@pytest.mark.os_agnostic
@pytest.mark.parametrize("host", ["pve1", "pve1.example.net", "192.0.2.10"])
def test_a_node_host_name_or_address_is_accepted(config_factory: Callable[[dict[str, Any]], Config], host: str) -> None:
    assert load_settings(config_factory({"node": {"host": host}})).node.host == host


@pytest.mark.os_agnostic
@pytest.mark.parametrize("host", ["-oProxyCommand=x", "pve 1", "pve1;id", "root@pve1"])
def test_a_node_host_that_ssh_could_read_as_an_option_or_a_second_word_is_refused(
    config_factory: Callable[[dict[str, Any]], Config], host: str
) -> None:
    with pytest.raises(SettingsError) as refused:
        load_settings(config_factory({"node": {"host": host}}))
    # The pattern reason, not "Extra inputs are not permitted": a model without the field refuses these too.
    assert any(line.startswith("node.host: String should match pattern") for line in refused.value.lines)


@pytest.mark.os_agnostic
def test_a_node_ssh_user_starting_with_a_dash_is_refused(config_factory: Callable[[dict[str, Any]], Config]) -> None:
    with pytest.raises(SettingsError) as refused:
        load_settings(config_factory({"node": {"ssh_user": "-oX"}}))
    assert any(line.startswith("node.ssh_user: String should match pattern") for line in refused.value.lines)


# --- ssh paths: known_hosts files, the node key -----------------------------------------------

#: The refusal reason for a "%" in a path that travels through the jump to a guest.
_PERCENT_REASON = "must not contain %: ssh expands it as a token, once more through the jump to a guest"


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("section", "key", "value", "reason"),
    [
        ("node", "known_hosts_file", "", "node.known_hosts_file: must not be empty"),
        (
            "node",
            "known_hosts_file",
            "/a b/kh",
            "node.known_hosts_file: must not contain whitespace: ssh splits the value into several files",
        ),
        (
            "node",
            "known_hosts_file",
            "/kh%h",
            f"node.known_hosts_file: {_PERCENT_REASON}",
        ),
        ("node", "ssh_key", '/k"ey', "node.ssh_key: must not contain a double quote"),
        (
            "ssh",
            "known_hosts_file",
            "/a b/kh",
            "ssh.known_hosts_file: must not contain whitespace: ssh splits the value into several files",
        ),
        ("ssh", "known_hosts_file", "", "ssh.known_hosts_file: must not be empty"),
    ],
)
def test_an_ssh_path_no_quoting_carries_is_refused_at_load(
    config_factory: Callable[[dict[str, Any]], Config], section: str, key: str, value: str, reason: str
) -> None:
    assert _refusal(config_factory({section: {key: value}})) == reason


@pytest.mark.os_agnostic
def test_a_guest_known_hosts_file_keeps_ssh_tokens_and_a_node_key_may_hold_a_space(
    config_factory: Callable[[dict[str, Any]], Config],
) -> None:
    settings = load_settings(
        config_factory({"ssh": {"known_hosts_file": "~/.ssh/kh_%h"}, "node": {"ssh_key": "/home/a b/node.key"}})
    )
    assert (settings.ssh.known_hosts_file, settings.node.ssh_key) == ("~/.ssh/kh_%h", "/home/a b/node.key")


# --- numbers: no booleans ----------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("section", "field"),
    [("guest", "expected_runners"), ("repair", "stage_free_gb"), ("repair", "system_free_gb")],
)
@pytest.mark.parametrize("flag", [True, False])
def test_a_boolean_is_refused_for_a_number(
    config_factory: Callable[[dict[str, Any]], Config], section: str, field: str, flag: bool
) -> None:
    text = _refusal(config_factory({section: {field: flag}}))

    assert text == f"{section}.{field}: must be a number, not true or false"


@pytest.mark.os_agnostic
def test_a_number_written_as_text_is_accepted(config_factory: Callable[[dict[str, Any]], Config]) -> None:
    config = config_factory({"guest": {"expected_runners": "4"}, "repair": {"stage_free_gb": "15.5"}})

    settings = load_settings(config)

    assert settings.guest.expected_runners == 4
    assert settings.repair.stage_free_gb == 15.5


@pytest.mark.os_agnostic
def test_numbers_from_a_dotenv_file_are_accepted_and_a_boolean_is_refused(isolated_layers: Path) -> None:
    dotenv = isolated_layers / ".env"
    dotenv.write_text("GUEST__EXPECTED_RUNNERS=4\nREPAIR__STAGE_FREE_GB=15.5\n", encoding="utf-8")
    config = build_production().get_config(dotenv_path=str(dotenv))
    # Premise: the dotenv layer hands both values over as numbers, the digit-only one as an int.
    assert type(config.as_dict()["guest"]["expected_runners"]) is int
    assert type(config.as_dict()["repair"]["stage_free_gb"]) is float

    settings = load_settings(config)

    assert settings.guest.expected_runners == 4
    assert settings.repair.stage_free_gb == 15.5

    get_config.cache_clear()
    dotenv.write_text("REPAIR__SYSTEM_FREE_GB=true\n", encoding="utf-8")
    config = build_production().get_config(dotenv_path=str(dotenv))
    # Premise: the dotenv layer turns "true" into a bool.
    assert config.as_dict()["repair"]["system_free_gb"] is True

    assert _refusal(config) == "repair.system_free_gb: must be a number, not true or false"


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
