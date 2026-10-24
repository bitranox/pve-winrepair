"""Tests for the profile descriptor check: which SDDL descriptors let someone else write the profile.

The node reads the ssh user's profile descriptor before it copies the guest tool there (an elevated
run executes that copy). The SIDs are generic: ``USER`` stands for the ssh user, ``CAP`` for an app
capability SID that a fleet profile carries with traverse rights only.
"""

from __future__ import annotations

import pytest

from pve_winrepair.domain.acl import (
    TRUSTED_WELL_KNOWN,
    AceFlag,
    AceKind,
    SddlError,
    parse_sddl,
    trusted_writers,
    write_problems,
)

USER = "S-1-5-21-1-2-3-1001"
TRUSTED = TRUSTED_WELL_KNOWN | {USER}
CAP = "S-1-15-3-1024-1-2-3"
FLEET = f"O:{USER}G:{USER}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{USER})(A;;0x100020;;;{CAP})"


def test_a_profile_only_admins_and_the_user_can_write_has_no_problem() -> None:
    assert write_problems(parse_sddl(FLEET), trusted=TRUSTED) == ()


@pytest.mark.parametrize(
    ("ace", "needle"),
    [
        ("(A;OICI;FW;;;BU)", "BU"),
        ("(A;;0x2;;;S-1-5-32-545)", "S-1-5-32-545"),
        ("(A;OICIIO;GA;;;AU)", "AU"),  # inherit-only, but files inherit it
        ("(A;;WD;;;WD)", "WD"),  # WRITE_DAC for Everyone
        ("(A;ID;0x10000;;;S-1-5-11)", "S-1-5-11"),  # DELETE, inherited ACE still applies
    ],
)
def test_a_write_right_for_anyone_else_is_a_problem_naming_them(ace: str, needle: str) -> None:
    problems = write_problems(parse_sddl(FLEET + ace), trusted=TRUSTED)
    assert len(problems) == 1 and needle in problems[0]


@pytest.mark.parametrize("ace", ["(A;CIIO;FA;;;BU)", "(D;OICI;FA;;;BU)", "(A;OICI;0x1200a9;;;BU)"])
def test_rights_that_reach_neither_the_directory_nor_the_copy_are_no_problem(ace: str) -> None:
    assert write_problems(parse_sddl(FLEET + ace), trusted=TRUSTED) == ()


def test_an_owner_outside_the_trusted_set_is_a_problem() -> None:
    problems = write_problems(parse_sddl(FLEET.replace(f"O:{USER}", "O:BU", 1)), trusted=TRUSTED)
    assert problems and "owner" in problems[0] and "BU" in problems[0]


def test_a_missing_dacl_is_a_problem() -> None:
    assert write_problems(parse_sddl(f"O:{USER}G:{USER}D:NO_ACCESS_CONTROL"), trusted=TRUSTED)


def test_an_ace_kind_it_does_not_judge_fails_closed() -> None:
    problems = write_problems(parse_sddl(FLEET + "(XA;;FA;;;BU;(x))"), trusted=TRUSTED)
    assert problems == ("an ACE of kind XA for BU is not judged (only allow and deny are)",)


def test_an_ace_is_parsed_once_into_its_kind_and_flags() -> None:
    allow, deny, other = parse_sddl("O:SYD:(A;OICIIO;FA;;;BU)(D;;FA;;;WD)(XA;;FA;;;BU;(x))").aces
    assert (allow.kind, allow.code, allow.flags_text) == (AceKind.ALLOW, "A", "OICIIO")
    assert allow.flags == frozenset({AceFlag.OBJECT_INHERIT, AceFlag.CONTAINER_INHERIT, AceFlag.INHERIT_ONLY})
    assert (deny.kind, deny.flags) == (AceKind.DENY, frozenset())
    assert (other.kind, other.code) == (AceKind.OTHER, "XA")


@pytest.mark.parametrize("text", ["", "O:", "D:P(A;;ZZ;;;BU)", "D:P(A;;FA;;)", "garbage"])
def test_malformed_descriptors_are_refused(text: str) -> None:
    with pytest.raises(SddlError):
        parse_sddl(text)


def test_flags_are_read_in_pairs_so_cioi_is_not_inherit_only() -> None:
    # "CIOI" holds the letters "IO" at 1-2 but no IO flag: the ACE applies to the directory itself.
    problems = write_problems(parse_sddl(FLEET + "(A;CIOI;FW;;;BU)"), trusted=TRUSTED)
    assert problems == ("BU may write: allow 0x120116 (flags CIOI)",)


def test_a_sacl_after_the_dacl_is_skipped_and_its_ace_kinds_are_not_judged() -> None:
    reading = parse_sddl(FLEET.replace("D:P", "D:PAI", 1) + "S:AI(AU;SA;FA;;;WD)")
    assert write_problems(reading, trusted=TRUSTED) == ()


@pytest.mark.parametrize(
    "text",
    [
        f"O:{USER}O:SY",
        "D:P(A;;FA;;;BU",
        "D:P(A;;FA;;;BU;x)",
        "D:P(A;QQ;FA;;;BU)",
        "D:P(A;;FA;;;bu)",
        "D:P(A;;F;;;BU)",
        "D:P(a;;FA;;;BU)",
    ],
    ids=[
        "repeated-owner",
        "unclosed-ace",
        "seventh-field-on-allow",
        "unknown-flag",
        "lowercase-sid",
        "odd-rights",
        "lowercase-kind",
    ],
)
def test_more_malformed_descriptors_are_refused(text: str) -> None:
    with pytest.raises(SddlError):
        parse_sddl(text)


# --- the built-in Administrator: Get-Acl prints its own SID as the alias LA -------------------

ADMIN = "S-1-5-21-1-2-3-500"
# The profile of the built-in Administrator (RID 500, the shipped default [ssh] user) as Get-Acl
# prints it: the account's own SID appears only as the alias LA, as owner and in its ACE.
ADMIN_PROFILE = "O:LAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LA)"


def test_the_built_in_administrator_profile_has_no_problem_for_that_user() -> None:
    assert write_problems(parse_sddl(ADMIN_PROFILE), trusted=trusted_writers(ADMIN)) == ()


@pytest.mark.parametrize(
    "user",
    [USER, "S-1-5-21-1-2-3-5000", "S-1-5-21-500-2-3-1001", "S-1-5-21-1-2-3-1500"],
    ids=["rid-1001", "rid-5000", "500-not-last", "rid-1500"],
)
def test_la_stays_untrusted_for_any_user_who_is_not_rid_500(user: str) -> None:
    problems = write_problems(parse_sddl(ADMIN_PROFILE), trusted=trusted_writers(user))
    assert problems == (
        "the owner LA is not trusted (an owner can rewrite the ACL)",
        "LA may write: allow 0x1f01ff (flags OICI)",
    )


def test_the_trusted_writers_are_the_well_known_principals_plus_the_user() -> None:
    assert trusted_writers(USER) == TRUSTED_WELL_KNOWN | {USER}
    assert trusted_writers(ADMIN) == TRUSTED_WELL_KNOWN | {ADMIN, "LA"}
