"""Privacy gate: no private site data in the tracked tree, its path names or the packed guest tool.

The repository is public, so this file must not carry the names it forbids, in clear or encoded.
Two kinds of check run:

* Generic patterns (always active, CI included): a private-range address prefix, ``vm-`` and
  ``lxc-`` host names, a key file named after a user and a host, and a credentials directory. They
  reveal nothing about any site and match case-insensitively, since host names do.
* The exact private tokens, read from a JSON list that is never committed: the file named by
  ``PVE_WINREPAIR_PRIVACY_TOKENS_FILE`` when that variable is set, else the gitignored
  ``.privacy-tokens.json`` at the checkout root. Shape: an object with keys from ``hosts``,
  ``vmids``, ``words`` and ``paths``, each a list of non-empty strings. A malformed list, or a
  variable naming a missing file, is an ERROR; only the default file being absent skips these tests
  (CI has no list, so CI skips them by design; a local skip means the list is missing).

The gate finds only the tokens written down. A new private name goes into BOTH copies of the list:
the gitignored one in the checkout and the maintainer's tracked canonical copy kept outside this
repository.

What is scanned: every entry ``git ls-files`` lists, as the bytes a commit stores (the index blob,
so a symlink's target too, never the worktree), in every rendering (UTF-8, else latin-1; plus
UTF-16-LE at both byte alignments whenever the bytes hold a NUL), and every listed path name.
``uv.lock``'s content is skipped (machine-written hashes and sizes; a size can equal a VM id) but
its name is scanned. A gitlink's content is another repository; only its name is scanned here. The
packed guest tool is scanned without its base64 payload, which can spell a token by chance and
changes on every repack; the payload is scanned DECODED, member by member. A finding names the
file, the line and the pattern or the token's list position (``token words[2]``), never the matched
text, so a failing log does not publish what it found. The list object prints only its counts.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pack_guest
import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

TOKENS_FILE = ".privacy-tokens.json"
TOKENS_VARIABLE = "PVE_WINREPAIR_PRIVACY_TOKENS_FILE"
TOKEN_KEYS = ("hosts", "vmids", "words")
KEYS = (*TOKEN_KEYS, "paths")
SKIP_REASON = "no private token list: site-specific check not run"
# Machine-written hashes and sizes, no prose: a size could equal a VM id.
CONTENT_EXCLUDED = frozenset({"uv.lock"})
GITLINK = "160000"  # the index mode of a submodule entry: its object is a commit, not a blob
# The character class in the last pattern keeps this file's own source from matching it.
GENERIC = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"192\.168\.",
        r"\bvm-[a-z]",
        r"\blxc-[a-z]",
        r"\b[\w.-]+@[\w.-]+\.key\b",
        r"/scripts/credential[s]/",
    )
)


class PrivacyListError(ValueError):
    """The private token list is unreadable or malformed: an error, never a reason to skip."""


@dataclass(frozen=True, repr=False)
class PrivateList:
    """The private tokens, each with the label a finding prints in its place."""

    tokens: tuple[tuple[str, str], ...]  # (label "words[2]", lower-case token) for hosts/vmids/words
    paths: tuple[tuple[str, str], ...]  # (label "paths[1]", lower-case substring)

    def __repr__(self) -> str:
        """Per-key counts only.

        pytest prints a failing test's arguments (the ``private`` fixture value among them) and the
        operands of a failing assert; the dataclass default repr would publish every token there.
        """
        counts = Counter(label.split("[", 1)[0] for label, _ in (*self.tokens, *self.paths))
        return "PrivateList(" + ", ".join(f"{key}={counts[key]}" for key in KEYS) + ")"


def _parse(path: Path) -> object:
    # "from None" for the decode errors: a chained traceback ends in json's own frame, whose
    # argument is the whole list text, and pytest prints that argument.
    try:
        return json.loads(path.read_bytes().decode("utf-8"))
    except OSError as exc:
        raise PrivacyListError(f"{path}: cannot read the private token list ({exc.strerror})") from exc
    except UnicodeDecodeError as exc:
        raise PrivacyListError(f"{path}: the private token list is not UTF-8 (byte {exc.start})") from None
    except json.JSONDecodeError as exc:
        raise PrivacyListError(f"{path}: not valid JSON ({exc.msg}, line {exc.lineno})") from None


def _entries(path: Path, key: str, values: object) -> tuple[tuple[str, str], ...]:
    # pytest prints the arguments of the frame that raised; ``values`` holds the tokens.
    __tracebackhide__ = True
    if not isinstance(values, list):
        raise PrivacyListError(f"{path}: {key} must be a list of non-empty strings")
    found: list[tuple[str, str]] = []
    for n, value in enumerate(cast("list[object]", values), start=1):
        if not isinstance(value, str) or not value.strip():
            raise PrivacyListError(f"{path}: {key} must be a list of non-empty strings")
        found.append((f"{key}[{n}]", value.strip().lower()))
    return tuple(found)


def load_private_list(path: Path) -> PrivateList:
    """Read and validate a private token list.

    Args:
        path: The JSON list.

    Returns:
        The tokens and path substrings, lower-cased, each labelled by key and 1-based position.

    Raises:
        PrivacyListError: The file is unreadable, not JSON, not an object, has an unknown key, a
            non-list value, a non-string or empty entry, or holds no token under any key.
    """
    data = _parse(path)
    if not isinstance(data, dict):
        raise PrivacyListError(f"{path}: the list must be a JSON object with keys from {', '.join(sorted(KEYS))}")
    entries = cast("dict[str, object]", data)
    unknown = sorted(set(entries) - set(KEYS))
    if unknown:
        raise PrivacyListError(f"{path}: unknown key(s) {', '.join(unknown)}; allowed: {', '.join(sorted(KEYS))}")
    parsed = {key: _entries(path, key, entries.get(key, [])) for key in KEYS}
    tokens = tuple(entry for key in TOKEN_KEYS for entry in parsed[key])
    if not tokens and not parsed["paths"]:
        raise PrivacyListError(f"{path}: the list holds no token, so it would check nothing")
    return PrivateList(tokens=tokens, paths=parsed["paths"])


def private_list() -> PrivateList | None:
    """The private token list in force, or None when the default file is absent.

    Returns:
        The list named by ``PVE_WINREPAIR_PRIVACY_TOKENS_FILE``, else the checkout's
        ``.privacy-tokens.json``; None only when the variable is unset and that file is absent.

    Raises:
        PrivacyListError: The list is malformed, or the variable names a missing file.
    """
    named = os.environ.get(TOKENS_VARIABLE)
    if named:
        return load_private_list(Path(named))
    default = pack_guest.PROJECT / TOKENS_FILE
    if not default.exists():
        return None
    return load_private_list(default)


def renderings(data: bytes) -> list[str]:
    """Every text reading of ``data`` the scan checks.

    UTF-16-LE is added on any NUL byte, not only when UTF-8 decoding fails: UTF-16-LE of ASCII text
    behind an ASCII header is valid UTF-8, so a decode-failure trigger would never read it as UTF-16.

    Args:
        data: A file's bytes.

    Returns:
        UTF-8 (else latin-1), plus UTF-16-LE at both byte alignments when ``data`` holds a NUL.
    """
    try:
        found = [data.decode("utf-8")]
    except UnicodeDecodeError:
        found = [data.decode("latin-1")]
    if b"\0" in data:
        found += [data.decode("utf-16-le", "replace"), data[1:].decode("utf-16-le", "replace")]
    return found


@functools.lru_cache(maxsize=8)
def _token_patterns(private: PrivateList) -> tuple[tuple[str, re.Pattern[str]], ...]:
    # A token is bounded by any non-alphanumeric, "_" included: "name_key" hits for "name", while a
    # VM id inside a longer number does not. One pattern per token: an empty alternation would match
    # the empty string everywhere, and an alternation would report only one of two overlapping tokens.
    return tuple(
        (label, re.compile(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])")) for label, token in private.tokens
    )


def _occurrences(text: str, needle: str) -> Iterator[int]:
    start = text.find(needle)
    while start >= 0:
        yield start
        start = text.find(needle, start + 1)


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _hits(text: str, private: PrivateList | None) -> list[tuple[int, str]]:
    found = [(_line(text, m.start()), f"pattern {p.pattern}") for p in GENERIC for m in p.finditer(text)]
    if private is None:
        return found
    lowered = text.lower()
    found += [
        (_line(lowered, m.start()), f"token {label}")
        for label, pattern in _token_patterns(private)
        for m in pattern.finditer(lowered)
    ]
    found += [
        (_line(lowered, at), f"token {label}")
        for label, needle in private.paths
        for at in _occurrences(lowered, needle)
    ]
    return found


def findings(name: str, text: str, private: PrivateList | None) -> list[str]:
    """The findings in one text, deduplicated, never quoting what matched.

    Args:
        name: The label printed before each finding (a file name).
        text: The text to scan.
        private: The private tokens, or None for the generic patterns alone.

    Returns:
        ``<name>:<line>: pattern <regex>`` and ``<name>:<line>: token <key>[<n>]`` lines, by line.
    """
    return [f"{name}:{line}: {what}" for line, what in sorted(set(_hits(text, private)))]


def file_findings(name: str, data: bytes, private: PrivateList | None) -> list[str]:
    """The findings in every rendering of a file's bytes, deduplicated.

    Args:
        name: The file's name, printed before each finding.
        data: The file's bytes.
        private: The private tokens, or None for the generic patterns alone.

    Returns:
        The findings of :func:`findings` over each of :func:`renderings`, first occurrence kept.
    """
    return list(dict.fromkeys(f for text in renderings(data) for f in findings(name, text, private)))


def path_findings(index: int, name: str, private: PrivateList | None) -> list[str]:
    """The findings in a path name, labelled by its index so the name itself is never printed.

    Args:
        index: The path's position in the scanned listing.
        name: The path name.
        private: The private tokens, or None for the generic patterns alone.

    Returns:
        ``path[<index>]: pattern <regex>`` and ``path[<index>]: token <key>[<n>]`` lines.
    """
    return list(dict.fromkeys(f"path[{index}]: {what}" for _, what in sorted(_hits(name, private))))


def payload_findings(text: str, private: PrivateList | None) -> list[str]:
    """The findings in each member of a packed script's decoded payload.

    Args:
        text: The packed script.
        private: The private tokens, or None for the generic patterns alone.

    Returns:
        The :func:`file_findings` of every member, labelled by the member name.
    """
    members = pack_guest.decode_payload(text)
    return [f for name, data in members.items() for f in file_findings(name, data, private)]


def _git() -> str:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is not on PATH: the privacy gate cannot list the tracked files")
    return git


def _git_run(project: Path, *args: str, stdin: bytes = b"") -> bytes:
    # Inherited GIT_* variables (a hook's GIT_DIR, a pathspec mode) would make git answer for
    # another repository or another pathspec rule; LC_ALL=C keeps its output unlocalised.
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env["LC_ALL"] = "C"
    return subprocess.run(  # noqa: S603 - fixed argv: git, resolved by shutil.which, run on a given checkout
        [_git(), "-C", str(project), *args],
        input=stdin,
        capture_output=True,
        check=True,
        env=env,
    ).stdout


def _index(project: Path) -> list[tuple[str, str, str]]:
    """Every index entry as (mode, object id, name), in ``git ls-files`` order, unmerged stages included."""
    listing = _git_run(project, "ls-files", "-z", "-s").decode("utf-8", "surrogateescape")
    entries: list[tuple[str, str, str]] = []
    for record in filter(None, listing.split("\0")):
        meta, name = record.split("\t", 1)
        mode, object_id, _stage = meta.split(" ")
        entries.append((mode, object_id, name))
    return entries


def _blobs(project: Path, object_ids: Sequence[str]) -> dict[str, bytes]:
    """The bytes of each blob, read from git's object store in one ``git cat-file --batch``."""
    out = _git_run(project, "cat-file", "--batch", stdin="".join(f"{i}\n" for i in object_ids).encode("ascii"))
    found: dict[str, bytes] = {}
    at = 0
    for object_id in object_ids:
        end = out.index(b"\n", at)
        header = out[at:end].split(b" ")
        if len(header) != 3 or header[1] != b"blob":  # "<id> missing", or not a blob
            raise RuntimeError(f"git cannot read the index blob {object_id}: the scan would miss it")
        size = int(header[2])
        found[object_id] = out[end + 1 : end + 1 + size]
        at = end + 1 + size + 1  # cat-file ends each object with a newline
    return found


def _tracked(project: Path = pack_guest.PROJECT) -> list[tuple[str, bytes]]:
    """Every index entry as (name, bytes to scan), in ``git ls-files`` order.

    The bytes are what a commit stores, read from the INDEX, never the worktree: a staged file
    deleted or restored in the worktree, a dangling symlink and a symlink's target (the blob of a
    mode-120000 entry) are all scanned. No entry is dropped, so a position here is the position in
    ``git ls-files``. A gitlink (mode 160000, a submodule) comes with empty bytes: its content is
    another repository, which its own scan covers; its name is still scanned. ``uv.lock`` comes with
    empty bytes too (its content is excluded, its name is not); the packed tool comes as its wrapper
    without the payload, whose base64 is never scanned as text.
    """
    entries = _index(project)
    readable = [i for mode, i, name in entries if mode != GITLINK and name not in CONTENT_EXCLUDED]
    blobs = _blobs(project, list(dict.fromkeys(readable)))
    artefact = pack_guest.ARTEFACT.as_posix()
    tracked: list[tuple[str, bytes]] = []
    for mode, object_id, name in entries:
        if mode == GITLINK or name in CONTENT_EXCLUDED:
            tracked.append((name, b""))
        elif name == artefact:
            wrapper = pack_guest.wrapper_without_payload(blobs[object_id].decode("utf-8"))
            tracked.append((name, wrapper.encode("utf-8")))
        else:
            tracked.append((name, blobs[object_id]))
    return tracked


def _artefact_text() -> str:
    """The packed tool as the index stores it, the same bytes :func:`_tracked` scans."""
    return _git_run(pack_guest.PROJECT, "cat-file", "blob", f":{pack_guest.ARTEFACT.as_posix()}").decode("utf-8")


def _tree_findings(private: PrivateList | None, project: Path = pack_guest.PROJECT) -> list[str]:
    tracked = _tracked(project)
    assert tracked, "the scan listed no tracked file: it examined nothing"
    return [
        f
        for i, (name, data) in enumerate(tracked)
        for f in (*path_findings(i, name, private), *file_findings(name, data, private))
    ]


@pytest.fixture
def private() -> PrivateList:
    found = private_list()
    if found is None:
        pytest.skip(SKIP_REASON)
    return found


def _planted(tmp_path: Path) -> PrivateList:
    path = tmp_path / "tokens.json"
    path.write_text(
        json.dumps(
            {"hosts": ["planted-host7"], "vmids": ["98765"], "words": ["plantedword"], "paths": ["/planted/dir/"]}
        ),
        encoding="utf-8",
    )
    return load_private_list(path)


def _packed(members: dict[str, bytes]) -> str:
    """A minimal script in pwshpy's runner layout carrying ``members`` as its payload."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    raw = buffer.getvalue()
    blob = base64.b64encode(raw).decode("ascii")
    return f"$PwshPySha = '{hashlib.sha256(raw).hexdigest()}'\n$PwshPyPayload = @'\n{blob}\n'@\nInvoke-It\n"


# --- the real tree --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_the_scan_examines_the_tree_and_the_payload() -> None:
    # Counted into locals: a failing assert on len(...) would print the scanned contents.
    entries = len(_tracked())
    members = len(pack_guest.decode_payload(_artefact_text()))
    assert entries >= 100
    assert members == 10


@pytest.mark.os_agnostic
def test_no_tracked_file_or_path_matches_a_generic_pattern() -> None:
    assert _tree_findings(None) == []


@pytest.mark.os_agnostic
def test_no_tracked_file_or_path_carries_a_private_token(private: PrivateList) -> None:
    assert _tree_findings(private) == []


@pytest.mark.os_agnostic
def test_the_packed_payload_matches_no_generic_pattern() -> None:
    assert payload_findings(_artefact_text(), None) == []


@pytest.mark.os_agnostic
def test_the_packed_payload_carries_no_private_token(private: PrivateList) -> None:
    assert payload_findings(_artefact_text(), private) == []


@pytest.mark.os_agnostic
def test_the_artefact_is_scanned_without_its_base64_payload() -> None:
    scanned = dict(_tracked())[pack_guest.ARTEFACT.as_posix()].decode("utf-8")
    # The wrapper still names the variables; their definitions (the here-string, the sha) are gone.
    # Booleans, not "x not in scanned": a failing assert would print the scanned text.
    has_payload = "$PwshPyPayload = @'" in scanned
    has_sha = "$PwshPySha = '" in scanned
    assert not has_payload
    assert not has_sha
    assert scanned.strip(), "the wrapper of the packed tool was not scanned"


# --- planted positives (a tmp_path list, so these run in CI too) ---------------------------


@pytest.mark.os_agnostic
def test_a_planted_token_and_a_planted_address_are_found(tmp_path: Path) -> None:
    planted = "line one\nkey for plantedword here\nnet " + "192." + "168.1.1\n"
    found = findings("planted.txt", planted, _planted(tmp_path))
    assert sorted(found) == ["planted.txt:2: token words[1]", "planted.txt:3: pattern 192\\.168\\."]


@pytest.mark.os_agnostic
def test_tokens_and_generic_host_names_match_in_any_case(tmp_path: Path) -> None:
    planted = "PLANTED-HOST7 runs\nnamed " + "VM" + "-Guest\n"
    found = findings("planted.txt", planted, _planted(tmp_path))
    assert found == ["planted.txt:1: token hosts[1]", "planted.txt:2: pattern \\bvm-[a-z]"]


@pytest.mark.os_agnostic
def test_an_underscore_bounds_a_token(tmp_path: Path) -> None:
    assert findings("k.txt", "id=98765_disk", _planted(tmp_path)) == ["k.txt:1: token vmids[1]"]


@pytest.mark.os_agnostic
def test_a_planted_token_in_utf16_behind_an_odd_length_header_is_found(tmp_path: Path) -> None:
    # 7 ASCII header bytes put the UTF-16 text at an odd offset: only the second alignment reads it.
    # "utf-16-le" (no BOM) keeps every byte ASCII, so the data is valid UTF-8: this fails when the
    # UTF-16 renderings are added only on a UTF-8 decode error instead of on any NUL byte.
    data = b"MSWIM\0\0" + "<NAME>plantedword</NAME>".encode("utf-16-le")
    assert data.decode("utf-8")  # the precondition the test exists for
    assert file_findings("planted.bin", data, _planted(tmp_path)) == ["planted.bin:1: token words[1]"]


@pytest.mark.os_agnostic
def test_a_planted_token_in_undecodable_bytes_is_found_as_latin1(tmp_path: Path) -> None:
    data = b"\xff\xfe junk /planted/dir/x"
    assert file_findings("planted.bin", data, _planted(tmp_path)) == ["planted.bin:1: token paths[1]"]


@pytest.mark.os_agnostic
def test_a_planted_token_in_a_decoded_payload_member_is_found(tmp_path: Path) -> None:
    packed = _packed({"pkg/clean.py": b"x = 1\n", "pkg/leak.py": b"# one\nHOST = 'planted-host7'\n"})
    assert payload_findings(packed, _planted(tmp_path)) == ["pkg/leak.py:2: token hosts[1]"]
    assert payload_findings(packed, None) == []


@pytest.mark.os_agnostic
def test_a_list_with_only_paths_loads_and_matches_no_empty_token(tmp_path: Path) -> None:
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps({"paths": ["/planted/dir/"]}), encoding="utf-8")
    only_paths = load_private_list(path)
    assert findings("ok.txt", "plain text, no private path", only_paths) == []
    assert findings("bad.txt", "see /planted/dir/x", only_paths) == ["bad.txt:1: token paths[1]"]


@pytest.mark.os_agnostic
def test_a_planted_path_name_is_found_without_printing_it(tmp_path: Path) -> None:
    assert path_findings(7, "docs/plantedword_notes.md", _planted(tmp_path)) == ["path[7]: token words[1]"]


@pytest.mark.os_agnostic
def test_a_second_payload_block_is_refused_not_skipped(tmp_path: Path) -> None:
    # The wrapper scan strips EVERY payload block; a decode of only the first would let a second
    # block escape both checks.
    packed = _packed({"pkg/clean.py": b"x = 1\n"}) + "$PwshPyPayload = @'\nAAAA\n'@\n"
    with pytest.raises(ValueError, match="exactly one"):
        payload_findings(packed, _planted(tmp_path))


# --- what a commit stores: the index, not the worktree (a scratch repository) ---------------


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A fresh repository with one clean staged file; nothing is committed (the index is the subject)."""
    path = tmp_path / "repo"
    path.mkdir()
    _git_run(path, "init", "-q")
    (path / "clean.txt").write_bytes(b"nothing private\n")
    _git_run(path, "add", "clean.txt")
    return path


def _stage(repo: Path, mode: str, name: str, data: bytes) -> None:
    """Put an index entry of ``mode`` holding ``data`` under ``name``, with no worktree file."""
    object_id = _git_run(repo, "hash-object", "-w", "--stdin", stdin=data).decode("ascii").strip()
    _git_run(repo, "update-index", "--add", "--cacheinfo", f"{mode},{object_id},{name}")


@pytest.mark.os_agnostic
def test_a_dangling_symlink_name_is_scanned(repo: Path, tmp_path: Path) -> None:
    _stage(repo, "120000", "docs/plantedword-link", b"nowhere")
    assert _tree_findings(_planted(tmp_path), repo) == ["path[1]: token words[1]"]


@pytest.mark.os_agnostic
def test_a_symlink_target_is_scanned_as_its_blob(repo: Path, tmp_path: Path) -> None:
    _stage(repo, "120000", "link", b"/planted/dir/x")
    assert _tree_findings(_planted(tmp_path), repo) == ["link:1: token paths[1]"]


@pytest.mark.os_agnostic
def test_a_staged_file_deleted_from_the_worktree_is_scanned(repo: Path, tmp_path: Path) -> None:
    (repo / "leak.txt").write_bytes(b"host planted-host7\n")
    _git_run(repo, "add", "leak.txt")
    (repo / "leak.txt").unlink()
    assert _tree_findings(_planted(tmp_path), repo) == ["leak.txt:1: token hosts[1]"]


@pytest.mark.os_agnostic
def test_staged_content_is_scanned_when_the_worktree_is_restored(repo: Path, tmp_path: Path) -> None:
    (repo / "leak.txt").write_bytes(b"host planted-host7\n")
    _git_run(repo, "add", "leak.txt")
    (repo / "leak.txt").write_bytes(b"nothing private\n")
    assert _tree_findings(_planted(tmp_path), repo) == ["leak.txt:1: token hosts[1]"]


@pytest.mark.os_agnostic
def test_a_gitlink_name_is_scanned_and_its_commit_is_not_read(repo: Path, tmp_path: Path) -> None:
    # The object id names a commit in another repository: reading it here would fail.
    _git_run(repo, "update-index", "--add", "--cacheinfo", f"{GITLINK},{'1' * 40},plantedword-sub")
    assert _tree_findings(_planted(tmp_path), repo) == ["path[1]: token words[1]"]


@pytest.mark.os_agnostic
def test_positions_are_those_of_git_ls_files(repo: Path) -> None:
    _stage(repo, "120000", "a-dangling-link", b"nowhere")
    (repo / "z.txt").write_bytes(b"z\n")
    _git_run(repo, "add", "z.txt")
    (repo / "z.txt").unlink()
    listed = _git_run(repo, "ls-files", "-z").decode("utf-8").split("\0")[:-1]
    assert [name for name, _ in _tracked(repo)] == listed == ["a-dangling-link", "clean.txt", "z.txt"]


# --- a failing privacy test prints no token -------------------------------------------------


@pytest.mark.os_agnostic
def test_a_private_list_prints_counts_never_tokens(tmp_path: Path) -> None:
    planted = _planted(tmp_path)
    assert repr(planted) == "PrivateList(hosts=1, vmids=1, words=1, paths=1)"
    assert str(planted) == repr(planted)


_PROBE = """
import os
from pathlib import Path

import test_privacy_gate as gate
from test_privacy_gate import private


def test_probe(private):
    assert gate._tree_findings(private, Path(os.environ["PROBE_REPO"])) == []
"""
_PLANTED_TOKENS = ("planted-host7", "98765", "plantedword", "/planted/dir/")


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("tokens_json", "outcome"),
    [
        (
            '{"hosts": ["planted-host7"], "vmids": ["98765"], "words": ["plantedword"], "paths": ["/planted/dir/"]}',
            "1 failed",
        ),
        ('{"hosts": ["planted-host7"], "vmids": ["98765"], "words": ["plantedword", ""]}', "1 error"),
        ('{"hosts": ["planted-host7"], "vmids": ["98765"], "words": ["plantedword"]', "1 error"),
    ],
    ids=["a-finding", "a-malformed-list", "invalid-json"],
)
def test_a_failing_run_prints_no_token(repo: Path, tmp_path: Path, tokens_json: str, outcome: str) -> None:
    """Run a failing privacy test in a child pytest, the strictest tracebacks on, and read its output."""
    (repo / "leak.txt").write_bytes(" ".join(_PLANTED_TOKENS).encode("utf-8") + b"x\n")
    _git_run(repo, "add", "leak.txt")
    (tmp_path / "tokens.json").write_text(tokens_json, encoding="utf-8")
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (tmp_path / "test_probe.py").write_text(_PROBE, encoding="utf-8")
    here = Path(__file__).resolve().parent
    env = {k: v for k, v in os.environ.items() if not k.startswith("COV_CORE_")}
    env |= {
        "PYTHONPATH": os.pathsep.join(
            str(p) for p in (here, pack_guest.PROJECT / "scripts", pack_guest.PROJECT / "src")
        ),
        TOKENS_VARIABLE: str(tmp_path / "tokens.json"),
        "PROBE_REPO": str(repo),
    }
    run = subprocess.run(  # noqa: S603 - fixed argv: this interpreter running pytest on a generated probe
        [
            sys.executable,
            "-m",
            "pytest",
            "-c",
            str(tmp_path / "pytest.ini"),
            "-p",
            "no:cacheprovider",
            "-vv",
            "--tb=long",
            str(tmp_path / "test_probe.py"),
        ],
        capture_output=True,
        env=env,
        cwd=tmp_path,
        check=False,
    )
    output = (run.stdout + run.stderr).decode("utf-8", "replace").lower()
    assert outcome in output, "the probe did not run to the expected outcome"
    leaked = [n for n, token in enumerate(_PLANTED_TOKENS, start=1) if token in output]
    assert leaked == [], "planted token number(s) printed by the failing run"


# --- known negatives ------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_public_numbers_and_names_are_not_findings(tmp_path: Path) -> None:
    text = "Proxmox VE build 26200 CVE-2025-987650 port 65535 vm-1-disk-0"
    assert findings("ok.txt", text, _planted(tmp_path)) == []


@pytest.mark.os_agnostic
def test_a_file_without_a_nul_has_one_rendering_and_a_nul_adds_two() -> None:
    assert renderings(b"plain") == ["plain"]
    assert len(renderings(b"a\0b\0")) == 3


# --- the list itself ------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("content", "message"),
    [
        ('{"host": ["x"]}', "unknown key(s) host; allowed: hosts, paths, vmids, words"),
        ('{"words": [1]}', "words must be a list of non-empty strings"),
        ('{"words": [""]}', "words must be a list of non-empty strings"),
        ('{"words": "x"}', "words must be a list of non-empty strings"),
        ("[]", "the list must be a JSON object with keys from hosts, paths, vmids, words"),
        ("{}", "the list holds no token, so it would check nothing"),
        ('{"words": [], "paths": []}', "the list holds no token, so it would check nothing"),
        ("not json", "not valid JSON (Expecting value, line 1)"),
    ],
)
def test_a_malformed_list_is_an_error_not_a_skip(tmp_path: Path, content: str, message: str) -> None:
    path = tmp_path / "tokens.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(PrivacyListError) as raised:
        load_private_list(path)
    assert str(raised.value) == f"{path}: {message}"


@pytest.mark.os_agnostic
def test_the_variable_names_another_list_and_a_missing_one_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _planted(tmp_path)
    monkeypatch.setenv(TOKENS_VARIABLE, str(tmp_path / "tokens.json"))
    assert private_list() == _planted(tmp_path)
    missing = tmp_path / "absent.json"
    monkeypatch.setenv(TOKENS_VARIABLE, str(missing))
    with pytest.raises(PrivacyListError) as raised:
        private_list()
    assert str(raised.value).startswith(f"{missing}: cannot read the private token list (")
