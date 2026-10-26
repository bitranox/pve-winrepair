# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it
responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. Contact the maintainer directly or use
   [GitHub's private vulnerability reporting](https://github.com/bitranox/pve-winrepair/security/advisories/new).
3. Include a description of the vulnerability, steps to reproduce, and any
   relevant logs or screenshots.

You can expect an initial response within 72 hours.

## Security Tooling

This project employs the following security measures in CI:

- **Bandit** -- static analysis for common Python security issues
- **CodeQL** -- GitHub code scanning (weekly schedule)
- **pip-audit** -- dependency vulnerability scanning against the OSV database
- **Snyk** -- continuous dependency monitoring
- **Ruff security rules** -- S (flake8-bandit) and B (flake8-bugbear) rulesets

## Dependency Policy

- Production dependencies use minimum version constraints (`>=`) and are audited
  on every CI run via `pip-audit`.
- Known CVEs in transitive dependencies are pinned in `pyproject.toml` with
  inline comments referencing the CVE identifier.

## Trust boundaries on the guest

What `pve-winrepair` checks, and what it trusts without checking:

- The guest tool's bytes are checked: every copy the node runs is hashed on the guest
  (`certutil -hashfile`) and compared with the node's own sha256 before it runs.
- The software the tool runs with is not. The first run of the tool as a given user (the ssh user,
  and SYSTEM for the upgrade run) installs `uv` from `https://astral.sh/uv` when the guest has none
  that user can trust, downloads a uv-managed Python into that user's profile, and uv then resolves
  the tool's pinned dependencies `pwshpy==1.8.0` and `pywin32==312` from PyPI. Every run is
  elevated, so pwshpy's packed runner only runs a uv and a Python that no account other than that
  user, SYSTEM, Administrators, TrustedInstaller and the two service accounts can modify, and
  ignores the caller's proxy, index and interpreter variables (pwshpy 1.8.0
  `docs/power-tools.md`).
  The versions are pinned; their hashes are not. That run trusts astral.sh, PyPI and the guest's
  TLS trust store. A guest that must not reach the internet needs uv and those packages in its
  cache beforehand.
- The ssh user's profile is checked before a copy goes there: only SYSTEM, Administrators and the
  ssh user may write it. A file that already exists there under the copy's name (left behind by a
  delete that failed, or put there by one of those principals) keeps its own DACL when the copy
  overwrites it. The hash check still runs, but a principal that the file's own DACL lets write
  could swap it between the hash and the run. Delete such a leftover by hand when a push reports
  `staged_left`.
- A staging directory that already exists and is exactly locked is reused, and the media copy goes
  over its contents: files of earlier, different media stay and setup can load them. Remove the
  directory before staging other media.
- With `--ip`, the address is bound to the VM only by MAC: the guest must report one of the VM's
  `qm config` MACs. A guest that can change its own adapter's MAC can claim to be another VM; the
  check guards against a typo, not against a hostile guest.
