# pve-winrepair

<!-- Badges -->
[![CI](https://github.com/bitranox/pve-winrepair/actions/workflows/default_cicd_public.yml/badge.svg)](https://github.com/bitranox/pve-winrepair/actions/workflows/default_cicd_public.yml)
[![CodeQL](https://github.com/bitranox/pve-winrepair/actions/workflows/codeql.yml/badge.svg)](https://github.com/bitranox/pve-winrepair/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Open in Codespaces](https://img.shields.io/badge/Codespaces-Open-blue?logo=github&logoColor=white&style=flat-square)](https://codespaces.new/bitranox/pve-winrepair?quickstart=1)
[![PyPI](https://img.shields.io/pypi/v/pve-winrepair.svg)](https://pypi.org/project/pve-winrepair/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/pve-winrepair.svg)](https://pypi.org/project/pve-winrepair/)
[![Code Style: Ruff](https://img.shields.io/badge/Code%20Style-Ruff-46A3FF?logo=ruff&labelColor=000)](https://docs.astral.sh/ruff/)
[![codecov](https://codecov.io/gh/bitranox/pve-winrepair/graph/badge.svg?token=UFBaUDIgRk)](https://codecov.io/gh/bitranox/pve-winrepair)
[![Maintainability](https://qlty.sh/badges/041ba2c1-37d6-40bb-85a0-ec5a8a0aca0c/maintainability.svg)](https://qlty.sh/gh/bitranox/projects/pve-winrepair)
[![security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)


`pve-winrepair` is a template CLI application demonstrating configuration management and structured logging. It showcases rich-click for ergonomics and lib_cli_exit_tools for exits, providing a solid foundation for building CLI applications.
- CLI entry point styled with rich-click (rich output + click ergonomics).
- Layered configuration system with lib_layered_config (defaults -> app -> host -> user -> .env -> env).
  The `.env` is the first one found from the current directory upward; when there is none,
  `$XDG_CONFIG_HOME/pve-winrepair/.env` (`~/.config/...` when unset) is read on Linux
  (see [CONFIG.md](CONFIG.md) for macOS and Windows).
- Rich structured logging with lib_log_rich (console, journald, eventlog, Graylog/GELF).
- Exit-code and messaging helpers powered by lib_cli_exit_tools.
- Metadata helpers ready for packaging, testing, and release automation.


### Python 3.10+ Baseline

- The project targets **Python 3.10 and newer**.
- Runtime dependencies are declared with >= floors in pyproject.toml. Dev
  dependencies (pytest, ruff, pyright, bandit, etc.) are declared the same way.
- CI workflows exercise GitHub's rolling runner images (`ubuntu-latest`,
  `macos-latest`, `windows-latest`) and cover CPython 3.10 through 3.15
  alongside the latest available 3.x release provided by Actions.

---

## Install - recommended via uv

[uv](https://docs.astral.sh/uv/) is an ultrafast Python package manager written in Rust (10-20x faster than pip/poetry).

### Install uv (if not already installed) 
```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Copy the actual binaries
cp /root/.local/bin/uv /usr/local/bin/uv
cp /root/.local/bin/uvx /usr/local/bin/uvx

# Ensure world-executable
chmod 755 /usr/local/bin/uv /usr/local/bin/uvx

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### One-shot run (no install needed)

```bash
uvx pve-winrepair@latest --help
```

### Persistent install as CLI tool

```bash
# One-time install from PyPI (isolated environment, added to PATH)
uv tool install pve-winrepair
# or from the git repository
uv tool install --from "git+https://github.com/bitranox/pve-winrepair.git" pve-winrepair
# Pick the interpreter explicitly if needed, e.g. --python 3.14
# Update (requires network)
uv tool upgrade pve-winrepair
# Run
pve-winrepair --help
```

### Install as project dependency

```bash
uv venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
uv pip install pve-winrepair
```

For alternative install paths (pip, pipx, source builds, etc.), see
[INSTALL.md](INSTALL.md). All supported methods register both the
`pve_winrepair` and `pve-winrepair` commands on your PATH.

### Why we recommend uv: supply-chain protection

This repository commits a `uv.lock`. It pins every package the project needs, transitive
dependencies included, to an exact version and to the hashes of that version's files. The
`exclude-newer` setting under `[tool.uv]` in `pyproject.toml` adds a cooldown: uv leaves any
release younger than that out of the lock. CI installs from the lock, so a hijacked release that
gets pulled again within the cooldown never reaches our builds, and a file whose hash does not
match is refused.

That protection stays in this repository. The installable package declares only lower bounds
(`>=`) for its dependencies, so a plain `pip install` takes the newest release of every transitive
dependency at the moment you run it. If one of them was hijacked an hour earlier, you get the
hijacked version. `pipx install` and `uv tool install` without options do the same.

To install the command line tool with a cooldown of your own (uv then skips any release younger
than 7 days, transitive ones included), or to run the exact tree our CI tests:

```bash
uv tool install --exclude-newer "7 days" pve-winrepair
git clone https://github.com/bitranox/pve-winrepair.git && cd pve-winrepair && uv sync --locked && uv run pve-winrepair --help
```

If you depend on pve-winrepair in your own project, give that project the same cooldown (7 days here, as
an example) and commit the `uv.lock` that `uv add pve-winrepair` writes:

```toml
[tool.uv]
exclude-newer = "7 days"
```

---

## Configuration

See [CONFIG.md](CONFIG.md) for detailed documentation on the layered configuration system, including precedence rules, profile support, and customization best practices.

---

## Quick Start

```bash
# Install
uv tool install pve-winrepair

# Verify
pve-winrepair --version

# deploy config files (user level; --target app or host needs sudo)
pve-winrepair config-deploy --target user

# Try it out
pve-winrepair hello
pve-winrepair info
pve-winrepair config
```

---

## Usage

The CLI leverages [rich-click](https://github.com/ewels/rich-click) so help output, validation errors, and prompts render with Rich styling while keeping the familiar click ergonomics.

### Available Commands

```bash
# Display package information
pve-winrepair info

# Greeting and error-handling demos
pve-winrepair hello
pve-winrepair fail
pve-winrepair --traceback fail

# Configuration management
pve-winrepair config                         # Show current configuration
pve-winrepair config --format json           # Show as JSON
pve-winrepair config --section lib_log_rich  # Show specific section
pve-winrepair config --profile production    # Use a named profile

# Deploy configuration templates to target directories
# Without profile:
pve-winrepair config-deploy --target app    # -> /etc/xdg/{slug}/config.toml
pve-winrepair config-deploy --target host   # -> /etc/xdg/{slug}/hosts/{hostname}.toml
pve-winrepair config-deploy --target user   # -> ~/.config/{slug}/config.toml

# With profile:
pve-winrepair config-deploy --target app --profile production   # -> /etc/xdg/{slug}/profile/production/config.toml
pve-winrepair config-deploy --target host --profile production  # -> /etc/xdg/{slug}/profile/production/hosts/{hostname}.toml
pve-winrepair config-deploy --target user --profile production  # -> ~/.config/{slug}/profile/production/config.toml

# With custom permissions (POSIX only):
pve-winrepair config-deploy --target user --file-mode 640       # Files with rw-r----- (640)
pve-winrepair config-deploy --target user --dir-mode 750        # Directories with rwxr-x--- (750)
pve-winrepair config-deploy --target app --no-permissions       # Skip permission setting (use umask)

# Profile names: alphanumeric, hyphens, underscores; max 64 chars; must start with letter/digit
# See CONFIG.md for full validation rules

# Deploy configuration examples
pve-winrepair config-generate-examples --destination ./examples

# Load configuration from an explicit .env file (skips upward directory search)
pve-winrepair --env-file /path/to/.env config
pve-winrepair --env-file ./environments/production.env config

# Override configuration at runtime (repeatable --set)
pve-winrepair --set lib_log_rich.console_level=DEBUG config
pve-winrepair --set lib_log_rich.service=pve-winrepair config --format json

# Logging demo
pve-winrepair logdemo
LOG_CONSOLE_LEVEL=DEBUG pve-winrepair logdemo   # logdemo reads LOG_* only, not --set

# All commands work with any entry point
python -m pve_winrepair info
uvx pve-winrepair info
```

---

## Guest tool subcommands

Every subcommand prints one JSON envelope `{"ok", "command", "data", "skipped"}` and exits 0 (ok),
1 (refused: its own gate said no, or it could not decide) or 2 (internal error, still with an
envelope). The drivers call them; an operator can run one by hand on the guest, as an elevated
admin:

```
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\winrepair\winrepair_guest-<sha16>.ps1 detect-lp-defect --json
```

| Subcommand                                                      | What it answers                                                                                                                                                                   | Exit 1 when                   |
|-----------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------|
| `detect-lp-defect`                                              | is this guest affected by the orphaned language pack: AFFECTED, CLEAN or UNKNOWN                                                                                                  | UNKNOWN                       |
| `drives`                                                        | free bytes per fixed drive (an unparsable volume is skipped)                                                                                                                      | never (2 when no drive reads) |
| `verify-runners [--task NAME]... [--expected N]`                | did the runner containers and their boot tasks come back after a reboot: OK, SHORT or UNKNOWN                                                                                     | SHORT or UNKNOWN              |
| `build`                                                         | CurrentBuild and UBR                                                                                                                                                              | never                         |
| `staged-os`                                                     | is the staged NewOS still there: REARMABLE (apply) or RERUN (a rollback deleted it)                                                                                               | never (2 when it cannot look) |
| `servicing-active`                                              | are TiWorker / TrustedInstaller running                                                                                                                                           | never                         |
| `setup-alive`                                                   | is SetupHost running                                                                                                                                                              | never                         |
| `state [--log PATH]`                                            | the upgrade state log and its last `STATE=DONE-OK` / `STATE=DONE-FAIL` marker                                                                                                     | never                         |
| `quiesce-wu`                                                    | hold Windows Update (Start=4, issue stops, bounded wait) and verify: OK, FAIL or UNKNOWN                                                                                          | FAIL or UNKNOWN               |
| `restore-wu`                                                    | restore the start types and verify: RESTORED, STILL_DISABLED or UNKNOWN; plus a bounded search probe                                                                              | STILL_DISABLED or UNKNOWN     |
| `prepare --stage-root X:\upgrade`                               | clear read-only, gate on the WIM, write the compat waiver: PASS or FAIL                                                                                                           | FAIL                          |
| `lock-dirs --tool PATH [--stage-root X:\upgrade] [--no-create]` | create `C:\winrepair` (and the stage root) already locked, before anything is copied in; with `--no-create` an absent one is reported ABSENT and nothing is created: OK or FAILED | FAILED                        |
| `launch --stage-root X:\upgrade --tool PATH [--state-log]`      | verify the locks, then upgrade-run as a SYSTEM task: OK, SUSPECT, NO_START, FAILED, TASK_LEFT                                                                                     | anything but OK               |
| `upgrade-run --stage-root X:\upgrade [--state-log]`             | the SYSTEM task's command: setup.exe, the state log, the marker: DONE-OK or DONE-FAIL                                                                                             | DONE-FAIL                     |

---

## Further Documentation

- [Install Guide](INSTALL.md)
- [Development Handbook](DEVELOPMENT.md)
- [Contributor Guide](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Module Reference](docs/systemdesign/module_reference.md)
- [License](LICENSE)
