# Installation Guide

> The CLI stack uses `rich-click`, which bundles `rich` styling on top of click-style ergonomics.

This guide collects every supported method to install `pve-winrepair`, including
isolated environments and system package managers. Pick the option that matches your workflow.


## We recommend `uv` to install the package

### `uv` = Ultra-fast Python package manager

> lightning-fast replacement for `pip`, `venv`, `pip-tools`, and `poetry`
written in Rust, compatible with PEP 621 (`pyproject.toml`)

### `uvx` = On-demand tool runner

> runs tools temporarily in isolated environments without installing them globally


## Install uv (if not already installed)

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

## One-shot run via uvx (no install needed)

```bash
uvx pve-winrepair@latest --help
```

## Persistent install as CLI tool

```bash
# install the CLI tool (isolated environment, added to PATH)
uv tool install pve-winrepair

# upgrade to latest
uv tool upgrade pve-winrepair
```

## Install as project dependency

```bash
uv venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
uv pip install pve-winrepair
```

## Verify installation

After any install method, confirm the CLI is available:

```bash
pve-winrepair --version
```

---

## Installation via pip

```bash
# optional, install in a venv (recommended)
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
# install from PyPI
pip install pve-winrepair
# optional install from GitHub
pip install "git+https://github.com/bitranox/pve-winrepair"
# optional development install from local
pip install -e ".[dev]"
# optional install from local runtime only:
pip install .
```

## Per-User Installation (No Virtualenv) - from local

```bash
# install from PyPI
pip install --user pve-winrepair
# optional install from GitHub
pip install --user "git+https://github.com/bitranox/pve-winrepair"
# optional install from local
pip install --user .
```

> Note: This respects PEP 668. Avoid using it on system Python builds marked as
> "externally managed". Ensure `~/.local/bin` (POSIX) is on your PATH so the CLI is available.

## pipx (Isolated CLI-Friendly Environment)

```bash
# install pipx via pip
python -m pip install pipx
# optional install pipx via apt
sudo apt install pipx
# install via pipx from PyPI
pipx install pve-winrepair
# optional install via pipx from GitHub
pipx install "git+https://github.com/bitranox/pve-winrepair"
# optional install from local
pipx install .
pipx upgrade pve-winrepair
# install from Git tag
pipx install "git+https://github.com/bitranox/pve-winrepair@v1.1.0"
```

## From Build Artifacts

```bash
python -m build
pip install dist/pve_winrepair-*.whl
pip install dist/pve_winrepair-*.tar.gz   # sdist
```

## Poetry or PDM Managed Environments

```bash
# Poetry
poetry add pve-winrepair     # as dependency
poetry install                          # for local dev

# PDM
pdm add pve-winrepair
pdm install
```

## Install Directly from Git

```bash
pip install "git+https://github.com/bitranox/pve-winrepair"
```

## System Package Managers (Optional Distribution Channels)

- Use [fpm](https://fpm.readthedocs.io/) to repackage the Python wheel into `.deb` or `.rpm` for distribution via `apt` or `yum`/`dnf`.

All methods register the `pve-winrepair` command on your PATH.
