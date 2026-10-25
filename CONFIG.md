# Configuration

`pve-winrepair` reads its settings through
[`lib_layered_config`](https://github.com/bitranox/lib_layered_config): bundled defaults, then
configuration files, then `.env`, environment variables and `--set` on the command line, each layer
overriding the ones before it.

On a Proxmox node, put the settings in **`/etc/pve-winrepair/config.toml`**. That is all most
installs need. The rest of this page lists every setting, then explains the layers for the cases
where one file is not enough.

```toml
[ssh]
key = "/root/.ssh/id_guest"
user = "admin"

[guest]
subnet = "192.0.2.0/24"

[repair]
media_dir = "/var/lib/vz/winmedia/win11"
```

`pve-winrepair config` shows the merged result and, for each value, the layer and file it came from.
`repair` and `apply` validate all four sections before they do anything: an unknown key or a refused
value stops them with exit 78 and one `Error: <section>.<key>: <reason>` line per problem, for
example `Error: node.state_dir: must be an absolute path on the node (starting with /)`.

---

## Settings

Every key below is shipped with its default in `defaultconfig.d/20-winrepair.toml`, which also
documents each key. An empty text value means "not configured": it loads, and the command that needs
it refuses to run until it is set.

### `[ssh]`

The guest side of these settings (OpenSSH, the key file and its ACL) is set up as described in
[Preparing a Windows guest for SSH key access](docs/windows-guest-ssh.md).

**`key`** (default `""`): the private key file the node logs in to the guests with. Required by
`repair` and `apply`, which refuse to start without it. A guest that refuses this key is reached by
overriding it for one run: `PVE_WINREPAIR___SSH__KEY=/root/.ssh/id_other_guest pve-winrepair ...`.

**`user`** (default `"Administrator"`): the account the node logs in as. It must be an administrator
on the guest. Letters, digits, `_`, `.` and `-`, 1 to 64 characters; no `DOMAIN\` part.

**`strict_host_key_checking`** (default `true`): passed to ssh as `StrictHostKeyChecking=yes`, or `no`
when false. Keep it true. Set it false only for internal guests that are cloned and rebuilt from
templates, where every rebuild brings a new host key, and only on a network you trust: with `no`, ssh
accepts any key, a changed one included. `pve-winrepair config` currently shows this value as
`***REDACTED***`, because its name contains `key`; the value is still used.

**`known_hosts_file`** (default `"~/.ssh/known_hosts"`): the known_hosts file ssh reads and writes for
the guests, passed to ssh as written (ssh expands a leading `~` against the home of the account that
runs it). Keep it a real file, never `/dev/null`: that turns every connection into a first
connection, ssh then prints a "Permanently added" warning on every call, and with strict checking
on, no guest could ever be reached. A separate file such as `~/.ssh/known_hosts_guests` keeps the
guests' keys apart from the node's own. An empty value, whitespace and `"` are refused at load:
ssh's option parser splits the value at whitespace into several files. A `%` token such as `%h` is
ssh's own and stays usable here (`~/.ssh/known_hosts_%h` keeps one file per guest).

### `[guest]`

**`subnet`** (default `""`): the IPv4 LAN the node reaches the guests on, in CIDR or netmask form with
no host bits set (`192.0.2.0/24` or `192.0.2.0/255.255.255.0`). `repair` reads the guest's addresses
from the QEMU guest agent and drops loopback and link-local ones:

- With a subnet, it takes the first address inside it. When there is none yet, it waits 10 seconds
  and asks the agent again (each read may take up to 60 seconds), up to 30 reads in all, and then
  refuses the run.
- Empty, it takes the only remaining address at once and refuses a guest that reports several.

Set it. Without it, a guest that briefly reports only a container-switch address (a `172.x` address
of a Docker or Hyper-V switch, with the LAN lease not up yet) is taken at that address at once, and
a guest running Docker that reports both is refused on the first read. With the subnet set, both
cases wait for the LAN address, within that bound.

**`runner_tasks`** (default `[]`) and **`expected_runners`** (default `0`): no node command reads
these. They record, for guests that run CI runners, what an operator passes to the guest tool's
`verify-runners --task NAME --expected N` after a reboot (one `--task` per entry; `0` means any count
is fine). They are validated with the same rules that verb applies (task names of letters, digits,
`_`, `.` and `-`, 1 to 64 characters; a count from 0 to 999999, never `true`/`false`), so
`pve-winrepair config` shows only values the verb accepts.

### `[repair]`

**`media_dir`** (default `""`): the directory on the node with the Windows installation media,
unpacked as on the ISO, so that `setup.exe` and `sources/install.wim` sit at its top level.
Required by `repair`. Everything in it is copied to the guest's staging directory.

**`snapshot_name`** (default `"pre_winrepair"`): the Proxmox snapshot `repair` takes. A letter first,
then letters, digits, `_` and `-`, 2 to 40 characters. `--snapshot-name` overrides it for one run
and follows the same rule.

**`stage_free_gb`** (default `15.0`) and **`system_free_gb`** (default `25.0`): the free space, in
GiB (1024^3 bytes), that `repair` requires before it copies anything. The staging drive needs
`stage_free_gb` for the media; `C:` needs `system_free_gb` for the upgrade's own working set and
its rollback copy. When `C:` is the only usable drive it needs both. Each must be a finite number
greater than 0.

### `[node]`

**`state_dir`** (default `"/var/lib/pve-winrepair"`): where the node keeps its state, the repair
receipts `receipt-<vmid>.json`. An absolute path; `""`, a relative path and a leading `~` are
refused. Before anything else, `repair` and `apply` check that it is a directory, or that its
nearest existing parent is one, so a receipt write cannot fail hours into a run on a path that is a
file. A directory `pve-winrepair` creates gets mode 0700, each receipt 0600.

A receipt holds the build of the staged image and, from the same moment, the build and the
InstallDate the guest ran (`build_before`, `install_date_before`); every field is required, and
`apply` refuses a receipt that lacks one. When the image carries the build the guest already ran,
`apply` accepts the result only if the guest's InstallDate changed across the apply reboot (an
in-place upgrade writes it anew; a rollback lands on the same build). Otherwise the verdict is
REVERTED_OR_UNCHANGED and Windows Update stays held.

No setting binds `--ip` to a VM: `repair --ip` and `apply` always require one of the MACs of the
VM's `netN` lines in `qm config` to be among the guest's network adapters, and refuse the run
otherwise.

**`host`** (default `""`): the PVE node whose `qm` the tool drives over ssh. A host name or an IPv4
address: a letter or digit first, and no space, `;` or `@`, so ssh can never read it as an option, a
second word or a user. Empty means the machine running the tool is the node. `repair --node HOST`
and `apply --node HOST` override it for one run; a node named either way needs `ssh_key`, or the
run is refused before any call.

**`ssh_user`** (default `"root"`): the account this machine logs in as on the node. Letters, digits,
`_`, `.` and `-`, 1 to 64 characters, never starting with `-`.

**`ssh_key`** (default `""`): the private key file this machine logs in to the node with, passed to
ssh as written (ssh expands a leading `~`). It is not `[ssh] key`, which is the key for the guests;
the node connection never shares that key or user. The key also travels inside the `ProxyCommand`
that reaches a guest through the node, so `"` and `%` are refused at load (no quoting carries them
through that string); a space is fine.

**`known_hosts_file`** (default `"~/.ssh/known_hosts"`): the known_hosts file the remote node's host
key is checked against, passed to ssh as written (ssh expands a leading `~`). The check is strict:
a node whose key is missing from the file, or has changed, is refused before any call, so add the
node's key there first. It is not `[ssh] known_hosts_file`, which holds the guests' keys; the jump
through the node to a guest checks the node against this file too. An empty value, whitespace, `"`
and `%` are refused at load: ssh splits the value at whitespace, and expands a `%` token once more
in the jump, where even `%%` does not give a literal percent.

---

## Configuration Layers

Configuration is loaded and merged in the following order (lowest to highest precedence):

| Priority | Layer        | Description                                     |
|:--------:|--------------|-------------------------------------------------|
| 1        | **defaults** | Bundled with the package (`defaultconfig.toml`) |
| 2        | **app**      | System-wide settings for all machines           |
| 3        | **host**     | Machine-specific overrides                      |
| 4        | **user**     | User's personal settings                        |
| 5        | **.env**     | First `.env` found upward, else per-user `.env` |
| 6        | **env vars** | Environment variables                           |
| 7        | **CLI**      | Command-line `--set` flags (highest priority)   |

**Merge behavior**: Each layer only needs to specify values it wants to override. Unspecified values
inherit from lower layers.

---

## File Locations

### Platform-Specific Paths

| Layer    | Linux                                   | macOS                                                               | Windows                                               |
|----------|-----------------------------------------|---------------------------------------------------------------------|-------------------------------------------------------|
| defaults | (bundled with package)                  | (bundled with package)                                              | (bundled with package)                                |
| app      | `/etc/xdg/{slug}/config.toml`           | `/Library/Application Support/{vendor}/{app}/config.toml`           | `C:\ProgramData\{vendor}\{app}\config.toml`           |
| host     | `/etc/xdg/{slug}/hosts/{hostname}.toml` | `/Library/Application Support/{vendor}/{app}/hosts/{hostname}.toml` | `C:\ProgramData\{vendor}\{app}\hosts\{hostname}.toml` |
| user     | `~/.config/{slug}/config.toml`          | `~/Library/Application Support/{vendor}/{app}/config.toml`          | `%APPDATA%\{vendor}\{app}\config.toml`                |
| .env     | `~/.config/{slug}/.env` (fallback)      | `~/Library/Application Support/{vendor}/{app}/.env` (fallback)      | `%APPDATA%\{vendor}\{app}\.env` (fallback)            |

Every layer reads `config.toml` first and then the files in the `config.d/` directory next to it
(for the host layer: `hosts/{hostname}.d/`), in lexical order; a `config.d/` file may be TOML, YAML
or JSON. On Linux the app and host layers are read from `/etc/xdg/{slug}/` and then from
`/etc/{slug}/`, so a key in `/etc/pve-winrepair/config.toml` wins over the same key under
`/etc/xdg/pve-winrepair/`. `$XDG_CONFIG_HOME` replaces `~/.config` when it is set. The `.env` row is
a fallback: it is read only when no `.env` is found in the working directory or one of its parents.

### Path Placeholders

| Placeholder  | Linux           | macOS / Windows |
|--------------|-----------------|-----------------|
| `{slug}`     | `pve-winrepair` | -               |
| `{vendor}`   | -               | `bitranox`      |
| `{app}`      | -               | `pve-winrepair` |
| `{hostname}` | System hostname | System hostname |

### Concrete Examples

**Linux (the Proxmox node):**
- App config: `/etc/pve-winrepair/config.toml` (read after `/etc/xdg/pve-winrepair/config.toml`)
- Host config: `/etc/xdg/pve-winrepair/hosts/myserver.toml`
- User config: `~/.config/pve-winrepair/config.toml` (`/root/.config/...` for root)

**macOS:**
- User config: `~/Library/Application Support/bitranox/pve-winrepair/config.toml`

**Windows:**
- User config: `%APPDATA%\bitranox\pve-winrepair\config.toml`

---

## CLI Commands

### Global Options

These options apply to all commands and must be specified **before** the command name:

| Option                    | Description                                                               |
|---------------------------|---------------------------------------------------------------------------|
| `--version`               | Show version and exit.                                                    |
| `--profile NAME`          | Load configuration from a named profile (e.g., `production`, `test`).     |
| `--set SECTION.KEY=VALUE` | Override a configuration setting. Can be repeated for multiple overrides. |
| `--env-file PATH`         | Explicit `.env` file path. Skips the default upward directory search.     |
| `--traceback`             | Show full Python traceback on errors (useful for debugging).              |
| `--no-traceback`          | Hide traceback, show only error message (default).                        |

**Example usage:**

```bash
# Use a specific profile
pve-winrepair --profile production config

# Override settings at runtime (repeatable)
pve-winrepair --set repair.snapshot_name=pre_repair_2 repair --vmid 100
pve-winrepair --set lib_log_rich.console_level=DEBUG --set ssh.user=admin config

# Load configuration from an explicit .env file
pve-winrepair --env-file /etc/pve-winrepair/.env config

# Show full traceback for debugging
pve-winrepair --traceback config
```

---

### View Configuration

Display the merged configuration from all sources (defaults -> app -> host -> user -> .env -> env
vars), each value with the layer and file it came from.

#### Options Reference

| Option           | Required | Description                                 |
|------------------|:--------:|---------------------------------------------|
| `--format`       | No       | Output format: `human` (default) or `json`. |
| `--section NAME` | No       | Show only a specific section (e.g., `ssh`). |
| `--profile NAME` | No       | Load configuration for a specific profile.  |

An unknown `--section` exits 22 (`Error: Section 'nope' not found`); a configuration that does not
load exits 78.

#### Examples

```bash
# Show merged configuration from all sources
pve-winrepair config

# Output as JSON (useful for scripting)
pve-winrepair config --format json

# Show specific section only
pve-winrepair config --section repair

# Load configuration for a specific profile
pve-winrepair config --profile production

# Combine options
pve-winrepair config --profile staging --format json --section ssh
```

### Deploy Configuration Files

`config-deploy` writes a documented copy of the bundled defaults into a configuration layer, as a
starting point to edit. In the deployed `20-winrepair.toml` (the `[ssh] [guest] [repair] [node]`
settings) every key is commented out, with its default as the example value: the file documents the
settings and sets none of them, so the values in `/etc/pve-winrepair/config.toml` stay in force until
you uncomment a key. `40-layered-config.toml` and `90-logging.toml` are deployed with their keys
active. An install whose own configuration management writes `/etc/pve-winrepair/config.toml` does
not need `config-deploy`.

#### Options Reference

| Option             | Required | Description                                                                                                                   |
|--------------------|:--------:|-------------------------------------------------------------------------------------------------------------------------------|
| `--target`         | Yes      | Target layer: `app`, `host`, or `user`. Can be specified multiple times.                                                      |
| `--force`          | No       | Replace existing files whose content differs; the old file is kept as `<name>.bak`. Without this, existing files are skipped. |
| `--profile NAME`   | No       | Deploy to a profile-specific subdirectory (e.g., `profile/production/`).                                                      |
| `--permissions`    | No       | Set Unix permissions even when the configured `enabled` is false.                                                             |
| `--no-permissions` | No       | Disable permission setting; use system umask instead. Not combinable with a mode option.                                      |
| `--dir-mode MODE`  | No       | Override directory permissions (octal: `750` or `0o750`).                                                                     |
| `--file-mode MODE` | No       | Override file permissions (octal: `640` or `0o640`).                                                                          |

#### What each target writes (Linux)

| Target | Files written                                                                                                       |
|--------|---------------------------------------------------------------------------------------------------------------------|
| `app`  | `/etc/xdg/pve-winrepair/config.toml` plus `config.d/20-winrepair.toml`, `40-layered-config.toml`, `90-logging.toml` |
| `host` | `/etc/xdg/pve-winrepair/hosts/{hostname}.toml` plus `hosts/{hostname}.d/` with the same three files                 |
| `user` | `~/.config/pve-winrepair/config.toml` plus `config.d/` with the same three files                                    |

With `--profile NAME` the same files go under `profile/NAME/` of the target's directory, for example
`/etc/xdg/pve-winrepair/profile/production/config.toml`.

**The deployed logging and layered-config files hide the lower layers for their keys.**
`40-layered-config.toml` (`[lib_layered_config.default_permissions]`) and `90-logging.toml`
(`[lib_log_rich]`) are deployed with every key active, so whatever layer they land in decides those
keys. A `host` deploy (host beats app) or a `user` deploy as root (user beats app and host)
therefore puts the logging and deploy-permission settings back to their defaults, values for them
in `/etc/pve-winrepair/config.toml` included. The winrepair settings are not affected: their file is
deployed commented out, and a key you uncomment there wins over the app file for that key alone.
`app` is safe next to `/etc/pve-winrepair/config.toml`: it writes under `/etc/xdg/`, which is read
first. Check the result with `pve-winrepair config`, which names the file each value came from.

#### Basic Examples

```bash
# The system-wide defaults to edit (as root)
pve-winrepair config-deploy --target app

# The defaults for this host only
pve-winrepair config-deploy --target host

# A personal copy in ~/.config/pve-winrepair/
pve-winrepair config-deploy --target user

# Several targets at once
pve-winrepair config-deploy --target user --target app

# Replace files that differ from what the deploy writes (keeps <name>.bak)
pve-winrepair config-deploy --target app --force

# Into a profile directory
pve-winrepair config-deploy --target app --profile production
```

With `--force`, a file whose content differs from what the deploy writes is replaced and the old
file is kept as `<name>.bak` (numbered, `<name>.bak.1` and so on, when a backup already exists); a
file whose content is already identical is left as it is, mode included. When nothing differs,
`config-deploy --force` writes nothing and says so. The `app` and `host` targets need write access
to `/etc/xdg/`, which on a node means root; a target that may not be written exits 13.

#### File Permissions (POSIX Only)

On Linux and macOS, `config-deploy` sets Unix file permissions based on the target layer. Windows uses ACLs and ignores these settings.

| Target | Directory Mode      | File Mode           | Description                             |
|--------|:-------------------:|:-------------------:|-----------------------------------------|
| `app`  | `0o755` (rwxr-xr-x) | `0o644` (rw-r--r--) | World-readable for system-wide config   |
| `host` | `0o755` (rwxr-xr-x) | `0o644` (rw-r--r--) | World-readable for host-specific config |
| `user` | `0o700` (rwx------) | `0o600` (rw-------) | Private to user only                    |

**Permission options:**

```bash
# Skip permission setting entirely (use system umask)
pve-winrepair config-deploy --target user --no-permissions

# Override directory mode (octal)
pve-winrepair config-deploy --target user --dir-mode 750

# Override file mode (octal)
pve-winrepair config-deploy --target user --file-mode 640

# Both overrides together
pve-winrepair config-deploy --target user --dir-mode 750 --file-mode 640

# Octal formats: both "750" and "0o750" are accepted
pve-winrepair config-deploy --target user --dir-mode 0o750
```

A mode must be a plain octal literal (`750` or `0o750`; no sign, whitespace, `_` or other base)
within `0`..`0o7777`. Because the deployed files can hold credentials, a mode is also refused when
it sets the setuid, setgid or sticky bit, grants group or world write, puts an execute bit on a
file, or takes the owner's access away (a directory needs owner `rwx`, a file owner `rw`). Group
write is refused like world write because a group can hold every local account (on macOS all of
them share `staff`), and a configuration file never needs `x`. A refused mode is a usage error
(exit 2) that names the offending bits, and nothing is written.

**Configurable defaults:**

Permission defaults can be customized in `[lib_layered_config.default_permissions]`:

```toml
[lib_layered_config.default_permissions]
# Values: octal strings ("0o755", "755"); a bare integer is refused (see below)
app_directory = "0o755"
app_file = "0o644"
host_directory = "0o755"
host_file = "0o644"
user_directory = "0o700"
user_file = "0o600"

# Set to false to disable permission setting by default
enabled = true
```

`config-deploy` decides none of this itself: it passes its options and any `--set` of this
section to lib_layered_config, which applies each target's own layer modes. The library reads the
section from the bundled defaults, the configuration files this deploy does not overwrite and the
environment, with the `--set` values laid over them. It never reads `.env` for it (neither one
found from the working directory nor an explicit `--env-file`), so a `.env` can neither change a
deployed mode nor block a deploy. `--dir-mode`/`--file-mode` override the configured modes for
every target, and a key left out falls back to the layer default in the table above. Without
`--permissions`/`--no-permissions`, `enabled` decides; `enabled = false` behaves like
`--no-permissions`, and `--permissions` sets the modes anyway.

A configured mode follows the same rules as `--dir-mode`/`--file-mode`: a plain octal STRING
(`"0o750"`, `"750"`), never setuid/setgid/sticky, group or world write, an execute bit on a file,
or a directory without owner `rwx` / a file without owner `rw`. A bare integer is refused rather
than reinterpreted: TOML `user_file = 400`, `--set ...user_file=400` and an environment value `400`
all arrive as the DECIMAL integer 400, which is `0o620`, not the owner-read-only mode the digits
suggest. Quote it in TOML (`user_file = "640"`); in an environment variable or `--set`, use the
`0o` prefix (`0o640`), which is never read as a number. `enabled` must be a real boolean
(`true`/`false` in TOML, an environment variable or `--set`); `"no"`, `"off"`, `0` or `1` are
refused rather than read as one. An unknown key in the section is refused rather than ignored.
Any violation stops `config-deploy` before it writes anything, with exit 78, one line per problem
naming the key and where it was set, and a hint, for example:

```text
Error: lib_layered_config.default_permissions.user_file: a bare integer is read as decimal (400 = 0o620); write the mode as an octal string: "0o640" (quoted) in a file, 0o640 in the environment or a runtime override (such as an application's --set) (source: env)
Hint: to deploy anyway, pass both --dir-mode and --file-mode (the built-in modes are 700 and 600 for user, 755 and 644 for app and host); --no-permissions also deploys, but leaves every mode to the umask, which can make a user file that holds secrets readable by other accounts.
```

The same refusal applies when a file the library reads cannot be loaded: `config-deploy` never
falls back to the layer defaults, which may be wider than what was configured. A refused `--set`
of the section names `(source: override)` and has no hint, since no option gets past it: fix or
drop the `--set`. The files a deploy writes are never read for it, so `config-deploy --force`
replaces a destination that carries a bad value, or does not parse at all, without further options.


### Generate Example Configuration Files

`config-generate-examples` writes lib_layered_config's example layout: one placeholder file per
layer location plus a `.env.example`. The files show WHERE each layer reads from and hold a generic
`[service]` placeholder, not this application's settings. For a file with this application's
defaults and every key documented, use `config-deploy`.

#### Options Reference

| Option              | Required | Description                                                         |
|---------------------|:--------:|---------------------------------------------------------------------|
| `--destination DIR` | Yes      | Directory to write example files.                                   |
| `--force`           | No       | Overwrite existing files. Without this, existing files are skipped. |

#### Examples

```bash
# Generate examples in a specific directory
pve-winrepair config-generate-examples --destination ./examples

# Overwrite existing example files
pve-winrepair config-generate-examples --destination ./examples --force
```

On Linux it writes `xdg/pve-winrepair/config.toml`, `xdg/pve-winrepair/hosts/your-hostname.toml`,
`home/pve-winrepair/config.toml`, `home/pve-winrepair/config.d/10-override.toml` and
`.env.example` below the destination.

### Runtime Overrides

Use `--set` to override configuration values without modifying files. This option:
- Has the **highest precedence** among the configuration layers; for logging, lib_log_rich's own `LOG_*` variables still override it
- Can be **repeated** to set multiple values
- Must appear **before** the command name

#### Syntax

```
--set SECTION.KEY=VALUE
--set SECTION.SUBSECTION.KEY=VALUE
```

#### Examples

```bash
# Override a single value
pve-winrepair --set lib_log_rich.console_level=DEBUG config

# Another snapshot name and more poll time for one repair
pve-winrepair --set repair.snapshot_name=pre_repair_2 repair --vmid 100 --hours 8

# Override multiple values
pve-winrepair --set lib_log_rich.console_level=DEBUG --set lib_log_rich.console_format_preset=short config

# Override nested values
pve-winrepair --set lib_log_rich.payload_limits.context_max_keys=30 config

# Override with JSON arrays/objects (use single quotes around the value)
pve-winrepair --set lib_log_rich.scrub_patterns='{"api_key": ".+"}' config

# Combine with profile
pve-winrepair --profile production --set lib_log_rich.console_level=DEBUG config
```

#### Supported Value Types

| Type        | Example                                                       |
|-------------|---------------------------------------------------------------|
| String      | `--set section.key=value`                                     |
| Integer     | `--set section.timeout=30`                                    |
| Float       | `--set section.ratio=0.5`                                     |
| Boolean     | `--set section.enabled=true` or `--set section.enabled=false` |
| JSON Array  | `--set section.hosts='["a.com", "b.com"]'`                    |
| JSON Object | `--set section.metadata='{"key": "value"}'`                   |

---

## Profiles

Profiles provide isolated configuration namespaces for different environments (e.g., `production`, `staging`, `test`).

### Profile Name Requirements

Profile names are validated for security and cross-platform compatibility:

| Rule                   | Description                                                                               |
|------------------------|-------------------------------------------------------------------------------------------|
| **Maximum length**     | 64 characters                                                                             |
| **Allowed characters** | ASCII letters (`a-z`, `A-Z`), digits (`0-9`), hyphens (`-`), underscores (`_`)            |
| **Start character**    | Must start with a letter or digit (not `-` or `_`)                                        |
| **Reserved names**     | Windows reserved names rejected: `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9` |
| **Path safety**        | No path separators (`/`, `\`) or traversal sequences (`..`)                               |

**Valid examples:** `production`, `staging-v2`, `test_env`, `dev01`

**Invalid examples:** `../etc` (path traversal), `-invalid` (starts with hyphen), `CON` (Windows reserved)

### Which Layers Are Affected?

| Layer    | Affected by Profile? | Notes                                                                        |
|----------|:--------------------:|------------------------------------------------------------------------------|
| defaults | No                   | Always loaded from package                                                   |
| app      | Yes                  | Uses `profile/<name>/` subdirectory                                          |
| host     | Yes                  | Uses `profile/<name>/` subdirectory                                          |
| user     | Yes                  | Uses `profile/<name>/` subdirectory                                          |
| .env     | Fallback only        | The per-user fallback `.env` uses `profile/<name>/`; one found upward is not |
| env vars | No                   | Environment                                                                  |
| CLI      | No                   | Command line                                                                 |

### Profile Path Examples

**Without profile:**
- `~/.config/pve-winrepair/config.toml`

**With profile `production`:**
- `~/.config/pve-winrepair/profile/production/config.toml`

### Reading Behavior

Profile directories are **separate namespaces**. Configuration deployed with a profile is only visible when reading with that same profile.

| Command                       | Sees `app` layer?                  | Sees `user` layer?                 |
|-------------------------------|------------------------------------|------------------------------------|
| `config` (no profile)         | Only if deployed without profile   | Only if deployed without profile   |
| `config --profile production` | Only if deployed with `production` | Only if deployed with `production` |

**Example**: If you deploy `app` with `--profile production` but `user` without a profile:

| Command                       | app layer | user layer |
|-------------------------------|:---------:|:----------:|
| `config`                      | No        | Yes        |
| `config --profile production` | Yes       | No         |

---

## Environment Variables

Configuration can be overridden via environment variables using two methods:

### Method 1: Native lib_log_rich Variables

For logging configuration, use the native `LOG_*` variables (highest precedence):

```bash
LOG_CONSOLE_LEVEL=DEBUG pve-winrepair info
LOG_ENABLE_GRAYLOG=true LOG_GRAYLOG_ENDPOINT="logs.example.com:12201" pve-winrepair info
```

### Method 2: Application-Prefixed Variables

For any configuration section, use the format: `<PREFIX>___<SECTION>__<KEY>=value`

```bash
PVE_WINREPAIR___SSH__KEY=/root/.ssh/id_other_guest pve-winrepair repair --vmid 100
PVE_WINREPAIR___REPAIR__STAGE_FREE_GB=20 pve-winrepair config --section repair
PVE_WINREPAIR___LIB_LOG_RICH__CONSOLE_LEVEL=DEBUG pve-winrepair info
```

`PVE_WINREPAIR___SSH__KEY` is the usual way to reach a guest that refuses the configured key, for
one run, without touching the file.

**Separator reference:**
- `___` (triple underscore) - separates prefix from section
- `__` (double underscore) - separates section from key

---

## .env File Support

A `.env` file holds overrides as `SECTION__KEY=value` lines (no prefix), plus lib_log_rich's own
`LOG_*` variables:

```bash
# .env
REPAIR__SNAPSHOT_NAME=pre_repair_2
LOG_CONSOLE_LEVEL=DEBUG
```

By default, the configuration loader reads ONE `.env` as its `.env` layer: the first one from the
current directory up to the filesystem root (past any `pyproject.toml` or `.git`, so a checkout
nested in another reads the outer one's `.env`), or, when there is none, the per-user fallback
`.env` (see the `.env` row of the layer table above). On a node, that walk starts in the
directory you run `pve-winrepair` from, so a stray `.env` there or in any parent directory changes
the settings; `pve-winrepair config` names the `.env` a value came from.

Logging reads the `LOG_*` lines of that same file (the `--env-file` when one is given; when the
configuration did not load, the first `.env` on the same upward walk) and copies only those into
the environment, never over a variable that is already set. No other `.env` line reaches the
environment, so a `.env` cannot act as the environment layer for a later configuration load.

To load a specific `.env` file instead, use `--env-file`:

```bash
# Load from an explicit path (skips upward directory search)
pve-winrepair --env-file /etc/pve-winrepair/.env config
```

The file must exist and be readable; Click validates this before the command runs.

---

## Default Configuration

The `defaultconfig.toml` and files in `defaultconfig.d/` (bundled with the package) provide baseline values. These serve as the fallback when no external configuration files are deployed. The bundled `20-winrepair.toml` keeps its keys active as this defaults layer; only the copy `config-deploy` writes has them commented out.

---

## Customization Best Practices

`config-deploy --force` replaces a deployed file whose content differs (keeping the old one as
`<name>.bak`), so an edit made to a deployed `config.d/` file does not survive a forced redeploy.
Two ways keep your values safe:

- Keep them in `/etc/pve-winrepair/config.toml`. `config-deploy` never writes that file.
- Or put an override file with a high number into the `config.d/` directory of the layer you use,
  for example `/etc/pve-winrepair/config.d/999-site.toml`. A layer reads `config.toml` first and then
  its `config.d/` files in lexical order, so a `999-` file loads after the deployed `20-`, `40-`
  and `90-` files and wins over them. `config-deploy` never writes a `999-` file.

A file placed directly next to `config.toml` (outside `config.d/`) is never read: each layer reads
only `config.toml` plus its `config.d/` files.

**Example `999-site.toml`:**

```toml
[repair]
media_dir = "/var/lib/vz/winmedia/win11"

[lib_log_rich]
console_level = "DEBUG"
```

---

## Library Use

The merged configuration is also available from Python:

```python
import pve_winrepair

config = pve_winrepair.get_config()
print(config.as_dict()["repair"])

# One section, with a default when it is absent
ssh = config.get("ssh", default={})
```
