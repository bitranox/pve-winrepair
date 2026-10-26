# Module Reference: Architecture & File Index

## Status

Describes the modules as they are in the source tree. Update it with every change that adds,
moves or removes a module, a CLI option or a public name.

---

## Related Files

### Domain Layer
- `src/pve_winrepair/domain/acl.py`  -  Who may write a directory, read from its SDDL security descriptor (`parse_sddl` into `SddlAce` with its `AceKind` and `AceFlag` set, `write_problems`, `trusted_writers`, `TRUSTED_WELL_KNOWN`; the alias `LA` counts as the ssh user only when its SID ends in -500); the node's check of the ssh user's profile before a copy of the tool goes there
- `src/pve_winrepair/domain/addresses.py`  -  `lan_address` picks the guest's LAN address out of what its agent reports (the first one in `[guest] subnet`; without a subnet the only candidate, several refused with `AmbiguousAddressError`); `normalise_mac` puts a MAC in `AA:BB:CC:DD:EE:FF` form, and `MacAddress` is that form as a boundary model's field type (a value that is no MAC is refused)
- `src/pve_winrepair/domain/enums.py`  -  Type-safe enums (`OutputFormat`, `DeployTarget`, `DriveLetter`, `MediaChoice`)
- `src/pve_winrepair/domain/envelope.py`  -  The guest tool's answer contract: `parse_answer` validates the one envelope line once, in strict JSON mode, into a `GuestAnswer[T]` (with `SkippedItem`s; exit 2 as `InternalErrorAnswer`) and checks `ok` against the payload's verdict; `describe_validation_error`; the error types (`GuestNoAnswerError`, `GuestInternalError`, `GuestProtocolError`, `GuestPushError`, `UnsafeArgumentError`), `check_argument`, `RunState`, `READ_FAILURES` and `WU_HELD_HINT`; starts no process
- `src/pve_winrepair/domain/guest_answers.py`  -  One frozen model, closed to unknown fields, per guest subcommand's payload (`BuildAnswer`, `PrepareAnswer`, `LaunchAnswer`, ...), their verdict and status enums (`StateVerdict`, `LaunchVerdict`, `PrepareGate`, ...) and `GuestCommand`, the subcommand names
- `src/pve_winrepair/domain/errors.py`  -  Domain exceptions (`ConfigurationError`)
- `src/pve_winrepair/domain/guest_tool.py`  -  `PackedTool` (the node's packed tool, its content address and sha256) and `Pushed` (what a push left on the guest)
- `src/pve_winrepair/domain/node_link.py`  -  `NodeLink` (host, ssh user, key, known_hosts file) reaches a PVE node this machine does not run on: `ssh_argv` sends a remote command to the node as one `shlex`-quoted word with a strict host-key check against that file (`forward_agent=True` adds `-A`, only for the node-side media copy), `proxy_command` is the `ProxyCommand` that carries a guest connection through the node with the node key (`shlex.join` on POSIX, the two path words double-quoted on Windows; `windows=None` = this machine), and `jumped` wraps a `Runner` so every ssh and scp goes through it; building a link refuses a key or known_hosts path that `ssh_paths` refuses; starts no process
- `src/pve_winrepair/domain/receipt.py`  -  `RepairReceipt`, the image build a repair's prepare step measured with the guest's `build_before` and `install_date_before` (all required; `same_build`), `GuestBuild` (CurrentBuild, UBR, InstallDate; `from_answer`), `BuildPair` (`build_before`, stored as the array `[build, ubr]`), and `ReceiptError`
- `src/pve_winrepair/domain/report.py`  -  `Report` collects a run's steps and hands each to `on_step`; `RunExit`, `RunResult`, `RunVerdict`, the `Step` model with its `StepName`; flags a run that leaves Windows Update held
- `src/pve_winrepair/domain/settings.py`  -  Node CLI settings models (`SshSettings`, `GuestSettings`, `RepairSettings`, `NodeSettings`, `Settings`), the `SnapshotName` type and `default_state_dir` (the per-OS `[node] state_dir` default); see Settings below
- `src/pve_winrepair/domain/ssh_paths.py`  -  `known_hosts_problem` and `jump_key_problem`: why ssh would misread a known_hosts or node-key path (empty, whitespace, `"`, a `%` token that the jump expands once more), or None; the reason never repeats the value
- `src/pve_winrepair/domain/vm_config.py`  -  `parse_vm_config` reads `qm config` once into a `VmConfig` (its `VmDisk`s with storage and `DiskMedia`, a `tpmstate0`, a launcher `--tpm`, the `netN` MACs); `VmConfigRead` is one such call with its exit code; `parse_snapshot_names` reads `qm listsnapshot`; `parse_snapshot_result` reads a `qm snapshot` call into a `SnapshotResult` (exit code, stderr, whether PVE froze the guest filesystem)

### Application Layer
- `src/pve_winrepair/application/ports.py`  -  Protocol definitions the adapters satisfy: the configuration and logging callables, `LoadSettings`, `GuestPort` (`ask` runs one subcommand and returns its typed answer), `NodePort` (`vm_config`, `snapshots` and `snapshot` return the parsed `qm config`, `qm listsnapshot` and `qm snapshot`; `check_link` is why a linked node cannot be used, or None; `media` is a run's media in a directory, on the node or on this machine), `MediaSource` (`check` is why the media cannot be used, or None; `copy_into` copies every media entry into a guest directory), `ReceiptStore` (`other_vm` is the VM a receipt file of another VM names, or None; a `--receipt` file that is no valid receipt is a `ReceiptError` and is never deleted), `MakeNode` (the node from the `[ssh]` settings and an optional `NodeLink`), `MakeReceipts` (the store in `[node] state_dir`, or in the one `--receipt` file)
- `src/pve_winrepair/application/guest_state.py`  -  `read_run_state`, the live-run gate both use cases read before they stop, relaunch or restage a guest; `read_guest_build`, the guest's build and InstallDate
- `src/pve_winrepair/application/guest_identity.py`  -  `check_guest_is_vm`: with `--ip`, a MAC of the VM's `qm config` must be among the guest's `nic-macs` (membership, both sides normalised); `GuestMismatchError`
- `src/pve_winrepair/application/repair.py`  -  `run_repair`: live-run check (with `--ip`: the MAC check first), Windows Update hold, vTPM, snapshot, push, MAC check again with `--ip`, stage root, locked staging, media copy, WIM gate, build before, receipt, launch, poll (a `--stage-only` run ends on a `staged` step flagged `wu_held`); `media_source` picks the media (`[repair] media_dir` or `local_media_dir`, by `RepairRequest.media`) and refuses them unconfigured, missing or empty before any VM call; `refuse_another_vms_receipt` refuses, next and still before any VM call, a receipt file holding another VM's receipt, or a `--receipt` file that is no valid receipt; `RepairRequest`, `RepairError`
- `src/pve_winrepair/application/apply.py`  -  `run_apply`: receipt, MAC check, run gate, staged-OS gate, clean stop and start, build check against the receipt (same-build media: InstallDate must change) from a verified profile copy, Windows Update release; `ApplyRequest`, `ApplyError`
- `src/pve_winrepair/application/vm.py`  -  `vm_status` reads `qm status` into a `VmStatus` (anything else is `UnknownVmStatusError`); the bounded `wait_status` polls through a failed read and ends with `VmStatusTimeoutError`; both errors are `VmStatusError`s

### Adapters Layer
- `src/pve_winrepair/adapters/config/loader.py`  -  Configuration loading with LRU caching; `NOT_SENSITIVE` names the keys `config` shows unredacted
- `src/pve_winrepair/adapters/config/deploy.py`  -  Configuration deployment: stages the bundled defaults in a temporary directory with `20-winrepair.toml` commented out (`DOCUMENTATION_ONLY`, `commented_settings`) and hands that copy to lib_layered_config's `deploy_config`
- `src/pve_winrepair/adapters/config/display.py`  -  Configuration display (TOML/JSON output, redaction)
- `src/pve_winrepair/adapters/config/overrides.py`  -  CLI `--set` override parsing and deep-merge
- `src/pve_winrepair/adapters/config/settings.py`  -  `load_settings` validates the `[ssh] [guest] [repair] [node]` sections into `Settings`; `SettingsError` carries one `<section>.<field>: <reason>` line per problem
- `src/pve_winrepair/adapters/guest_ssh.py`  -  The guest tool over ssh: `Guest` checks the ssh user's profile, pushes the packed tool to its content address (`push_tool`) or stages a verified profile copy (`stage_tool`), runs one subcommand (`ask`) and hands the answer to `parse_answer`; `ssh_options` turns `SshSettings` into ssh's `-o` options; `TOOL_DIR` is the packed tool shipped in `adapters/guest_tool/`
- `src/pve_winrepair/adapters/guest_tool/winrepair_guest.ps1`  -  The packed guest tool, a committed artefact (`make custom pack` writes it)
- `src/pve_winrepair/adapters/node.py`  -  `Node`, the PVE node a run uses: one runner for `qm` and every guest, the clock and sleep, `qm config`, `qm listsnapshot` and `qm snapshot` parsed where they answer; with a `NodeLink` it is a remote node, `qm` runs there over ssh and every guest call is jumped through it, and `check_link` proves it usable in one round trip (`command -v qm`: it answers, accepts the key and host key, has `qm`), else names why in ssh's own words; `media` is a run's media (`NodeMedia` on a linked node when they come from the node, else `LocalMedia`); `run` is the production runner
- `src/pve_winrepair/adapters/media.py`  -  `LocalMedia`: the media in a directory on this machine, refused missing or empty, every entry copied in name order by the guest's scp (through the node when it is remote); `NodeMedia`: the media in a directory on a remote node, checked with `ssh-add -l` (an agent holding a key) and one `ssh -A` call (the forwarded agent arrived, the directory exists and is not empty), copied node -> guest by the node's own scp with the forwarded key (no `IdentitiesOnly`, the node's own known_hosts)
- `src/pve_winrepair/adapters/receipts.py`  -  `FileReceiptStore`: one receipt per VM at `<state_dir>/receipt-<vmid>.json`, or in the one file `--receipt` names, replaced atomically, 0600 in a 0700 directory; `other_vm` is the VM such a file names when it is another one
- `src/pve_winrepair/adapters/logging/setup.py`  -  lib_log_rich initialization; takes only the `LOG_*` lines of a `.env`, and raises `InvalidLoggingConfigError` for a refused `[lib_log_rich]` value or `LOG_*` variable, after starting logging with its defaults (and without the `LOG_*` variables only when one of them is refused); `check_logging_config` refuses another configuration's logging settings through lib_log_rich's `validate_config`, without touching the running runtime
- `src/pve_winrepair/adapters/cli/`  -  CLI adapter package:
  - `__init__.py`  -  Public facade
  - `constants.py`  -  Shared constants
  - `safe_console.py`  -  Encode-safe terminal output; use `safe_console.echo` instead of `click.echo`
  - `exit_codes.py`  -  POSIX exit codes (ExitCode IntEnum)
  - `context.py`  -  Click context helpers (`CLIContext`) and the traceback preference state
  - `config_load.py`  -  Configuration load for the CLI; records a load failure, `require_config` refuses with exit 78, `check_logging` checks the logging settings of a configuration reloaded by `config --profile`, refusing them as the root does
  - `root.py`  -  Root command group
  - `main.py`  -  Entry point
  - `param_types.py`  -  Click parameter types of the run options: `PositiveFiniteFloat` (`--hours`, `--apply-minutes`), `StorageId` (`--tpm-storage`), `NodeHost` (`--node`, held to `[node] host`'s rule, empty refused), `Ipv4Address` (`--ip`, an `IPv4Address`), `WindowsDrive` (`--stage-root`, a `DriveLetter`)
  - `typed_click.py`  -  Strictly typed wrappers for rich_click's `option`, `version_option` and `get_current_context`
  - `commands/__init__.py`  -  Re-exports every command (`cli_repair`, `cli_apply`, `cli_guest_tool`, `cli_config`, ...)
  - `commands/info.py`  -  info command
  - `commands/config.py`  -  config, config-deploy, config-generate-examples commands
  - `commands/repair.py`  -  `repair --vmid N [--stage-only] [--snapshot-name S] [--hours H] [--ip IP] [--node HOST] [--receipt FILE] [--media node|local] [--stage-root X:] [--tpm-storage S] [--json]`; `--snapshot-name` defaults to `[repair] snapshot_name` and is validated by its rule, `--media` to `[repair] media_source`
  - `commands/apply.py`  -  `apply --vmid N --ip IP [--node HOST] [--receipt FILE] [--apply-minutes M] [--json]`
  - `commands/guest_tool.py`  -  `guest-tool path` (the packed tool) and `guest-tool sha256` (`<sha256>  <content address>`); neither reads the configuration
  - `commands/runs.py`  -  What `repair` and `apply` share: settings (exit 78), the checks before any call (`[ssh] key` set, the receipt's directory (`[node] state_dir`, or the `--receipt` file's) a directory or creatable as one, the remote node `--node` or `[node] host` names (`resolve_link`: `[node] ssh_key` set) usable (`check_link`); exit 1), steps and progress lines on stderr, the `--json` envelope `{ok, command, vmid, verdict, steps}` (a `RunEnvelope` for a `RunCommand`) or `vm <vmid>: <verdict>` on stdout; exit 0 OK, 1 refused, 2 internal

### Adapters Layer (In-Memory / Testing)
- `src/pve_winrepair/adapters/memory/__init__.py`  -  Public facade + Protocol conformance assertions
- `src/pve_winrepair/adapters/memory/config.py`  -  In-memory config adapters
- `src/pve_winrepair/adapters/memory/logging.py`  -  In-memory logging (a quiet lib_log_rich runtime for tests)

### Composition Layer
- `src/pve_winrepair/composition/__init__.py`  -  Wires adapters to ports (`AppServices`, `build_production`); `build_testing(make_node=..., make_receipts=...)` takes a node on a fake runner, and its default node refuses to run anything

### Entry Points
- `src/pve_winrepair/entry.py`  -  Console-script entry point; wires production services before invoking the CLI
- `src/pve_winrepair/__main__.py`  -  Thin shim for `python -m`
- `src/pve_winrepair/__init__.py`  -  Public API exports (`get_config`, `print_info`)
- `src/pve_winrepair/__init__conf__.py`  -  Package metadata constants

### Package Facades
- `src/pve_winrepair/domain/__init__.py`  -  Re-exports `ConfigurationError`, `DeployTarget`, `OutputFormat`
- `src/pve_winrepair/application/__init__.py`  -  Re-exports the configuration and logging ports
- `src/pve_winrepair/adapters/__init__.py`  -  Layer docstring only
- `src/pve_winrepair/adapters/config/__init__.py`  -  Re-exports the configuration adapter functions (`get_config`, `deploy_configuration`, `display_config`, `apply_overrides`, ...)
- `src/pve_winrepair/adapters/logging/__init__.py`  -  Re-exports the logging setup

### Guest Tool (`src/pve_winrepair_guest/`, runs on the Windows guest)

Every payload a subcommand emits is a frozen `envelope.Report` model whose verdicts and statuses
are str enums; each subcommand parses its argparse namespace into one args model.

- `src/pve_winrepair_guest/__init__.py`  -  Empty on purpose: the packer executes every parent `__init__.py` on the guest
- `src/pve_winrepair_guest/winrepair_guest.py`  -  The entry script: one subcommand per run (`default_commands`), one JSON envelope on stdout, exit 0 ok, 1 refused, 2 internal error
- `src/pve_winrepair_guest/envelope.py`  -  The tool's output contract: `Report`, the frozen base of every payload; the `Envelope` model and its one-line ASCII `render`; `Outcome`, `Skip`, `InternalError` and the exit code they imply
- `src/pve_winrepair_guest/probes.py`  -  The read-only probes: `detect-lp-defect`, `drives`, `verify-runners`, `build`, `staged-os`, `servicing-active`, `setup-alive`, `state`, `nic-macs`
- `src/pve_winrepair_guest/wu.py`  -  `quiesce-wu` and `restore-wu`, and the bounded Windows Update search probe (pwshpy `get_windows_update`)
- `src/pve_winrepair_guest/lockdown.py`  -  `lock-dirs` and the protected DACL that keeps non-admins away from what the SYSTEM task executes
- `src/pve_winrepair_guest/upgrade.py`  -  `prepare` (the WIM gate and the compat waiver), `launch` (the trigger-less SYSTEM task) and `upgrade-run` (setup.exe, the state log and its marker)

### Scripts
- `scripts/pack_guest.py`  -  Packs the guest tool into the committed artefact with pwshpy (`make custom pack`); `--check` exits 1 when the artefact is stale

### Configuration Defaults
- `src/pve_winrepair/adapters/config/defaultconfig.toml`  -  Base defaults
- `src/pve_winrepair/adapters/config/defaultconfig.d/20-winrepair.toml`  -  Node CLI settings defaults (`[ssh] [guest] [repair] [node]`)
- `src/pve_winrepair/adapters/config/defaultconfig.d/40-layered-config.toml`  -  lib_layered_config integration docs
- `src/pve_winrepair/adapters/config/defaultconfig.d/90-logging.toml`  -  Logging defaults

### Tests

Helpers and fixtures:
- `tests/conftest.py`  -  Shared fixtures (see Test Fixtures below)
- `tests/cli_fakes.py`  -  The command name and message of the `failing_command` fixture, which the tests assert on
- `tests/guest_fakes.py`  -  A fake ssh/scp runner answering with the guest tool's real envelopes, plus fake `qm` and clock, the whole-run guests of a repair and an apply, and `run_cli` (the real `main()` with a node on the fake runner)
- `tests/win32_fakes.py`  -  In-memory stand-ins for the pywin32 modules the guest tool calls
- `tests/json_paths.py`  -  Typed reads of a parsed JSON envelope
- `tests/build_wim_fixture.py`  -  Builds the small WIM fixture from a real `install.wim`
- `tests/fixtures/install_wim_header_xml.bin`  -  The WIM fixture: a header plus the image XML
- `tests/fixtures/packed_tool/winrepair_guest.ps1`  -  A small stand-in for the packed tool, for the push tests

Node CLI and its layers:
- `tests/test_acl.py`  -  Which SDDL descriptors let someone else write the ssh user's profile
- `tests/test_addresses.py`  -  Picking the guest's LAN address out of what its agent reports, and a MAC's normal form
- `tests/test_apply.py`  -  The apply use case's gates and its whole run, through the ssh runner seam
- `tests/test_envelope.py`  -  The envelope contract: the arguments it refuses, how an answer is read, its typed fields
- `tests/test_guest_ssh.py`  -  The ssh adapter: the argv it builds from `SshSettings`, the profile check, the push and its hashes, the profile copy
- `tests/test_media.py`  -  `LocalMedia`: its refusals of a missing and an empty directory, and the copy of every entry in name order; `NodeMedia`: the agent and node check with each refusal, and the node-side copy's argv, timeout and failures
- `tests/test_node.py`  -  The node bundle: one runner for `qm` and every guest, and the port the use cases take
- `tests/test_node_link.py`  -  The ssh argv to a remote node (one quoted word, strict host key, `-A` only when asked), the `ProxyCommand` per platform, and the jump through the node
- `tests/test_receipts.py`  -  The repair receipt and the file store that keeps one per VM in `[node] state_dir`, or in one `--receipt` file
- `tests/test_repair.py`  -  The repair use case's steps and its whole run, through the ssh runner seam
- `tests/test_settings.py`  -  Settings models and `load_settings`: shipped defaults, refusals by field, the env override end to end
- `tests/test_settings_dotenv_numbers.py`  -  Digit-only `.env` values reach every text setting as the text the operator wrote
- `tests/test_ssh_paths.py`  -  The ssh path rules: the known_hosts and node-key characters no quoting carries
- `tests/test_vm_config.py`  -  Reading `qm config` and `qm listsnapshot` output, against the line shapes PVE prints

CLI:
- `tests/test_cli_apply.py`  -  `apply` through `main()`: the receipt from `[node] state_dir` or `--receipt`, refusals before any call, output and exit codes
- `tests/test_cli_config.py`  -  `config`, `config-deploy`, `config-generate-examples` commands
- `tests/test_cli_config_errors.py`  -  A configuration that cannot be loaded: who reports it, and who still runs
- `tests/test_cli_core.py`  -  Traceback, main entry, help, info, unknown command, the registered command set
- `tests/test_cli_env_file.py`  -  `--env-file` path passing, validation and value override
- `tests/test_cli_exit_codes.py`  -  Exit codes through the CLI
- `tests/test_cli_guest_tool.py`  -  `guest-tool path` and `guest-tool sha256`
- `tests/test_cli_main_exit.py`  -  Exit codes and stderr through the real `main()` entry point
- `tests/test_cli_overrides.py`  -  `--set` through the CLI
- `tests/test_cli_repair.py`  -  `repair` through `main()`: options, settings, refusals before any call, progress lines on stderr, output and exit codes
- `tests/test_cli_validation.py`  -  Profile name validation

Configuration and logging:
- `tests/test_cache_effectiveness.py`  -  Configuration loading returns consistent (cached) results
- `tests/test_config_overrides.py`  -  `--set` parsing tests
- `tests/test_config_deploy_layers.py`  -  A `host` or `user` deploy leaves the app file's winrepair settings in force; the deployed `20-winrepair.toml` sets no key and documents every one
- `tests/test_deploy_mode_safety.py`  -  `--dir-mode`/`--file-mode` literal, range and safety checks
- `tests/test_deploy_permissions.py`  -  `config-deploy` permission options
- `tests/test_display.py`  -  Config display formatting tests
- `tests/test_logging.py`  -  Logging configuration model
- `tests/test_logging_dotenv_isolation.py`  -  Only `LOG_*` lines of a `.env` reach the environment; an invalid `[lib_log_rich]` section or `LOG_*` variable is a configuration failure that leaves logging running
- `tests/test_memory_logging.py`  -  Testing-composition logging runtime and the per-test logging reset
- `tests/test_permission_defaults.py`  -  `config-deploy` hands permissions to lib_layered_config: `--set` overrides, `.env` and deployed destinations never decide a mode, refusals exit 78
- `tests/test_property_overrides.py`  -  Property-based `--set` override tests

Guest tool:
- `tests/test_entry.py`  -  The guest tool's entry point and its one-envelope-per-run contract; the README's subcommand table lists every subcommand
- `tests/test_lockdown.py`  -  `lock-dirs` and the DACL that keeps non-admins away from what the SYSTEM task executes
- `tests/test_probes.py`  -  The read-only probe subcommands
- `tests/test_upgrade.py`  -  `prepare`, `launch` and `upgrade-run`
- `tests/test_wu.py`  -  `quiesce-wu`, `restore-wu` and the bounded Windows Update search probe
- `tests/test_artefact.py`  -  The committed packed tool is a fresh pack of the current guest sources
- `tests/test_pack_guest.py`  -  `scripts/pack_guest.py`: pack, check, and its exit codes

Project and repository:
- `tests/test_coverage_database.py`  -  A pytest run leaves every coverage database it did not create alone
- `tests/test_declared_dependencies.py`  -  Every third-party module imported at run time is a declared dependency
- `tests/test_enums.py`  -  Domain enum tests
- `tests/test_errors.py`  -  Domain error types
- `tests/test_metadata.py`  -  Package metadata and PEP 561 marker tests
- `tests/test_metadata_sync.py`  -  `__init__conf__` constants stay in sync with `pyproject.toml`
- `tests/test_module_entry.py`  -  `python -m` entry tests
- `tests/test_module_reference_sync.py`  -  This document names both packages, and its settings tables match the models' fields and defaults
- `tests/test_packaging.py`  -  The source distribution carries the package, its tests and its docs, and nothing else
- `tests/test_platform_markers.py`  -  The `os_*` markers skip a test off its platform
- `tests/test_ports.py`  -  Protocol conformance tests
- `tests/test_privacy_gate.py`  -  No private site data in the tracked tree, its path names or the packed guest tool (generic patterns always; the exact tokens from a local, never committed list)
- `tests/test_safe_console.py`  -  Legacy-codepage output tests, plus the guard forbidding direct `click.echo`

---

## Architecture

### Layer Assignments

| Directory/Module        | Layer       | Responsibility                                                  |
|-------------------------|-------------|-----------------------------------------------------------------|
| `domain/`               | Domain      | Pure logic  -  no I/O, logging, or frameworks                   |
| `application/ports.py`  | Application | Protocol definitions for adapters                               |
| `application/`          | Application | The repair and apply use cases, over the ports                  |
| `adapters/guest_ssh.py` | Adapters    | ssh and scp to a guest; the push of the packed tool             |
| `adapters/node.py`      | Adapters    | `qm`, the clock and the guests of one PVE node                  |
| `adapters/media.py`     | Adapters    | The installation media and their copy into the guest            |
| `adapters/receipts.py`  | Adapters    | Repair receipts as files in `[node] state_dir` or `--receipt`   |
| `adapters/config/`      | Adapters    | Configuration loading, deployment, display                      |
| `adapters/logging/`     | Adapters    | lib_log_rich initialization                                     |
| `adapters/cli/`         | Adapters    | Click CLI framework integration                                 |
| `adapters/memory/`      | Adapters    | In-memory implementations for testing                           |
| `composition/`          | Composition | Wires adapters to ports                                         |
| `pve_winrepair_guest/`  | Guest tool  | Runs on the Windows guest; imports nothing from `pve_winrepair` |

### Import Enforcement

Layer boundaries enforced via `import-linter` contracts in `pyproject.toml`:
- **Domain is pure**: Cannot import from adapters or composition
- **Clean Architecture layers**: Validates dependency direction (composition -> adapters -> application -> domain)
- **Guest tool is independent**: `pve_winrepair` and `pve_winrepair_guest` never import each other

Run `lint-imports` to verify compliance.

---

## Exit Codes

POSIX-conventional exit codes defined in `adapters/cli/exit_codes.py`:

| Code | Name                | Usage                                                                                                                |
|------|---------------------|----------------------------------------------------------------------------------------------------------------------|
| 0    | `SUCCESS`           | Command completed successfully                                                                                       |
| 1    | `GENERAL_ERROR`     | Unhandled exception, general failure                                                                                 |
| 2    | `FILE_NOT_FOUND`    | File not found; also click's usage error             (bad option value, malformed `--set`, invalid `--profile` name) |
| 13   | `PERMISSION_DENIED` | Cannot write to target directory                                                                                     |
| 22   | `INVALID_ARGUMENT`  | Invalid CLI argument or section not found                                                                            |
| 78   | `CONFIG_ERROR`      | Configuration missing, not loadable or invalid                                                                       |
| 110  | `TIMEOUT`           | Operation timed out                                                                                                  |
| 130  | `SIGNAL_INT`        | Interrupted (SIGINT/Ctrl+C)                                                                                          |
| 141  | `BROKEN_PIPE`       | Output pipe closed                                                                                                   |
| 143  | `SIGNAL_TERM`       | Terminated (SIGTERM)                                                                                                 |

---

## CLI Commands

### Root Command

**Command:** `pve-winrepair`

| Option                         | Description                                 |
|--------------------------------|---------------------------------------------|
| `--version`                    | Show version and exit                       |
| `--traceback / --no-traceback` | Show full Python traceback on errors        |
| `--profile NAME`               | Load configuration from a named profile     |
| `--set SECTION.KEY=VALUE`      | Override configuration setting (repeatable) |
| `--env-file PATH`              | Explicit `.env` file path                   |
| `-h, --help`                   | Show help and exit                          |

### info

Print resolved package metadata.

**Exit codes:** 0

### config

Display merged configuration from all sources.

| Option                   | Description                    |
|--------------------------|--------------------------------|
| `--format [human\|json]` | Output format (default: human) |
| `--section NAME`         | Show only specific section     |
| `--profile NAME`         | Override the root's profile    |

**Exit codes:** 0, 2 (usage error), 22 (section not found), 78 (configuration not loadable)

### config-deploy

Deploy default configuration to system or user directories: `config.toml` plus `config.d/` with
`20-winrepair.toml` (every key commented out, so the deploy sets no winrepair value and the app file
keeps deciding them), `40-layered-config.toml` and `90-logging.toml` (keys active).

| Option                             | Description                                                      |
|------------------------------------|------------------------------------------------------------------|
| `--target [app\|host\|user]`       | Target layer(s)  -  required, repeatable                         |
| `--force`                          | Replace differing files, keeping the old one as `<name>.bak`     |
| `--profile NAME`                   | Deploy to profile subdirectory                                   |
| `--permissions / --no-permissions` | Set Unix permissions (default: `enabled` from the configuration) |
| `--dir-mode MODE`                  | Directory mode for every target (octal)                          |
| `--file-mode MODE`                 | File mode for every target (octal)                               |

**Exit codes:** 0, 1, 2 (usage error, including a refused `--dir-mode`/`--file-mode` or `--profile` name, and `--no-permissions` together with a mode), 13 (permission denied), 78 (lib_layered_config refused the permission settings: a configured one, which both `--dir-mode` and `--file-mode` or `--no-permissions` deploy past, or a `--set` of `lib_layered_config.default_permissions`)

### config-generate-examples

Generate example configuration files.

| Option              | Description                   |
|---------------------|-------------------------------|
| `--destination DIR` | Target directory  -  required |
| `--force`           | Overwrite existing files      |

**Exit codes:** 0, 1

### repair

Repair one guest by an in-place repair upgrade (`application/repair.py`).

| Option              | Description                                                                                           |
|---------------------|-------------------------------------------------------------------------------------------------------|
| `--vmid N`          | The guest's VMID on the node  -  required, at least 1                                                 |
| `--snapshot-name S` | Snapshot to take (default `[repair] snapshot_name`, validated by its rule)                            |
| `--hours H`         | Polling deadline in hours, a finite number above 0 (default 6.0)                                      |
| `--stage-only`      | Stage the media and hold Windows Update, but neither gate the WIM nor launch setup (verdict `STAGED`) |
| `--ip IP`           | Guest IPv4 address for a guest without QEMU agent; implies the offline snapshot; MAC-checked          |
| `--node HOST`       | PVE node to drive over ssh, guests reached through it (default `[node] host`; empty: this machine)    |
| `--receipt FILE`    | Receipt file on this machine (made absolute), instead of `receipt-<vmid>.json` in `[node] state_dir`  |
| `--media M`         | Media from `node` (`[repair] media_dir`) or `local` (`local_media_dir` here); default `media_source`  |
| `--stage-root X:`   | Drive to stage on (default: a non-system fixed drive with room, else `C:`)                            |
| `--tpm-storage S`   | PVE storage ID for a new vTPM volume (default: the storage of the guest's disk)                       |
| `--json`            | Print the envelope `{ok, command, vmid, verdict, steps}` instead of the verdict line                  |

**Exit codes:** 0 (`STATE=DONE-OK`, `STAGED`), 1 (refused; `STATE=DONE-FAIL`, `WORKER_GONE`, `TIMEOUT`, `ERROR`), 2 (internal error, or a usage error), 78 (configuration not loadable or invalid)

### apply

Apply the upgrade a repair staged and verify the build its receipt recorded (`application/apply.py`).

| Option              | Description                                                                                                                 |
|---------------------|-----------------------------------------------------------------------------------------------------------------------------|
| `--vmid N`          | The guest's VMID on the node  -  required, at least 1                                                                       |
| `--ip IP`           | The guest's IPv4 address  -  required; MAC-checked against `qm config`                                                      |
| `--node HOST`       | PVE node to drive over ssh (default `[node] host`; empty: this machine)                                                     |
| `--receipt FILE`    | Receipt file to read (made absolute), as `repair --receipt` wrote it (default: `receipt-<vmid>.json` in `[node] state_dir`) |
| `--apply-minutes M` | Apply phase limit before overrun, a finite number above 0 (default 90.0)                                                    |
| `--json`            | Print the envelope instead of the verdict line                                                                              |

**Exit codes:** 0 (`VERIFIED`), 1 (refused: `RUN_LIVE`, `RUN_UNFINISHED`, `RUN_FAILED`, `NO_RUN`, `REVERTED_OR_UNCHANGED`, `ERROR`), 2 (internal error, or a usage error), 78 (configuration not loadable or invalid)

### guest-tool

`guest-tool path` prints the absolute path of the packed guest tool; `guest-tool sha256` prints
`<sha256>  <content address on a guest>`. Neither reads the configuration.

**Exit codes:** 0

---

## Profile Validation

Profile names (`--profile` option) are validated using `lib_layered_config.validate_profile_name()`.

### validate_profile()

**Location:** `adapters/config/loader.py`

```python
def validate_profile(profile: str, max_length: int | None = None) -> None:
    """Validate profile name using lib_layered_config."""
```

| Parameter    | Type          | Default  | Description                                 |
|--------------|---------------|----------|---------------------------------------------|
| `profile`    | `str`         | required | Profile name to validate                    |
| `max_length` | `int \| None` | 64       | Maximum length (DEFAULT_MAX_PROFILE_LENGTH) |

### Validation Rules

| Rule             | Description                                          |
|------------------|------------------------------------------------------|
| Maximum length   | 64 characters (configurable via `max_length`)        |
| Character set    | ASCII alphanumeric, hyphens (`-`), underscores (`_`) |
| Start character  | Must start with alphanumeric character               |
| Empty string     | Rejected                                             |
| Windows reserved | CON, PRN, AUX, NUL, COM1-9, LPT1-9 rejected          |
| Path traversal   | `/`, `\`, `..` rejected                              |
| Control chars    | Rejected                                             |

### Error Handling

Raises `ValueError` with descriptive message on invalid input.

---

## Configuration Overrides

`adapters/config/overrides.py` parses and applies `--set SECTION.KEY=VALUE`. Public names
(`__all__`):

| Name              | Kind     | Purpose                                                                                   |
|-------------------|----------|-------------------------------------------------------------------------------------------|
| `parse_override`  | function | Split one `SECTION.KEY[.SUBKEY...]=VALUE` string into a `ConfigOverride` (a frozen model) |
| `coerce_value`    | function | Read a raw value as JSON (bool, number, null, array, object), falling back to the text    |
| `nest_overrides`  | function | Parse all `--set` values into the nested mapping they override, refusing contradictions   |
| `apply_overrides` | function | Deep-merge the overrides into a `Config`, recording their provenance as `CLI_LAYER`       |
| `ConfigOverride`  | class    | One parsed override: section, key path and value                                          |
| `CoercedValue`    | type     | Union of the types `coerce_value` can return                                              |
| `CLI_LAYER`       | constant | Provenance layer name (`"cli"`) for a value that came from `--set`                        |

---

## Settings

`domain/settings.py` holds one frozen model per configuration section; each refuses an unknown key
(`extra="forbid"`) and keeps a number given to a text field as its digits (`coerce_numbers_to_str`),
because lib_layered_config reads an unquoted digit-only `.env` or environment value as an int.
`adapters/config/settings.py` `load_settings(config)` validates the four sections of a loaded
`Config` (an absent section takes its defaults) and raises `SettingsError(ValueError)` with one
`<section>.<field>: <reason>` line per problem, never echoing the refused value. The shipped defaults
are `adapters/config/defaultconfig.d/20-winrepair.toml` (the defaults layer, keys active; the copy
`config-deploy` writes has them commented out); an empty `ssh.key`, `repair.media_dir` or
`repair.local_media_dir` loads and means "not configured". Override one key per run with
`PVE_WINREPAIR___<SECTION>__<KEY>`, e.g. `PVE_WINREPAIR___SSH__KEY=<path>`.

### `[ssh]`  -  `SshSettings`

| Field                      | Type   | Default                | Rule                                                                                                                           |
|----------------------------|--------|------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| `key`                      | `str`  | `""`                   | private key path; empty = not configured                                                                                       |
| `user`                     | `str`  | `"Administrator"`      | `[A-Za-z0-9_.-]{1,64}`                                                                                                         |
| `strict_host_key_checking` | `bool` | `true`                 | the ssh adapter passes `yes` or `no`                                                                                           |
| `known_hosts_file`         | `str`  | `"~/.ssh/known_hosts"` | passed to ssh as written; a leading `~` is expanded by ssh, not here; empty, whitespace and `"` refused (`%` tokens are ssh's) |

### `[guest]`  -  `GuestSettings`

| Field              | Type              | Default | Rule                                                                                                                       |
|--------------------|-------------------|---------|----------------------------------------------------------------------------------------------------------------------------|
| `subnet`           | `IPv4Network`     | `""`    | IPv4 network in CIDR or netmask form, no host bits, or empty; held as an `IPv4Network`, empty as `None`                    |
| `runner_tasks`     | `tuple[str, ...]` | `[]`    | each `[A-Za-z0-9_.-]{1,64}`; no node command reads it: the values for guest `verify-runners --task NAME`                   |
| `expected_runners` | `int`             | `0`     | 0 to 999999, never true/false; no node command reads it: the value for guest `verify-runners --expected N` (0 = any count) |

### `[repair]`  -  `RepairSettings`

| Field                   | Type          | Default           | Rule                                                                           |
|-------------------------|---------------|-------------------|--------------------------------------------------------------------------------|
| `media_dir`             | `str`         | `""`              | directory of the installation media on the node; empty = not configured        |
| `local_media_dir`       | `str`         | `""`              | this machine's copy of the installation media; empty = not configured          |
| `media_source`          | `MediaChoice` | `"node"`          | `"node"` (`media_dir`) or `"local"` (`local_media_dir`); anything else refused |
| `stage_timeout_minutes` | `int`         | `90`              | 1 to 1440, never true/false (minutes the media copy to the guest may take)     |
| `snapshot_name`         | `str`         | `"pre_winrepair"` | `[A-Za-z][A-Za-z0-9_-]{1,39}`                                                  |
| `stage_free_gb`         | `float`       | `15.0`            | finite, greater than 0, never true/false (GiB on the staging drive)            |
| `system_free_gb`        | `float`       | `25.0`            | finite, greater than 0, never true/false (GiB on C:)                           |

### `[node]`  -  `NodeSettings`

| Field              | Type   | Default                | Rule                                                                                                                                                                                                                                           |
|--------------------|--------|------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `state_dir`        | `Path` | `default_state_dir()`  | where receipts are kept; absolute on the machine running the tool ("", relative and `~` refused); default per OS (`/var/lib/pve-winrepair` on POSIX, `%LOCALAPPDATA%\pve-winrepair` on Windows); a non-root Linux or macOS workstation sets it |
| `host`             | `str`  | `""`                   | the PVE node to drive over ssh, a DNS name or IPv4 address (`NODE_HOST_PATTERN`: letter or digit first, no space, `;` or `@`); empty = this machine is the node                                                                                |
| `ssh_user`         | `str`  | `"root"`               | `[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}` (never a leading `-`)                                                                                                                                                                                       |
| `ssh_key`          | `str`  | `""`                   | private key this machine logs in to the node with, passed to ssh as written; empty = not configured; `"` and `%` refused (the `ProxyCommand` carries neither)                                                                                  |
| `known_hosts_file` | `str`  | `"~/.ssh/known_hosts"` | the known_hosts file the node's host key is checked against (strictly), passed to ssh as written; a leading `~` is expanded by ssh; empty, whitespace, `"` and `%` refused                                                                     |

---

## Testing Infrastructure

### In-Memory Adapters

The `adapters/memory/` package provides lightweight implementations for testing:

| Module              | Protocols Satisfied                                                         |
|---------------------|-----------------------------------------------------------------------------|
| `memory/config.py`  | `GetConfig`, `GetDefaultConfigPath`, `DeployConfiguration`, `DisplayConfig` |
| `memory/logging.py` | `InitLogging`, `CheckLoggingConfig`                                         |

Use `composition.build_testing()` to wire all in-memory adapters.

### Test Fixtures (conftest.py)

| Fixture                   | Purpose                                                                                                                                                                 |
|---------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `config_factory`          | Creates real `Config` instances from test data                                                                                                                          |
| `inject_config`           | Injects config into CLI path                                                                                                                                            |
| `cli_runner`              | Fresh `CliRunner` per test                                                                                                                                              |
| `strip_ansi`              | Strips ANSI escape codes from output                                                                                                                                    |
| `clear_config_cache`      | Clears LRU cache before tests                                                                                                                                           |
| `managed_traceback_state` | Resets/restores traceback configuration                                                                                                                                 |
| `failing_command`         | Registers a test-only command that raises `RuntimeError` (for the exit and traceback paths) and returns its name                                                        |
| `isolated_logging_state`  | Autouse: after every test, shuts the lib_log_rich runtime down and restores the root logger; yields that restore step                                                   |
| `user_layer_in_tmp_path`  | Points every OS's user-layer location (`HOME`, `USERPROFILE`, `XDG_CONFIG_HOME`, `APPDATA`, `LOCALAPPDATA`) at `tmp_path` and returns it, so a real deploy writes there |
| `isolated_layers`         | Points every config layer but the shipped defaults (all three app roots, the user layer, the cwd) at `tmp_path` and removes inherited `PVE_WINREPAIR___` variables      |

---

**Last Updated:** 2026-10-23 (module list after the node CLI port; repair, apply and guest-tool commands)
