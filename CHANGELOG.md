# Changelog

All notable changes to this project will be documented in this file following
the [Keep a Changelog](https://keepachangelog.com/) format.


## [Unreleased]

### Changed

- Ruff selects `C90` (mccabe), so a function over cyclomatic complexity 10, the house hard limit,
  now fails `make test`; before, nothing enforced it. Proven with a complexity-11 function, which
  ruff reported only once `C90` was selected; the tree itself already passes.

### Tests

- The sdist bytecode check in `tests/test_packaging.py` matches a path component named `__pycache__`
  (or a `.pyc` file); its substring test failed a repository whose test fixtures sit under a directory
  such as `test__pycache__`.
- The `test_real_smtp_*` tests (`make testintegration`) also skip when `[email].recipients` is
  empty, as the shipped `50-mail.toml` leaves it; with a host and sender configured they failed
  three times with "No recipients configured".

## [2.4.3] 2026-10-15 13:17:15

### Fixed
- The source distribution ships only the package, its tests, its docs, `README.md`, `CONFIG.md`,
  `LICENSE`, `CHANGELOG.md` and `pyproject.toml` (an include list). Earlier sdists also carried
  repository working files such as `reset_git_history.sh` and, in a local build, anything hidden
  only through `.git/info/exclude` or a nested `.gitignore` (`handover.md`, `OPEN-WORK.md`,
  `.private/`). `tests/test_packaging.py` builds the sdist and wheel and checks both.
- Logging takes its `LOG_*` lines from the `.env` the configuration loader read, named by the
  configuration's provenance. It searched only up to the first `pyproject.toml` or `.git`, while
  the loader walks on to the filesystem root and falls back to the per-user `.env`, so in a
  checkout nested in another (a worktree), or with only a per-user `.env`, that file's other lines
  applied and its `LOG_CONSOLE_LEVEL` did not. When the configuration did not load, logging takes
  the first `.env` on the loader's own walk.
- A refused `[lib_log_rich]` setting that takes one of several types (`console_styles`) is named
  by the key a configuration file writes, once: pydantic's tag for each arm of the union
  (`console_styles.dict[str,str]`) no longer appears, and arms refused for the same reason share
  one line.
- A `[lib_log_rich]` value a validator refuses reads as the validator wrote it
  (`lib_log_rich.queue_maxsize: queue_maxsize must be positive`), without pydantic's
  `Value error, ` in front, like the `[email]` refusals.
- Console output no longer writes a raw C1 control byte (0x80-0x9F) for a lone surrogate on a
  `surrogateescape` stream (Python's UTF-8 mode, a C/POSIX locale): such a byte, 0x9B being the
  8-bit CSI, is obeyed by a terminal that reads 8-bit controls, so it is written as the inert
  ASCII escape `\x9b`, which still names the byte. Any other non-UTF-8 path byte is still
  written back as it is on disk.
- `send-email --smtp-host H` and `send-notification --smtp-host H` send through `H` when the
  configuration names no SMTP host; they exited 78 "No SMTP hosts configured", because the hosts
  were checked before the command-line overrides were applied.
- `config-deploy` logs "Deployed configuration" only when it wrote a file, now with the files
  written; a deploy that wrote nothing (every target exists, or under `--force` already holds the
  bundled content) logs "No configuration file written".
- `send-email` logs "Sending email" once per send: the command logged it and so did the transport.
  The transport's line stays, since it carries the resolved sender and recipients.
- `config` shows `lib_log_rich.payload_limits.context_max_keys` and `extra_max_keys`, plain counts,
  instead of `***REDACTED***`: their names matched lib_layered_config's secret pattern (`*_keys`).
  The two paths are declared not sensitive (`NOT_SENSITIVE` in `adapters/config/loader.py`), also
  for a configuration a `--set` rebuilt; `email.smtp_password` stays redacted.
- `config` shows the shipped `lib_log_rich.scrub_patterns` fields `password`, `secret` and `token`
  (each a regex such as `.+` naming what the log scrubber hides) instead of `***REDACTED***`, so
  the scrubbing can be checked. A field an operator adds to `scrub_patterns` stays redacted.
- The refusal of an empty blocked attachment set built from Python names its way out as
  `attachment_allow_empty_blocklists=True`, the setting that exists; it said
  `attachments.allow_empty_blocklists`, a key the configuration loader refuses as unknown.

### Tests
- A plain `pytest` run no longer deletes the coverage database in the system temp directory, and
  its SQLite journal files, at the start of every session: `tests/conftest.py`'s
  `pytest_configure` purged them whatever else was using them, while the `COVERAGE_FILE` redirect
  it also set never took effect (pytest-cov creates its Coverage object before any conftest is
  imported). Both are gone; `tests/test_coverage_database.py` plants a database and requires a real
  pytest run to leave it alone.
- The `os_windows`, `os_macos`, `os_linux` and `os_posix` markers now skip a test off its platform
  (`pytest_runtest_setup` in `tests/conftest.py`); registered in `pyproject.toml` alone they skipped
  nothing, so a test trusting its marker ran everywhere. `tests/test_platform_markers.py` pins it.
- A configuration file the user cannot read (mode 000) is pinned to exit 78 with one stderr line naming the
  file, for `config` and `send-notification`: lib_layered_config 7.1.1 wraps the PermissionError in a
  LayerLoadError, and exit 13 stays reserved for a refused write (`config-deploy`).

## [2.4.2] 2026-10-15 12:30:56

### Added
- `uv.lock` is committed, and `[tool.uv] exclude-newer` sets a cooldown that keeps releases younger
  than it out of the lock. CI installs exactly the locked tree on push and pull request; the nightly
  scheduled run still resolves afresh to catch upstream breakage early.

### Changed
- The install section explains why installing with uv protects against supply-chain attacks and why
  a plain `pip install` from PyPI does not.

### Fixed
- `ai-transparency.md` described another project (pve-bindsnap: Proxmox bind mounts, its
  `BINDSNAP-*` keywords and skill) and claimed the GNU AGPL v3.0, while this template is under
  the MIT License. It now describes this template's own work and states the MIT License.

## [2.4.1] 2026-10-12 18:59:22

### Added
- Python 3.15 is declared and tested: the classifier puts it into the CI matrix and
  `make test-all`, and `make test` now builds the development venv on 3.15.

### Changed
- The devcontainer image and interpreter path move from Python 3.13 to 3.14.
- Requires `lib_log_rich>=6.5.1`, `lib_layered_config>=7.1.6` and `pydantic>=2.14.1` (and, in the
  dev extra, `ruff>=0.17.0`, `rtoml>=0.14.0`, `virtualenv>=21.14.7`); the Makefile is bmk 3.19.0.

### Fixed
- **A digit-only `[lib_log_rich]` service or environment name no longer fails validation.**
  lib_layered_config 7.1 reads an unquoted `.env` or environment value that spells a number
  losslessly as an int, so `LIB_LOG_RICH__SERVICE=4711` reached `LoggingConfigModel` as `4711`
  and was refused with `Input should be a valid string`. The model now reads the number back as
  the text that was written. The email section already did this for the SMTP user name and
  password.
- The `graylog_endpoint` and `rate_limit` notes in `.env.example` and `90-logging.toml` said a
  `host:port` or `100:60` string makes every command exit 22. It does not: `info` still runs
  (exit 0) and the commands that read the configuration exit 78. The notes now say that only the
  native `LOG_GRAYLOG_ENDPOINT` and `LOG_RATE_LIMIT` variables take that form.

## [2.4.0] 2026-10-08 17:34:36

### Changed
- **The email commands' SMTP options reach the configuration as a typed `EmailConfigOverrides`
  model instead of a plain dict.** `EmailConfigOverrides.from_cli_options(...)` takes the Click
  values (an option that was not given is `None`, an unset `--smtp-host` an empty tuple) and
  `apply_validated_overrides` merges only the options that were given. Its fields carry
  EmailConfig's own names, so a field EmailConfig renames is refused instead of slipping through,
  and `--smtp-password` is a `SecretStr` from the moment it is read; the model is a btx_lib_mail
  `SecretSafeModel`, so a refused password never appears in a validation error's details.
  `filter_sentinels` is gone; the command line behaves as before.
- Requires `pydantic>=2.14.0` (and `virtualenv>=21.14.6` in the dev extra).

## [2.3.0] 2026-10-08 16:14:12

### Changed
- **`config --profile NAME` checks the profile's logging settings instead of restarting logging.**
  The check now runs through lib_log_rich's `validate_config`, which refuses exactly what starting
  logging refuses, with the same `Error:` lines and exit 78, so nothing changes for an invalid
  setting. What changes: the running logging runtime is no longer shut down and started again, so
  the rest of the command keeps logging with the settings logging started with (not the profile's),
  and a `main()` call from a worker thread no longer replaces the logging every other thread uses.
  The `RestartLogging` port is now `CheckLoggingConfig` (`AppServices.check_logging_config`; the
  testing composition's double refuses nothing). Requires `lib_log_rich>=6.4.2`.

### Fixed
- **A logging refusal no single setting owns reads `lib_log_rich: <reason>`.** Such a problem (for
  example TLS together with UDP for Graylog, which lib_log_rich 6.4.2 now refuses up front) has no
  key, and its `Error:` line came out as `lib_log_rich.: <reason>` with a dangling dot.

## [2.2.0] 2026-10-08 13:56:49

### Removed
- **`send-notification --raise-on-missing-attachments` (usage change).** A notification takes no
  attachments, so the switch did nothing there. `send-notification` now refuses it as an unknown
  option (exit 2); `send-email` keeps it. Drop the flag from any script that passes it to
  `send-notification`.

### Tests
- The `config-deploy --force` report for a deploy in which every target file is already identical
  is covered end to end. New shared fixture `user_layer_in_tmp_path` points every OS's user-layer
  location at `tmp_path`; it replaces two hand-written copies of the same loop.

## [2.1.3] 2026-10-08 11:57:40

### Fixed
- **`config --profile NAME` refuses an invalid logging setting like `config` does.** The
  subcommand's `--profile` reloads the configuration after logging has started, and that reload
  skipped the logging settings, so a `[lib_log_rich]` value or `LOG_*` variable that makes plain
  `config` exit 78 was displayed with exit 0. The reload now restarts logging with the reloaded
  configuration, which refuses exactly what plain `config` refuses (a scrub pattern, a console
  format preset or style key and a level name included) with the same `Error:` lines, also for a
  `[lib_log_rich]` section that is invalid only in that profile's own file; the rest of the
  command then logs with the profile's settings. New `RestartLogging` port
  (`AppServices.restart_logging`; the testing composition's double keeps its quiet runtime).

## [2.1.2] 2026-10-08 09:43:32

### Changed
- **A refused attachment exits 77, not 1 with a traceback (exit code change).** An attachment
  btx_lib_mail's security checks refuse (a blocked extension such as `.exe`, a file under a
  blocked directory, a symlink, a file over the size limit) made `send-email` exit 1 with
  `Error: Unexpected error - Attachment security violation (...)` and log the refusal with a
  traceback, as if the program had crashed. Since btx_lib_mail 4.0.0 every blocked extension is
  refused on every platform, so this is an ordinary outcome on Linux and macOS too. It now exits
  77 (`ExitCode.ATTACHMENT_REFUSED`, sysexits `EX_NOPERM`: not permitted by policy) with one
  line, `Error: Attachment refused by security policy - <the library's reason>`, logs no
  traceback, and delivers nothing. A script that checks for 1 after a refused attachment must
  check for 77. With `email.attachments.raise_on_security_violation = false` the attachment is
  still skipped with a warning and the message sent, as before; a violation that names no attachment
  left to drop is refused in warn mode too, and now exits 77 where it exited 1.

## [2.1.1] 2026-10-06 18:13:05

### Fixed
- **A refused `LOG_*` variable no longer disables every command (exit code change).** A value
  lib_log_rich refuses in a `LOG_*` variable, set in the environment or in the `.env` logging
  reads (`LOG_CONSOLE_LEVEL=bogus` in the `--env-file`), made every command, `info` and
  `config-deploy` included, exit 1 with `InvalidLoggingConfigError: lib_log_rich: Unknown log
  level: 'bogus'`: the fallback restarted logging with an empty configuration, but lib_log_rich
  reads the `LOG_*` variables on every start and refused the same variable again. Logging now
  falls back to its defaults with every `LOG_*` variable hidden for that start (and put back
  afterwards), so only the commands that read the configuration (`config`, `send-email`,
  `send-notification`) exit 78, and the others run with exit 0. The 78 carries lib_log_rich's
  own message, `Error: lib_log_rich: Unknown log level: 'bogus'`, which may name neither the
  variable nor where it was set. A refused `[lib_log_rich]` value still leaves every valid
  `LOG_*` variable in force for the fallback, as in 2.1.0: only a refused variable hides them.
- **The testing composition ignores the developer's `LOG_*` variables.** `build_testing()`'s
  logging runtime (`init_logging_in_memory`) now starts with every `LOG_*` variable hidden and
  puts them back afterwards. A `LOG_CONSOLE_LEVEL=bogus` in the shell running the tests made
  every command under `build_testing()` fail with `ValueError: Unknown log level: 'bogus'`, and a
  valid one changed the quiet test runtime. Production logging is unaffected.

## [2.1.0] 2026-10-06 15:37:27

### Added
- **Three email limits from btx_lib_mail 4.0.0 are configurable**: `[email] delivery_deadline`
  (an upper bound in seconds for one SMTP session; the field is `smtp_delivery_deadline`),
  `[email] recipient_max_count` (default 1000) and `[email.attachments] max_count` (default
  100). A value of 0 means no limit, as `max_size_bytes = 0` already did. Shipped in
  `50-mail.toml`, `.env.example` and the module reference.

### Changed
- **Requires `btx_lib_mail>=4.0.0`.** Effects a user of the email commands can see: the
  Windows dangerous extensions (`.exe`, `.bat`, `.ps1`, ...) are refused on every platform by
  default and the POSIX ones on Windows; a sender or recipient longer than RFC 5321 allows is
  refused; a subject with a control character or over 4096 characters is refused; an
  attachment swapped after its checks is refused; a delivery error is a `DeliveryError` (still
  a `RuntimeError`). See the btx_lib_mail 4.0.0 changelog for the full list.

### Removed
- **`EmailConfig`'s own SMTP host validator.** `ConfMail` checks every host's syntax (port
  range, IPv6 brackets) itself since btx_lib_mail 3.0.1; the messages are unchanged.

## [2.0.1] 2026-10-06 13:09:50

Re-release of 2.0.0, which was tagged but never published: PyPI rejected the upload because
that filename had been used by a file that has since been deleted, and PyPI never permits
filename reuse. Package contents are identical to 2.0.0.

## [2.0.0] 2026-10-06 08:26:05 [NOT PUBLISHED]

### Added
- **`describe_validation_error` and `nest_overrides` are public** (in `__all__` of
  `adapters/email/config.py` and `adapters/config/overrides.py`): the one-line-per-problem
  rendering of a validation error, and the `--set` nesting that refuses a conflicting pair.

### Fixed
- **`email.recipients` set to nothing means no default recipients.** A bare YAML key or an
  environment `null` was refused as "Input should be a valid list", while the same value for
  `email.smtp_hosts` already meant an empty list. Both now read `None` as not configured.
- **`build_testing()` can run a command.** The in-memory logging initializer was a no-op while every
  command binds job context onto the lib_log_rich runtime, so any command under the testing
  composition raised `RuntimeError('lib_log_rich.init() must be called before using the logging
  API')`. It now starts a quiet runtime (no journald, event log, Graylog or queue; console at ERROR;
  no `.env` loading).
- **Tests no longer pass or fail by order.** An autouse fixture shuts the lib_log_rich runtime down
  and restores the root logger's handlers, level and propagate flag after every test; production
  `init_logging` attaches a stdlib handler and raises the root level, which `runtime.shutdown()`
  does not undo.
- **No more `SystemExit: N` on stderr.** The email and config commands raised a bare `SystemExit`,
  which `main()`'s catch-all branch printed as `SystemExit: 78` after the real error message. They
  now exit through click's context (`ctx.exit`), and `main()` returns the exit code rich_click's
  `main()` hands back instead of discarding it and returning 0. `typed_click` gains a typed
  `get_current_context` wrapper for the helpers that have no `ctx` parameter.
- **A failed send is reported once.** click's `Exit` subclasses `RuntimeError`, so the send-result
  exit raised inside the delivery `try` was caught again by the `DeliveryError`/`RuntimeError`
  branch, adding "SMTP delivery failed" / "Failed to send email" to the correct "sending failed".
  The send result is handled in the `try`'s `else`, and `config-deploy` re-raises an `Exit` before
  its catch-all.
- **A non-UTF-8 path no longer crashes output, and the console fallback degrades only what it
  must.** `safe_console.encode_safe` skipped its check for utf-8/16/32, but a lone surrogate (a
  filesystem byte decoded with `surrogateescape`) encodes in none of them, so
  `config-generate-examples` into such a directory wrote its files and then exited 1 on the path
  echo. Once any character failed, the fallback also rewrote every known glyph in the text,
  including ones the stream could print. The fallback is now a registered codec error handler: the
  codec calls it for exactly the characters it rejects, which become their ASCII form or, when
  the table has none, whatever the stream's own error handler writes: under Python's UTF-8 mode
  or a C/POSIX locale stdout uses `surrogateescape`, so a non-UTF-8 path prints byte-exact and
  still names the directory on disk, and stderr (`backslashreplace`) spells such a character
  out. Only a `strict` stream gets `?`.
- **A broken configuration file no longer disables every command.** The root group loaded the
  configuration before any subcommand option was parsed and let a load error escape, so a
  malformed `config.toml` made every command, `--help` and `config-deploy` (the command that
  replaces the file) exit 1 with empty stdout. The root now records the failure
  (`adapters/cli/config_load.py`); `config`, `send-email` and `send-notification` refuse with exit
  78 and one line naming it, while `config-generate-examples`, `info`, `hello` and help still run.
  `config-deploy` runs too: it reads nothing from that configuration (see the next entry), so
  `config-deploy --force` replaces the broken file. An unreadable file takes the same path, and
  so does an `--env-file` that is not UTF-8 (the line names the file).
  `--traceback` prints the loader's chained traceback before the line. What the command line
  gets wrong is checked BEFORE loading, so a broken file cannot hide it: a malformed `--set` or
  an invalid `--profile` name is a usage error (exit 2) for every command, `info` and `hello`
  included (see Changed for the `--profile` exit code). So are two `--set` values that give one
  key a value and put a key under it (`--set a.b=1 --set a.b.c=2`), which escaped as a
  `TypeError` (exit 22) in one order and silently dropped the earlier value in the other. A table
  value with a key put under it (`--set 'a.b={"c": 1}' --set a.b.d=2`), which used to merge into
  `{"c": 1, "d": 2}`, is refused the same way: give the whole table in one `--set`. Any
  other exception from the loader is a bug and propagates as one instead of being reported as a
  configuration error.
  `config --profile X` reloads with the root's `--env-file` instead of searching for another `.env`.
- **`[lib_layered_config.default_permissions]` now takes effect, and only the configuration
  files decide it.** The per-layer modes were read, but only `enabled` was ever used, so
  `--set lib_layered_config.default_permissions.user_directory='"0o750"'` still produced a `0o700`
  directory. `config-deploy` now hands its options and any `--set` of the section to
  lib_layered_config (6.0.0 or later), which deploys each target with its configured directory
  and file mode (`--dir-mode`/`--file-mode` still win) and reads the section itself: from the
  bundled defaults, the configuration files the deploy does not overwrite and the environment,
  never from `.env` (nor `--env-file`). So a `.env` in the working directory can neither change
  a deployed mode nor block a deploy (`sudo myapp config-deploy --target app` run from a
  directory holding one used to be decided or refused by it), and `config-deploy --force`
  replaces a deployed file that does not parse or holds a bad value without further options.
  A malformed or out-of-range mode, a bare integer (TOML `user_file = 400` is decimal 400, i.e.
  `0o620`), an unsafe mode, a non-boolean `enabled` (`"no"`, `"off"`, `0` and `1` are refused,
  not read as a boolean), a section that is not a table or an unknown key stops the command with
  exit 78 before anything is written: one `Error:` line per problem naming the key and where it
  was set (`(source: override)` for a `--set`), then, for a configured value, a hint that both
  `--dir-mode` and `--file-mode` deploy anyway. It used to fall back to the default, crash with
  `AttributeError`, or print pydantic's multi-line error. `--no-permissions` together with
  `--dir-mode` or `--file-mode` is a usage error (exit 2).
- **An invalid `[email]` section is a configuration error.** `send-email` and `send-notification`
  let the `ValidationError` escape to `main()`'s catch-all, which exited 22 with pydantic's
  multi-line report and documentation URL. They now exit 78 with one line per problem,
  `Error: Invalid configuration: email.<key>: <reason>` (an `[email.attachments]` setting is
  named by its nested key). An invalid option value (`--timeout -5`) still exits 22, now in the
  same one-line form (`Error: Invalid option value: ...`).
- **The documented `.env` and environment syntax for lists and tables works.** `.env.example`,
  `defaultconfig.d/50-mail.toml`, `defaultconfig.d/90-logging.toml` and the README showed
  comma-separated lists (`EMAIL__SMTP_HOSTS=a:587,b:587`) and `LEVEL=style` / `field=regex`
  pairs, but a comma-separated value arrives as ONE string in both layers: one bogus SMTP host, an
  attachment whitelist that was silently ignored, or a logging table that was refused. They now
  show a JSON array or object (unquoted in `.env`, shell-quoted in the environment) or one key
  per entry (`EMAIL__SMTP_HOSTS__0=...`). An unquoted `.env` value converts like the
  environment layer (lib_layered_config 7, see Changed): `true`/`false` arrive as booleans,
  `null`/`none` as None (not for a secret key such as a password), a JSON array or object
  parsed, a number that converts back to the same text as a number, anything else as text;
  quote a value to keep it text.
- **A `.env` reaches logging and nothing else.** The logging setup called lib_log_rich's
  `enable_dotenv()`, which copied every line of the nearest `.env` into the process
  environment, so a later configuration load (`config --profile`, the deploy's permission
  read) took an app-prefixed `.env` line for the environment layer: a prefixed
  `..._DEFAULT_PERMISSIONS__USER_FILE=400` in the working directory refused `config-deploy`
  even under `--env-file`. Logging now copies only the `LOG_*` lines, never over a variable
  that is already set, and reads them from the `--env-file` when one is given; otherwise from
  the nearest `.env` up to the project root, without changing directory and passing over a
  directory it cannot read. A `.env` that is not UTF-8 no longer stops logging from starting,
  and neither does a working directory that was deleted or an ancestor that cannot be read (both
  exited 2 with `FileNotFoundError`). Other `.env` lines (`DEVELOPMENT_MODE=1` included) no
  longer reach the environment; set such a variable in the environment itself. A `${VAR}` in a
  `LOG_*` line resolves from the file's own lines first, then the environment.
- **An invalid `[lib_log_rich]` value no longer disables every command.** A value lib_log_rich
  refuses (`rate_limit = "100:60"`, `queue_maxsize = 0`, an unknown `console_level`) exited 22
  with pydantic's multi-line report from every command, `config-deploy --force` included. It is now a configuration failure like a broken
  file: logging starts with its defaults, `config`, `send-email` and `send-notification` refuse
  with exit 78 and one line per problem (`lib_log_rich.rate_limit: Input should be a valid
  tuple`), and the other commands run. `InvalidLoggingConfigError` (a `ConfigurationError`) is
  what the logging setup raises for it.
- **The password-leak test no longer flakes on a process id.** Its noise filter removed the
  `process_id` key but not the value after it, so a PID holding four digits of the planted dummy
  failed the test (about 1 run in 500); it now drops the value in both JSON fields. The
  environment-password test isolates every operating system's user configuration directory, not
  only `XDG_CONFIG_HOME`, so a developer's own config cannot decide it on macOS or Windows.

### Changed
- **Requires lib_layered_config 7.0.1** (6.0.0 moved the permission decisions into the
  library, 7.0 converts unquoted `.env` values). `config-deploy` leaves every permission
  decision to its `deploy_config` (see Fixed). The deploy port (`DeployConfiguration`) takes
  `set_permissions: bool | None` (None, the default, follows the configured `enabled`) and
  `permission_overrides`; a derived repo's own deploy double needs both. Refusals of
  `--dir-mode`/`--file-mode` use the library's wording ("unsafe directory mode 0o777: group
  write (0o020); world write (0o002)"), and a zero-padded mode such as `0000750` is accepted
  as `0o750`. An unquoted `.env` value converts like the environment layer, so `ENABLED=false`
  arrives as the boolean `false`; a `.env` setting still never reaches a deploy.
- **Requires python-dotenv** (already installed through lib_log_rich): the logging setup reads
  the `LOG_*` lines of a `.env` itself. **`InitLogging` takes `dotenv_path`**: the port is
  `init_logging(config, *, dotenv_path=None)`, and a derived repo's own logging double needs
  the keyword.
- **Breaking: an invalid `[email]` section exits 78, no longer 22** (see Fixed). A script that
  checks for 22 after `send-email` or `send-notification` must check for 78 (EX_CONFIG); an
  invalid option value such as `--timeout -5` still exits 22. The log record for a refused
  option names its problems in a `problems` field instead of the pydantic dump in `error`.
- **Breaking: `EmailConfig` is a btx_lib_mail `ConfMail`.** It inherits the `SecretStr` password,
  the timeout and EHLO-name checks, the empty-blocklist refusal and validation errors that never
  show the password or a host, and adds `from_address` and `recipients`; every SMTP host's syntax
  (port range, IPv6 brackets) is still checked when it loads. In Python it uses the library's
  names: `smtphosts`, `smtp_use_starttls`, `smtp_timeout`. `to_conf_mail()` is gone: pass the
  config itself (`btx_lib_mail.send(config=...)`). Configuration files and environment variables
  keep their keys (`smtp_hosts`, `use_starttls`, `timeout`); `FILE_KEY_TO_FIELD` in
  `adapters/email/config.py` maps them.
- **Breaking, for code that builds `EmailConfig` in Python: the attachment settings follow
  `ConfMail`.** The "empty means the defaults" and "0 means no limit" readings apply only to
  configuration read through `load_email_config_from_dict`. From Python, an empty
  `attachment_allowed_extensions` or `attachment_allowed_directories` now allows NOTHING (it
  meant "no allowlist"), an empty blocked set is refused unless
  `attachment_allow_empty_blocklists=True`, and `attachment_max_size_bytes=0` is refused (pass
  `None` for no limit). Unchanged from Python: a blank user name, password or sender means not
  set, one recipient string is a one-entry list, and an all-digit user name is read as its digits.
- **A blank entry in an attachment list is refused** (`email.attachments.<key>: an entry is
  blank; remove it`). A blank directory became `Path(".")`, which REPLACED the operating system's
  blocked directories, so `blocked_directories = [""]` switched directory protection off.
- **Breaking: an unknown key in `[email]` or `[email.attachments]` is refused** (exit 78,
  `Error: Invalid configuration: email.<key>: unknown key`), from any layer including `.env`, the
  environment and `--set`. A typo used to be ignored silently and leave the setting at its
  default.
- **New keys `email.starttls_verify` (default true) and `email.local_hostname`** (default unset):
  certificate verification after STARTTLS, and the host name announced in EHLO (Python fields
  `smtp_starttls_verify`, `smtp_local_hostname`).
- **Delivery errors carry the library's message.** The filter that replaced any message
  mentioning `auth`, `login`, `key` and similar words with "Email delivery failed. Check SMTP
  configuration." is removed. The message names the recipients and hosts that failed, and a host
  or address that merely contained such a word (`smtp.keystone.example`) no longer hid it; the
  SMTP password is never part of it.
- **Error lines name the file key**: `email.timeout: timeout must be positive, got -5.0` (was
  `email: timeout must be positive ...` for a check that ran on the whole model).
- **Breaking: an invalid `--profile` name exits 2, no longer 78.** A name such as `../x` is now
  refused as a usage error for every command, before the configuration is loaded (the root's
  `--profile`, `config --profile` and `config-deploy --profile`). `config`, `send-email` and
  `send-notification` exited 78 for it, `config-deploy` exited 1 ("Failed to deploy
  configuration"), and `info` and `hello` ignored it and exited 0. A script that tells a bad
  profile name from a broken configuration file by exit code 78 has to test for 2. A profile
  FILE that does not load is still 78.
- **Breaking: `EmailConfig.smtp_password` is a pydantic `SecretStr`, no longer a `str`** (see
  Security below for why). Code that reads the password now gets a `SecretStr`, so
  `config.smtp_password == "app-password"` is silently `False`, and under pyright strict
  `EmailConfig(smtp_password="app-password")` is a `reportArgumentType` error (pydantic still
  coerces a plain string at run time). Migration: read the value with
  `config.smtp_password.get_secret_value()`, and construct with
  `EmailConfig(smtp_password=SecretStr("app-password"))` (`from pydantic import SecretStr`).
- **`click` is a declared dependency.** The package imports it directly (`adapters/cli/main.py`,
  `commands/config.py`) but only had it through rich-click. A new test fails when a runtime
  import is missing from `[project].dependencies`.
- **For derived repos: tests under `build_testing()` now see ERROR log lines on stderr.** The
  testing composition starts a quiet lib_log_rich runtime (console at ERROR) instead of a no-op,
  so a `logger.error` in a command, e.g. "Failed to deploy configuration", now precedes its
  `Error:` line in CliRunner's stderr. A test asserting exact or line-counted stderr under
  `build_testing()` has to allow for it. The conftest fixtures that build services
  (`inject_config`, `inject_config_with_profile_capture`, `inject_deploy_with_profile_capture`,
  `inject_deploy_configuration`, `email_cli_context`, `config_cli_context`) now use that quiet
  runtime too: the production one queues INFO lines that raced into stderr by timing.

### Removed
- `EmailConfig.to_conf_mail()` and the custom `EmailConfig.__repr__` (the `SecretStr` password
  already renders as `'**********'`), `transport._sanitize_exception_message`, and
  `adapters.memory.load_email_config_from_dict_in_memory`: `build_testing()` wires the real
  `load_email_config_from_dict`, so CLI tests run through the same translation as production.
- `adapters.config.permissions` as a whole: `parse_mode` (whose silent fall-back to the default
  was the bug), `get_permission_defaults`, `get_modes_for_target` and the `PermissionDefaults`
  model. lib_layered_config reads and validates the section now; a caller that wants the
  settings uses its `deploy_permissions_from_config`.
- `config_load._not_utf8` and the `UnicodeError` branch of `load_config`: lib_layered_config
  6.0.0, the declared floor, reports a `.env` or TOML file that is not UTF-8 as its own
  `ConfigError` naming the file, so the branch was unreachable. The tests for that case now drive
  the real loader instead of injecting the error the library no longer raises.

### Security
- **`config-deploy` refuses unsafe and malformed modes.** `--dir-mode -1` passed the unbounded
  octal parser and chmodded the config directory to `0o7777` (setuid, sticky, world-writable); a
  20-digit value raised `OverflowError`. `--dir-mode`/`--file-mode` now accept only a plain octal
  literal in `0`..`0o7777`, and refuse the setuid/setgid/sticky bits, group and world write, an
  execute bit on a file, a directory without owner `rwx` and a file without owner `rw`, naming
  each offending bit (exit 2, nothing written). The rule is lib_layered_config's, the same one it
  applies to configured modes.
- **The SMTP password no longer prints.** `EmailConfig.smtp_password` was a plain `str`: the
  custom `__repr__` hid it, but `str()`, `format()` and `model_dump()`/`model_dump_json()` printed it.
  It is now a pydantic `SecretStr`, unwrapped only where the SMTP login receives it.
- **The SMTP password no longer appears in validation errors.** pydantic prints the input it
  refuses: the offending value for a field error (an integer or list password was shown in full,
  on stderr through `main()` with and without `--traceback`) and the whole input mapping for a
  model-level error such as a negative `timeout` or an invalid host next to the password (shown
  or elided depending on key order). `EmailConfig` now sets `hide_input_in_errors=True`, and the
  credential validator names only the type it refuses. An all-digit password, which the
  environment layer reads as an integer and which was therefore refused and could never be used,
  is now read as its digits (a leading zero is lost in the environment; quote such a password
  in a TOML file). A float, boolean, list or table is refused. A non-ASCII password or user name
  is accepted: btx_lib_mail logs in with UTF-8 AUTH PLAIN.
- **No group-writable or executable configuration, and no decimal integer read as a mode.** A
  configured mode given as a bare integer was read as DECIMAL (TOML `user_file = 444`, `--set`, or
  the environment value `444`), and several such values passed the safety rule: `444` deployed
  `config.toml`, the file holding the SMTP password, at `0o674`, and `400` meant as owner-read-only
  became `0o620`. A bare integer is now refused with a hint to write an octal string (`"0o640"`),
  and every mode, from the CLI or the configuration, is also refused when it grants group write
  (on macOS every local account shares the group `staff`) or, for a file, sets any execute bit.
  `--dir-mode 770` and `--file-mode 660`, accepted before, are refused. Migration: quote configured
  modes (`user_file = "640"`), and use the `0o` prefix in environment variables and `--set`.
- **An attachment allow or block list in the wrong form is refused, not dropped.** The
  `[email.attachments]` lists `allowed_extensions`, `blocked_extensions`, `allowed_directories`
  and `blocked_directories` read any value that was not a list as "not configured", so a
  comma-separated environment value (`.pdf,.txt`, which arrives as one string; only a JSON array
  `[".pdf", ".txt"]` arrives as a list) silently replaced the configured list with btx_lib_mail's
  defaults: a configured whitelist was lifted, a configured blacklist replaced. Such a value, and
  a number, boolean or table, is now refused: the command exits 78 with
  `Error: Invalid configuration: email.attachments.<key>: expected a list ...`. An empty value
  (`[]`, an empty or whitespace-only string) still means "not configured". From Python,
  `EmailConfig` follows `ConfMail`: a list, tuple or set is read as a frozenset, and an empty
  blocked set is refused unless `attachment_allow_empty_blocklists=True`. `smtp_hosts` and
  `recipients` no longer empty a tuple or a non-list value: a tuple is read as a list, a number is
  refused.

## [1.7.2] 2026-09-12 02:11:47

### Fixed
- **`--set` overrides now report the CLI as their source.** `Config.with_overrides` returns the
  merged data with the ORIGINAL provenance map by design, so an overridden key kept naming the
  file it replaced and `config` sent a reader to a file holding the old value. The override path
  rebuilds provenance, naming layer `cli` with no path for exactly the keys `--set` supplied and
  leaving every other key's source alone.

## [1.7.1] 2026-08-01 01:02:45

Re-release of 1.7.0, which was tagged but never published: PyPI rejected the upload because
that filename had been used by a file that has since been deleted, and PyPI never permits
filename reuse. Package contents are identical to 1.7.0.

## [1.7.0] 2026-08-01 00:45:53 [NOT PUBLISHED]

### Added
- **`adapters/cli/safe_console.py`, an encode-safe replacement for `click.echo`.** A Windows console at
  codepage 1252 gives Python an `errors="strict"` stream, so writing a check mark raises
  `UnicodeEncodeError: 'charmap' codec can't encode character '✓'` and the command exits 1 *after*
  its work has already succeeded. Click does not protect against this, and Rich raises the same way
  through its own writer. `safe_console.echo` degrades at the sink, so a UTF-8 terminal and every email
  body still receive the character and only a stream that cannot encode it sees `[OK]` / `[X]` /
  `[!]`; `safe_console.safe_stream` wraps a writer handed to Rich.

  The template itself never emitted such a character, but nine repos derived from it have since
  drifted into doing so, which is why the protection and its guard now ship from here.

### Changed
- All 21 `click.echo` call sites route through `safe_console.echo`. `tests/test_safe_console.py` asserts that
  no module calls `click.echo` or builds an unwrapped `Console(file=sys.stdout)` again, so a project
  scaffolded from this template keeps the property by construction.

## [1.6.2] 2026-07-24 12:00:55

### Fixed
- CI (scheduled runs install the latest ruff) went red on `PLR0917` (too many positional arguments) for the four CLI command callbacks. Their option parameters are now keyword-only, which matches how Click actually invokes them (`f(ctx, **ctx.params)`) and drops the positional-argument count without suppressing the rule.

### Changed
- Removed the blanket `[tool.ruff.lint].ignore` list and fixed each cause at the root instead of silencing it: `RUF002` (en-dash to ASCII hyphen), `RUF022` (sorted `__all__`), `TC001`/`TC002`/`TC003` (typing-only imports moved into `TYPE_CHECKING`), and `TC006` (quoted `cast()` type expressions).
- Added `[tool.ruff.lint.flake8-type-checking] runtime-evaluated-base-classes = ["pydantic.BaseModel"]` so the Pydantic models keep their field-type imports at runtime while the type-checking rules still apply everywhere else.
- Genuinely deferred imports (the root/commands circular-import break, lazy heavy imports) now carry a narrow, documented `# noqa: PLC0415`; unjustified deferred imports were moved to module top. Deferred imports inside tests remain a deliberate idiom and are scoped-ignored.

## [1.6.1] - 2026-07-20

Re-release of 1.6.0. PyPI rejected the 1.6.0 upload because that filename was previously used by a file that has since been deleted, and PyPI never permits filename reuse. Package contents are identical to 1.6.0.

### Added
- `send_email()` and `send_notification()` accept an optional `transport` argument, exposing btx_lib_mail's `Transport` port so a delivery double can be injected at a real seam instead of monkeypatching `smtplib`.

### Fixed
- Mail tests failed against btx_lib_mail 1.5.0, which streams the message over the wire protocol directly (MAIL/RCPT plus DATA or BDAT) instead of calling `smtp.sendmail()`. The suite now injects a recording transport and asserts delivery intent (envelope sender, recipients, host failover order, credentials, payload), so it no longer depends on the library's internals.
- `ConfMail.smtp_password` is a `SecretStr` as of btx_lib_mail 1.5.0 and is now unwrapped before comparison.
- `config-deploy` emits an ASCII marker so it cannot crash on a cp1252 Windows console.
- `validate_profile` normalised to raise `ValueError`.
- DEVELOPMENT.md referenced a `make test-slow` target that no longer exists (4 places); the target is `make testintegration`. It also documented the SMTP username environment variable as `EMAIL__SMTP_USER`, but the field is `smtp_username`, so the correct name is `EMAIL__SMTP_USERNAME`.

### Documentation
- DEVELOPMENT.md documents the SMTP test seam: inject a `transport` double instead of patching `smtplib`, and leave `transport` off the application ports.

### Changed
- Raised the `btx_lib_mail` floor to `>=1.5.0`, which the injected transport seam requires. Other dependency floors refreshed and the current bmk Makefile adopted.
- CI: configurable pytest marker exclusion, pip-audit scoped to the project dependency tree with direct-URL dependencies filtered out, `actions/checkout` v7 and `actions/cache` v6.
- `codecov-cli` disabled (it capped `click<8.3.0` and held click on CVE-2026-7246); the redundant PYSEC-2026-2132 ignore dropped.
- LF line endings pinned via `.gitattributes`; file modes normalised so the executable bit is set only on shebang scripts.
- Quickstart notebook installs the package with uv.

## [1.6.0] - 2026-07-20 [NOT PUBLISHED]

Tagged and released on GitHub, but never published to PyPI: the upload was rejected because the `1.6.0` filename had been used by a previously deleted file. Superseded by 1.6.1, which carries the same changes.

## [1.5.4] 2026-06-14

### Changed
- Added a `typed_click.py` facade wrapping rich-click's `option` / `version_option` decorators behind explicit, fully-known signatures, keeping the CLI strict-clean under pyright 1.1.410 (`reportUnknownMemberType`) without disabling the rule (ignore isolated to the facade).
- Bumped internal dependency floors: `lib_cli_exit_tools>=2.3.2`, `lib_log_rich>=6.3.5`, `lib_layered_config>=5.5.2`, `btx_lib_mail>=1.3.2`.

## [1.5.3] - 2026-03-30

### Changed
- Bumped Codecov GitHub Action to V6
- Updated CVE exclusion list: removed stale entries, added inline documentation for remaining exclusions
- pip-audit set to warning-only to reduce CI noise

### Fixed
- Email transport: minor improvements to SMTP handling

## [1.5.2] - 2026-03-05

### Fixed
- Re-release as 1.5.2: PyPI rejected 1.5.1 due to filename reuse after prior upload deletion

### Changed
- `get_permission_defaults()` now returns a `PermissionDefaults` Pydantic model instead of a raw dict, with typed field access and `dir_mode_for()`/`file_mode_for()` methods
- `EmailSpy` now stores captured calls as `CapturedEmail` and `CapturedNotification` frozen dataclasses instead of `list[dict[str, Any]]`

### Added
- Tests for `--env-file` CLI option (argument passing, validation, end-to-end integration)

## [1.5.1] - 2026-03-05 [YANKED]

### Changed
- `get_permission_defaults()` now returns a `PermissionDefaults` Pydantic model instead of a raw dict, with typed field access and `dir_mode_for()`/`file_mode_for()` methods
- `EmailSpy` now stores captured calls as `CapturedEmail` and `CapturedNotification` frozen dataclasses instead of `list[dict[str, Any]]`

### Added
- Tests for `--env-file` CLI option (argument passing, validation, end-to-end integration)

## [1.5.0] - 2026-03-02

### Added
- `--env-file PATH` global CLI option to load an explicit `.env` file instead of searching upward from the working directory
- `dotenv_path` parameter added to `GetConfig` protocol, config loader, and in-memory adapter
- `__all__` to `__init__conf__.py` listing all public symbols
- `@pytest.mark.integration` marker on email integration tests

### Fixed
- Subprocess tests (`test_module_entry_subprocess_help`, `test_module_entry_subprocess_version`) now pass without editable install by setting `PYTHONPATH` to `src/`
- pip-audit CVE-2025-8869 ignore (pip is environment-level, not a project dependency)

### Changed
- CI workflow: dynamic Python version matrix extracted from `pyproject.toml` classifiers
- CI workflow: ruff cache restricted to GitHub-hosted runners
- CI workflow: bandit reads configuration from `pyproject.toml` (`-c pyproject.toml`)
- CI workflow: Codecov upload uses dynamically resolved latest Python version
- Release workflow: `actions/upload-artifact` upgraded to v7
- Added `[tool.hatch.metadata]` and `[tool.bashate]` sections to `pyproject.toml`
- Documentation updates: CONFIG.md, README.md, DEVELOPMENT.md for `--env-file` option

## [1.4.1] - 2026-02-13

### Fixed
- `reset_git_history.sh`: fixed shellcheck SC1083 warning by quoting `HEAD^{tree}` and normalized indentation to 4 spaces (shfmt)

### Changed
- Updated Makefile from v2.2.1 to v2.3.3
- Bumped dependency minimums: `lib_cli_exit_tools` >=2.3.0, `lib_log_rich` >=6.3.3, `lib_layered_config` >=5.4.1
- Added CVE ignore entries for CVE-2026-26007 and CVE-2026-25990
- Updated CI/CD workflows and added Bash 4+ requirement for macOS

## [1.4.0] - 2026-02-13

### Changed
- **Build automation**: replaced `scripts/` directory with `bmk`-based Makefile (`uvx bmk@latest`); all build, test, bump, push, and release tasks now delegated to `bmk`
- Makefile updated to v2.2.1 with alias targets, trailing argument forwarding, and new commands (config, email, info, logdemo)

## [1.3.1] - 2026-02-13

### Fixed
- `tests/test_metadata_sync.py`: replaced `importlib.metadata` lookups with direct `pyproject.toml` reads - tests no longer fail when the package is not installed in the test environment (uvx)
- Makefile `dev` target now correctly installs dev extras (`uv pip install -e ".[dev]"`)

### Changed
- CLAUDE.md: updated project structure trees to reflect actual codebase (added `entry.py`, `domain/errors.py`, `adapters/memory/`, `adapters/config/permissions.py`, `adapters/email/validation.py`; removed deleted `traceback.py`)
- CLAUDE.md: rewrote Make targets table to match new `bmk`-based Makefile (added aliases, new targets; removed obsolete `menu`, `test-slow`)
- CLAUDE.md: corrected versioning documentation - runtime metadata is served from `__init__conf__.py` constants, not `importlib.metadata`
- CLAUDE.md: replaced stale `scripts/` instrumentation section with `bmk` delegation note
- CLAUDE.md: updated `make test-slow` references to `make testintegration`

## [1.3.0] - 2026-02-01

### Added
- **File permission options for `config-deploy`**: `--permissions/--no-permissions`, `--dir-mode`, `--file-mode`
- **Configurable permission defaults** in `[lib_layered_config.default_permissions]` (app/host: 755/644, user: 700/600)
- **Octal string support** in config files (`"0o755"`, `"755"`, or decimal `493`)

### Changed
- `deploy_configuration()` accepts `set_permissions`, `dir_mode`, `file_mode` parameters
- CONFIG.md: comprehensive CLI options reference, `sudo -u` deployment examples

## [1.2.1] - 2026-02-01

### Changed
- **Profile validation** now delegates to `lib_layered_config.validate_profile_name()` with comprehensive security checks:
  - Maximum length enforcement (64 characters)
  - Empty string rejection
  - Windows reserved name rejection (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
  - Leading character validation (must start with alphanumeric)
  - Path traversal prevention (/, \, ..)
- `validate_profile()` now accepts optional `max_length` parameter for customization

### Added
- `40-layered-config.toml` in `defaultconfig.d/` documenting lib_layered_config integration settings
- Profile validation tests for length limits, empty strings, Windows reserved names, and leading character rules
- Profile name requirements documentation in CONFIG.md and README.md

### Removed
- Custom `_PROFILE_PATTERN` regex - replaced by lib_layered_config's built-in validation

## [1.2.0] - 2026-01-30

### Added
- **Attachment security settings** for email configuration (`[email.attachments]` section in `50-mail.toml`)
  - `allowed_extensions` / `blocked_extensions` - whitelist/blacklist file extensions
  - `allowed_directories` / `blocked_directories` - whitelist/blacklist attachment source directories
  - `max_size_bytes` - maximum attachment file size (default 25 MiB, 0 to disable)
  - `allow_symlinks` - whether symbolic links are permitted (default false)
  - `raise_on_security_violation` - raise or skip on violations (default true)
- New `EmailConfig` fields for attachment security with Pydantic validators
- `load_email_config_from_dict()` now flattens nested `[email.attachments]` section

### Changed
- Bumped `btx_lib_mail` dependency from `>=1.2.1` to `>=1.3.0` for attachment security features

## [1.1.2] - 2026-01-28

### Fixed
- Coverage SQLite "database is locked" errors on Python 3.14 free-threaded builds and network mounts (SMB/NFS)
- Removed bogus `COVERAGE_NO_SQL=1` environment variable from `scripts/test.py` (not a real coverage.py setting)
- CI workflow now sets `COVERAGE_FILE` to `runner.temp` so coverage always writes to local disk
- **Import-linter was a silent no-op** in `make test` / `make push` - `python -m importlinter.cli lint` silently exits 0 without checking; replaced with `lint-imports` (the working console entry point)
- CI/local parameter mismatches: ruff now targets `.` (not hardcoded `src tests notebooks`), pytest uses `python -m pytest` with `--cov=src/$PACKAGE_MODULE`, `--cov-fail-under=90`, and `-vv` matching local runs
- `scripts/test.py` bandit source path now reads `src-path` from `[tool.scripts.test]` instead of hardcoding `Path("src")`
- `scripts/test.py` module-level `_default_env` now rebuilt with configured `src_path` before running checks
- `run_slow_tests()` now reads pytest verbosity from `[tool.scripts.test].pytest-verbosity` instead of hardcoding `"-vv"`

### Changed
- **pyproject.toml as single source of truth**: CI workflow extracts all tool configuration (src-path, pytest-verbosity, coverage-report-file, fail_under, bandit skips) from `pyproject.toml` via metadata step - workflow is portable across projects without editing
- `scripts/test.py` removed module-level `PACKAGE_SRC` constant; bandit source path computed from `config.src_path` inside the functions that need it
- `make push` now accepts an unquoted message as trailing words (e.g. `make push fix typo in readme`); commit message format is `<version> - <message>`, defaulting to `<version> - chores` when no message is given
- Removed interactive commit-message prompt from `push.py` - message is either provided via CLI args / `COMMIT_MESSAGE` env var, or defaults to `"chores"`

### Added
- `pytest_configure` hook in `tests/conftest.py` that redirects coverage data to `tempfile.gettempdir()` and purges stale SQLite journal files before each run

## [1.1.1] - 2026-01-28

### Fixed
- CLAUDE.md: replaced stale package name `bitranox_template_cli_app_config_log_mail` with `pve_winrepair` throughout
- Brittle SMTP mock assertions in `test_cli.py` now use structured `call_args` attributes instead of `str()` coercion
- Stale docstring in `__init__conf__.py` claiming "adapters/platform layer" - corrected to "Package-level metadata module"
- Weak OR assertion in `test_cli.py` for SMTP host display - replaced with two independent assertions
- Removed stale `# type: ignore[reportUnknownVariableType]` from `sender.py` (`btx_lib_mail.ConfMail` now has proper type annotations)
- Late function-body imports in `adapters/cli/commands/config.py` moved to module-level for consistency

### Removed
- Dead code: unused `_format_value()` and `_format_source()` wrappers in `adapters/config/display.py`

### Added
- `__all__` to `__init__conf__.py` listing all public symbols
- `tests/test_enums.py` with parametrized tests for `OutputFormat` and `DeployTarget`
- Expanded `tests/test_behaviors.py` with return type, constant value, and constant-usage checks
- Python 3.14 classifier in `pyproject.toml`
- Codecov upload step in CI workflow (gated to `ubuntu-latest` + `3.13`)
- Edge-case tests for `parse_override`: bare `=value`, bare `=`, and CLI `--set ""` empty string
- Duplication-tracking comments for CI metadata extraction scripts

### Changed
- `tests/test_display.py` rewritten to test `_format_raw_value` and `_format_source_line` directly (replacing dead wrapper tests)

## [1.1.0] - 2026-01-27

### Changed
- Replaced `MockConfig` in-memory adapter with real `Config` objects in all tests (`config_factory` / `inject_config` fixtures)
- Replaced `MagicMock` Config objects in CLI email tests with real `Config` instances
- Unified test names to BDD-style `test_when_<condition>_<behavior>` pattern in `test_cli.py`
- Email integration tests now load configuration via `lib_layered_config` instead of dedicated `TEST_SMTP_SERVER` / `TEST_EMAIL_ADDRESS` environment variables

### Added
- Cache effectiveness tests for `get_config()` and `get_default_config_path()` LRU caches (`tests/test_cache_effectiveness.py`)
- Callable Protocol definitions in `application/ports.py` for all adapter functions, with static conformance assertions and `tests/test_ports.py`
- `ExitCode` IntEnum (`adapters/cli/exit_codes.py`) with POSIX-conventional exit codes for all CLI error paths
- `logdemo` and `config-generate-examples` CLI commands
- `--set SECTION.KEY=VALUE` repeatable CLI option for runtime configuration overrides (`adapters.config.overrides` module)
- Unit tests for config overrides and display module (sensitive key matching, redaction, nested rendering)

### Removed
- Dead code: `raise_intentional_failure()`, `noop_main()`, `cli_main()`, duplicate `cli_session` orchestration, catch-log-reraise in `send_email()`
- Replaced dead `ConfigPort`/`EmailPort` protocol classes with callable Protocol definitions

### Fixed
- POSIX-conventional exit codes across all CLI error paths (replacing hardcoded `SystemExit(1)`)
- Sensitive value redaction: word-boundary matching to avoid false positives, nested dict/list redaction, TOML sub-section rendering
- Email validation: reject bogus addresses (`@`, `user@`, `@domain`); IPv6 SMTP host support; credential construction
- Profile name validation against path traversal
- Security: list-based subprocess calls in scripts, sensitive env-var redaction in test output, stale CVE exclusion cleanup
- Documentation: wrong project name references, truncated CLI command names, stale import paths, wrong layer descriptions
- CI: `actions/download-artifact` version mismatch, stale `codecov.yml` ignore patterns
- Unified `__main__.py` and `adapters/cli/main.py` error handling via delegation

### Changed
- Precompile all regex patterns in `scripts/` as module-level constants for consistent compilation
- **LIBRARIES**: Replace custom redaction/validation with `lib_layered_config` redaction API and `btx_lib_mail` validators; bump both libraries
- **LIBRARIES**: Replace stdlib `json` with `orjson`; replace `urllib` with `httpx` in scripts
- **ARCHITECTURE**: Purified domain layer - `emit_greeting()` renamed to `build_greeting()` (returns `str`, no I/O); decoupled `display.py` from Click
- **DATA ARCHITECTURE**: Consolidated `EmailConfig` into single Pydantic `BaseModel` (eliminated dataclass conversion chain)

## [1.0.0] - 2026-01-15

### Added
- Slow integration test infrastructure (`make test-slow`, `@pytest.mark.slow` marker)
- `pydantic>=2.0.0` dependency for boundary validation
- `CLIContext` dataclass replacing untyped `ctx.obj` dict
- Pydantic models: `EmailSectionModel`, `LoggingConfigModel`
- `application/ports.py` with Protocol definitions; `composition/__init__.py` wiring layer

### Changed
- **BREAKING**: Full Clean Architecture refactoring into explicit layer directories (`domain/`, `application/`, `adapters/`, `composition/`)
- CLI restructured from monolithic `cli.py` into focused `cli/` package with single-responsibility modules
- Type hints modernized to Python 3.10+ style
- Removed backward compatibility re-exports; tests import from canonical module paths
- `import-linter` contracts enforce layer dependency direction
- `make test` excludes slow tests by default

## [0.2.5] - 2026-01-01

### Changed
- Bumped `lib_log_rich` to >=6.1.0 and `lib_layered_config` to >=5.2.0

## [0.2.4] - 2025-12-27

### Fixed
- Intermittent test failures on Windows when parsing JSON config output (switched to `result.stdout`)

## [0.2.3] - 2025-12-15

### Changed
- Lowered minimum Python version from 3.13 to 3.10; expanded CI matrix accordingly

## [0.2.2] - 2025-12-15

### Added
- Global `--profile` option for profile-specific configuration across all commands

### Changed
- **BREAKING**: Configuration loaded once in root CLI command and stored in Click context for subcommands
- Subcommand `--profile` options act as overrides that reload config when specified

## [0.2.0] - 2025-12-07

### Added
- `--profile` option for `config` and `config-deploy` commands
- `OutputFormat` and `DeployTarget` enums for type-safe CLI options
- LRU caching for `get_config()` (maxsize=4) and `get_default_config_path()`

### Fixed
- UTF-8 encoding issues in subprocess calls across different locales

## [0.1.0] - 2025-12-07

### Added
- Email sending via `btx-lib-mail` integration: `send-email` and `send-notification` CLI commands
- Email configuration support with `EmailConfig` dataclass and validation
- Real SMTP integration tests using `.env` configuration

## [0.0.1] - 2025-11-11
- Bootstrap
