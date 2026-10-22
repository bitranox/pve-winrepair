# AI transparency

The author and owner of this project is the human, [@bitranox](https://github.com/bitranox).
Every design and engineering decision is theirs, and they answer for everything published here.
An AI assistant (Claude, run through the Claude Code CLI) was used as a tool along the way,
mostly for the typing and the legwork under that direction. This page says where, plainly, so
you can weigh the work on its merits. The reasoning behind working this way is in
[ai-stance.md](ai-stance.md).

## The human's work

This is a template: a scaffold other Python command-line applications are copied from. Its shape
is the human's, start to finish. They set the problem and made every call.

- The problem is theirs: every new command-line tool needs the same plumbing (configuration from
  files and the environment, logging, error handling, exit codes, a release pipeline), and
  rebuilding it per project means doing it in a hurry and slightly wrong each time. The good
  defaults should be inherited once instead of retyped.
- Every structural decision was the human's: the Python 3.10 baseline; the clean-architecture
  layering (domain, application ports, adapters, composition), enforced in CI by import-linter
  contracts; ports as typed protocols with in-memory adapters, so tests swap a collaborator
  instead of patching internals; layered configuration through `lib_layered_config` (defaults,
  app, host, user, `.env` and environment, with named profiles, `--set` overrides and the source
  of every value shown by `config`); structured logging through `lib_log_rich` with its secret
  scrubber; POSIX `sysexits` exit codes, so a script can tell a bad configuration (78) from a
  refused permission (13); console output that survives a Windows
  codepage; and the whole lint, type, test and release pipeline driven through bmk behind a
  single `make` command. Where there were options, the human picked.
- The human reviewed and corrected the work at each step; what ships is what they signed off on.
- Every commit went out under the human's name and authority, with no AI co-author line. The
  human is responsible for what is published.

## Where the AI was used

As a tool, under the human's direction, it did the mechanical parts: typing the modules, the
CLI commands, the tests and the docs to the human's design; carrying template changes into the
applications built from it and auditing each merge for anything it dropped; keeping
`pyproject.toml`, the metadata module and the docs consistent with each other; laying out options
at each fork for the human to choose from; and checking the prose against the actual code so the
docs describe what the code does now. None of the decisions, and none of the accountability, were
the AI's. The human directed and approved every action and owns the result.

## What's been checked

The template's own gate is `make test`, and CI runs the same checks: Ruff (lint and format),
Pyright in strict mode, the import-linter layer contracts, Bandit, pip-audit, and Pytest with
coverage, including the doctests embedded in the source modules. CI runs them on Linux, macOS and
Windows for every Python version from 3.10 to 3.15 on every push and pull request. The badges at
the top of the README report the live state.

## Checking it yourself

You do not have to take any of this on faith.

- The source is available. Read `src/pve_winrepair/`; the module-by-module map is in
  [docs/systemdesign/module_reference.md](docs/systemdesign/module_reference.md).
- The history is available too. Decisions and reversals show up over time.
- The tests live in `tests/` and the doctests live in the modules. Run `make test` and see.

If something does not line up, open an issue. That is what they are for.

## What this isn't

It is a starting point, not a framework. The shipped domain is deliberately tiny (a greeting, an
intentional failure, a metadata printout, plus the configuration and logging commands) and
exists to prove that the layering, configuration, packaging and error handling work end to end.
A project copied from this template inherits this page with its name swapped; it should describe
its own work here instead.

## License and attribution

The text and code here are under the MIT License (see [LICENSE](LICENSE)). Anthropic's terms put
ownership of model output with the user, so the human owns this and answers for it.
