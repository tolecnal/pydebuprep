# Development

## Set up

```sh
git clone https://github.com/tolecnal/pydebuprep && cd pydebuprep
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt && .venv/bin/pip install --no-deps -e .
```

| Command | Does |
|---|---|
| `make lint` | ruff (lint and format), flake8, mypy |
| `make test` | the test suite |
| `make coverage` | the tests with line and branch coverage, enforced at 100% |
| `make generated` | regenerate the example config and shell completions after changing commands, options or checks |
| `sudo make audit` | with the package installed: the read-only audit on this machine |
| `make deb` | build the package (needs `debhelper dh-python python3-all python3-setuptools python3-yaml python3-pytest`) |

The tests never touch the host: checks run against `FakeSystem`, an in-memory system
that refuses any command not on the allowlist.

## The documentation

This site is built with [Zensical](https://zensical.org/) from `docs/` and
`mkdocs.yml`, which Zensical reads:

```sh
python3 -m venv .venv-docs
.venv-docs/bin/pip install -r requirements-docs.txt
make docs          # strict: fails on broken links or missing pages; the site is in build/site/
make docs-serve    # http://127.0.0.1:8000
```

Facts that live in the code are generated, not written: each check page's
"At a glance" box and options, the checks index, the configuration reference and the
command-line reference come from `tools/docs_build.py`, which reads pydebuprep's
own registry, configuration schema and argument parser. `tests/test_docs_site.py`
fails if a check has no page, a page has no check, the navigation misses one, or
an allowlisted command isn't documented on any check page.

Every pull request builds the site; merges to `main` publish it.

## Adding a check

1. Create `src/pydebuprep/checks/<name>.py` with a `Check` subclass: set `id`,
   `title`, `category`, and `requires_root` / `requires_commands` if needed, and
   implement `run(ctx) -> list[Finding]`. Give every finding at least one
   remediation step.
2. To take part in snapshots, also implement `collect_baseline(ctx)` and
   `compare(ctx, before)`. For settings, declare
   `options = (Option("name", default, "help"),)` and read them with
   `self.opt("name")`; the type comes from the default, and the option appears in
   the configuration reference, `example-config`, `list-checks --verbose` and config
   validation automatically. Override `validate()` to check values against each
   other.
3. Add the class to `ALL_CHECKS` in `src/pydebuprep/checks/__init__.py`. Its
   `category` must be one of `CATEGORY_ORDER` in `src/pydebuprep/model.py`.
4. Run commands only through `run_checked(ctx, argv)`, which turns a timeout or an
   unexpected exit status into a check error instead of empty output. For a new
   command, add its **complete** argv to `ALLOWED_COMMANDS` in
   `src/pydebuprep/system.py`. Use `apt_command()` for anything apt.
5. Write tests under `tests/checks/` with `FakeSystem` and real command output;
   coverage must stay at 100%. Map each option to the test that proves it in
   `tests/test_option_coverage.py`.
6. Document it: a page `docs/checks/<id>.md` (copy an existing one: purpose, what
   it checks, findings, snapshot, commands, limitations, and the `facts` and
   `options` markers), an entry in `mkdocs.yml`'s navigation, a row in the
   README's checks table and an entry in the man page's CHECKS section. The docs
   tests fail until all of these match the code. Run `make generated`.
7. Prove it's read-only: run the new command under `scripts/readonly-audit.sh` as
   root with the service it inspects installed, and add that package to
   `scripts/ci-readonly-audit.sh` (and the command to `AUDIT_EXPECT` there) so every
   pull request is audited with it. Some obvious commands write (`nginx -t`,
   `postfix check`, `ufw status`); don't use those.

## Security guardrails

pydebuprep runs as root and inspects directories where unprivileged users can create
files and symlinks (`/home`, `/var/www`, `/tmp`), reads logs and journal entries
written by other users, and can fetch configs from a remote portal. Architectural
tests in `tests/test_allowlist.py` enforce these rules:

- **One module touches the system.** Only `src/pydebuprep/system.py` may import
  `subprocess` or call `os.walk`. Checks must read files, glob and run commands
  exclusively through `ctx.system`.
- **Opening files as root must refuse devices and FIFOs.** `System` opens files
  through `_open_regular()`, which resolves symlinks, verifies `stat.S_ISREG` before
  opening and again with `fstat` after, passes `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`, and caps reads at
  `MAX_READ_BYTES` (16 MiB). `portal.read_token()` likewise opens the token file with
  `O_NOFOLLOW | O_NONBLOCK` and checks `stat.S_ISREG`. Never use bare `open()` on
  paths that could be symlinks to `/dev/watchdog`, `/dev/zero` or a named pipe.
- **Every file pydebuprep creates uses `O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC`
  with mode `0600`.** Snapshots (`snapshot.py`), report files (`cli.py`), portal state
  (`state.py`) and scratch files (`system.py`) are opened with `os.open` and
  `CREATE_FLAGS`, never `open(..., "w")` or `open(..., "x")`.
- **Regular expressions from a config are limited** (`src/pydebuprep/patterns.py`):
  at most 100 patterns of 200 characters, and none that repeats a part which itself
  repeats without bound, so no pattern can backtrack for minutes over a log line.
  Compile every pattern a config gives through `patterns_problems()`.
- **Remote configs may not name files, search roots or HTTP probe paths.** If you add
  a config or check option that names a file to read or write, a directory tree to
  walk, or a URL/path to request, add it to `REMOTE_FORBIDDEN` or `CHECK_FORBIDDEN`
  in `src/pydebuprep/remote_config.py`. Bound integer depth/count options in
  `Check.validate()`.
- **Untrusted text is cleaned before rendering or printing to stderr.** Every
  human-readable renderer (`text`, `html`, `markdown`, `jira`, `confluence`) receives
  `clean_report(report)`, which strips C0/DEL/C1 control sequences from every string
  field (including `host`, `baseline`, `config` and `generated_at`). Portal error
  excerpts, upload locations and baseline warnings also pass through `clean()`.
  `Finding.references` must be `http://` or `https://` URLs (`safe_url()`), enforced
  both when loading reports (`reportfile.py`) and when rendering links.

## Releasing

Bump the version in `debian/changelog` (`dch -v X.Y.Z`) and in
`src/pydebuprep/__init__.py` together and merge that; then push a matching tag
from `main` (only maintainers can create release tags):

```sh
git tag -a vX.Y.Z -m "pydebuprep X.Y.Z" && git push origin vX.Y.Z
```

The Release workflow builds the package, audits it on every supported release, and
publishes it with checksums and a provenance attestation only if everything passes.

The release's notes are the version's `debian/changelog` entry, then how to verify the
download, then GitHub's list of merged pull requests. Write the entry for someone
deciding whether and how to upgrade (say what breaks, and what to upgrade first), and
preview the notes before tagging:

```sh
python3 scripts/release-notes.py X.Y.Z
```
