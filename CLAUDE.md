# CLAUDE.md — Project Guardrails & Development Requirements

`pydebuprep` is a post-upgrade health reporter for Debian and Ubuntu that runs as
**root** on production servers. Its most important property is that it **never
modifies the system it inspects** and **cannot be tricked by unprivileged local
users, log entries, or remote portal configs**.

Follow every rule in this file when making changes.

## Required Checks Before Finishing Any Change

Run all four commands in `.venv` and fix any failure before concluding:

```sh
make generated                         # keep example-config and shell completions in sync
make lint                              # ruff check, ruff format --check, flake8, mypy
.venv/bin/bandit -r src scripts        # static security analysis
make coverage                          # pytest with 100% line AND branch coverage required
```

- **100% line and branch coverage (`fail_under = 100`) is mandatory.** Write real
  tests for every new branch; do not add `# pragma: no cover` to bypass coverage.
- **Do not silence linters (`# noqa`, `# type: ignore`, `# nosec`)** unless strictly
  necessary and accompanied by a short explanation on the same line.
- **Documentation is tested against the code** (`tests/test_docs_site.py`,
  `tests/test_docs_portal.py`, `tests/test_manpage.py`, `tests/test_readme_and_example.py`,
  `tests/test_schema.py`). Any change to checks, options, CLI flags, or allowed
  commands must update the corresponding docs and schemas and run `make generated`.

## Security Guardrails (Enforced by `tests/test_allowlist.py`)

1. **All system access goes through `src/pydebuprep/system.py`:**
   - Never import `subprocess`, call `os.walk`, or call `open()` inside `src/pydebuprep/checks/`.
   - Checks must use `ctx.system` (`run_checked(ctx, argv)`, `read_text`, `read_bytes`,
     `read_range`, `lines`, `glob`, `walk_files`, `find_files`).
   - Every command executed by `System.run()` must match a complete entry in
     `ALLOWED_COMMANDS` (or the strict validators `_is_signature_check`, `_is_probe`,
     `SHOW_UNITS`, `UNIT_QUERIES`). Never pass `shell=True`.
   - Every `apt`/`apt-get`/`apt-cache`/`apt-mark` command must be built with
     `apt_command()` so `APT_RO_OPTS` prevents lock creation, cache regeneration, and
     `/var/log/apt/eipp.log.xz` writes.
   - Client environment variables that redirect connections or write files (`PG*`,
     `MYSQL*`, `MARIADB*`, `APT_*`, `DOCKER_*`) are stripped in `System.run()`.

2. **Safe file reading as root (`_open_regular`):**
   - Unprivileged users control `/home`, `/var/www`, and `/tmp`. Opening a symlink to
     `/dev/watchdog` as root arms a hardware reboot; `/dev/zero` exhausts memory; a
     FIFO blocks forever.
   - `System.read_text`, `read_bytes`, `read_range`, and `lines` must go through
     `_open_regular()`, which resolves symlinks, checks `stat.S_ISREG(os.lstat(real).st_mode)`
     *before* calling `os.open(real, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)`,
     checks `os.fstat` again on the opened descriptor, and bounds reads to
     `MAX_READ_BYTES` (16 MiB).
   - `portal.read_token()` must also open with `O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC`
     and verify `stat.S_ISREG` and mode `0600` (`st_mode & 0o077 == 0`).

3. **Safe file creation as root (`CREATE_FLAGS`):**
   - Any file created by `pydebuprep` (`snapshot.py`, `cli.py`, `state.py`,
     `system.write_scratch`) must be opened with `os.open(path, CREATE_FLAGS, 0o600)`
     where `CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC`.
   - Never use `open(path, "w")`, `open(path, "a")`, or `open(path, "x")` in production
     code (`tests/test_allowlist.py` rejects `open()` with write modes across the codebase).
   - `cli.resolve_output_path()` must check `path.exists() or path.is_symlink()` so a
     dangling symlink gets a timestamped filename rather than failing or being followed.

4. **Regular expressions from configs (`src/pydebuprep/patterns.py`):**
   - Every pattern a config gives (`logs.ignore`, a check's `ignore`) goes through
     `patterns_problems()`: at most 100 patterns, 200 characters each, and no repeated
     part that itself repeats without bound (catastrophic backtracking).

5. **Remote configuration restrictions (`src/pydebuprep/remote_config.py`):**
   - A config fetched via `--config https://…` is untrusted relative to root on the host.
   - It must never set write paths, credential paths, filesystem walk roots, or
     arbitrary HTTP probe targets.
   - Whenever you add a config setting or check option that names a file path, directory
     root, or network target, add it to `REMOTE_FORBIDDEN` or `CHECK_FORBIDDEN` in
     `src/pydebuprep/remote_config.py` and add a test in `tests/test_remote_config.py`.
   - Always bound numeric check options (such as `max_depth` or timeouts) in
     `Check.validate()`.

6. **Untrusted input & output sanitization:**
   - Log lines, unit names, package names, container statuses, snapshot fields, and
     portal responses can contain terminal escape sequences (CSI/OSC) or markup.
   - All human-readable renderers (`text`, `html`, `markdown`, `jira`, `confluence`)
     must render `clean_report(report)`, which runs `clean()` over every text field in
     `Report`, `Host`, `BaselineInfo`, `ConfigInfo`, `CheckResult`, and `Finding`.
   - Stderr warnings derived from snapshots (`baseline_warnings`) or portal replies
     (`_excerpt`, `upload_report` location) must also pass through `clean()`.
   - `Finding.references` must be validated with `safe_url()` (`http://` or `https://`
     only, no whitespace, control characters, or `<>`) both when loading saved reports
     (`reportfile.py`) and when rendering links (`html.py`, `markdown.py`, `_wiki.py`).
   - Always use `yaml.safe_load()` (never `yaml.load()`) and catch `RecursionError` on
     untrusted YAML/JSON inputs.
