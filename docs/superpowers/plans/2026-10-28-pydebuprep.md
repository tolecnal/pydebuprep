# pydebuprep Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A read-only CLI, shipped as an `Architecture: all` `.deb`, that reports on the health of a Debian/Ubuntu system after a release upgrade, optionally comparing against a pre-upgrade snapshot.

**Architecture:** Checks are small classes registered in an explicit list; each receives a `Context` whose `System` object is the only code allowed to run commands or read files, and which enforces a read-only command allowlist. Checks produce `CheckResult`s into a single `Report` dataclass tree; five renderers turn that one tree into text/JSON/YAML/HTML/Markdown. Snapshots are the union of each check's `collect_baseline()` output.

**Tech Stack:** Python ≥ 3.10 stdlib, PyYAML (`python3-yaml`), pytest, ruff, flake8, mypy, debhelper + dh-python/pybuild.

**Spec:** `docs/superpowers/specs/2026-10-28-pydebuprep-design.md`

## Global Constraints

- Python floor 3.10: no `tomllib` at runtime, no `datetime.UTC` (use `datetime.timezone.utc`), no `except*`, no PEP 695 generics, no `typing.Self`/`override`. Use `from __future__ import annotations` in every module.
- Runtime deps: stdlib + `yaml` only.
- Nothing in `src/` imports `subprocess` or `os.walk`/`open` for system data except `src/pydebuprep/system.py`. Writes happen only in `snapshot.create_snapshot()` and `cli` when writing a report file.
- Every external command goes through `System.run()`, which rejects argv not matching `ALLOWED_PREFIXES` (Task 2). Commands run with `shell=False`, env `LC_ALL=C`, `LANG=C`, timeout default 30 s, output decoded UTF-8 with `errors="replace"`.
- All apt/apt-get/apt-cache invocations include `APT_RO_OPTS = ("-o", "Debug::NoLocking=1", "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=")` so apt neither locks nor rewrites its binary caches.
- Severity values: `critical`, `warning`, `info`. Status values: `ok`, `findings`, `skipped`, `error`.
- Exit codes: 0 none ≥ warning; 1 max is warning; 2 any critical; 3 tool error. Skipped/error checks don't affect it. Exit code is computed from all findings including `baseline_diff`, before `--min-severity` filtering (filtering is display-only — planner's call).
- Report filename: `pydebuprep-<hostname>-<YYYYmmddTHHMMSSZ>.<ext>` (UTC); ext map `text→txt, json→json, yaml→yaml, html→html, markdown→md`.
- Snapshot dir default `/var/lib/pydebuprep/snapshots`, created mode `0o750`; snapshot filename `<YYYYmmddTHHMMSSZ>.json`; `schema_version` `"1"` for both report and snapshot.
- Disk thresholds (boot-space, disk-space): free < 10 % → critical, < 25 % → warning; same for inodes.
- Evidence lists truncated to 20 lines, last line `... (+N more)`.
- Release table: bookworm 12 (debian, prev bullseye), trixie 13 (debian, prev bookworm), jammy 22.04 (ubuntu, prev focal), noble 24.04 (ubuntu, prev jammy), resolute 26.04 (ubuntu, prev noble).
- Tooling clean: `ruff check`, `ruff format --check`, `flake8`, `mypy src`, `pytest` — all pass before each commit. ruff `target-version = "py310"`, line length 100.
- Maintainer: `Jostein Elvaker Haande <jehaande@gmail.com>`. License MIT (`Expat` in `debian/copyright`).
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Running as non-root** — checks with `requires_root` become `skipped` with reason "requires root"; no tracebacks; exit code unaffected. Test: `tests/test_runner.py::test_non_root_skips_root_checks` (Task 3) and `tests/test_cli.py::test_report_as_non_root_exits_cleanly` (Task 6).
2. **Minimal hosts/containers missing tools** (no `dkms`, `efibootmgr`, `needrestart`, `debsums`, even no `systemctl`) — `skipped` with reason "command not found: X" and an install hint where applicable. Test: `tests/test_runner.py::test_missing_command_skips` (Task 3).
3. **A hung or crashing command** (e.g. `systemctl` with broken D-Bus) — `System.run` times out and the check becomes `error`, the rest of the report still renders. Tests: `tests/test_system.py::test_run_timeout_returns_result` (Task 2), `tests/test_runner.py::test_check_exception_becomes_error` (Task 3).
4. **Bad snapshot files** (invalid JSON, wrong schema_version, another host's snapshot) — explicit `--baseline` → exit 3 with a one-line message; auto-selection skips unreadable files and uses the next newest; other-host snapshot is used but a `warning` finding is added to `os-release`. Tests in Task 5 and Task 7.
5. **Huge or non-UTF-8 output and unwritable output paths** — evidence truncated, bytes replaced not crashing; `--output-dir` missing/unwritable → exit 3 with message. Tests: `tests/test_model.py::test_truncate_evidence`, `tests/test_system.py::test_run_decodes_invalid_utf8`, `tests/test_cli.py::test_unwritable_output_dir_exits_3`.

---

## File Structure

```
pyproject.toml  .flake8  Makefile  LICENSE  README.md  .gitignore
.github/workflows/ci.yml
man/pydebuprep.1
debian/{control,rules,changelog,copyright,pydebuprep.dirs,pydebuprep.manpages,source/format,tests/control}
src/pydebuprep/
  __init__.py  __main__.py  cli.py  model.py  system.py  osinfo.py  runner.py  snapshot.py
  checks/__init__.py  checks/base.py
  checks/os_release.py  checks/apt_sources.py  checks/apt_lists_age.py
  checks/dpkg_audit.py  checks/apt_upgradable.py  checks/apt_held.py  checks/apt_autoremove.py
  checks/dpkg_rc.py  checks/obsolete_packages.py  checks/config_conflicts.py  checks/debsums.py
  checks/kernel_running.py  checks/needrestart.py  checks/dkms.py  checks/bootloader.py
  checks/boot_space.py  checks/systemd_failed.py  checks/systemd_timers.py
  checks/journal_errors.py  checks/dmesg_errors.py  checks/boot_time.py
  checks/fstab.py  checks/disk_space.py  checks/_diskutil.py
  render/__init__.py  render/text.py  render/json_.py  render/yaml_.py  render/html.py  render/markdown.py
tests/
  fakes.py  conftest.py
  test_model.py  test_system.py  test_osinfo.py  test_runner.py  test_render.py
  test_snapshot.py  test_cli.py  test_allowlist.py
  checks/test_<module>.py   (one per check module)
```

---

### Task 1: Project scaffold and data model

**Files:**
- Create: `pyproject.toml`, `.flake8`, `Makefile`, `LICENSE`, `.gitignore`, `src/pydebuprep/__init__.py`, `src/pydebuprep/__main__.py` (calls `cli.main` — stub `cli.py` with `def main(argv: list[str] | None = None) -> int: return 0` for now), `src/pydebuprep/model.py`
- Test: `tests/test_model.py`

**Interfaces:**
- Produces (`pydebuprep.model`):
  - `__version__ = "0.1.0"` in `pydebuprep/__init__.py`
  - `class Severity(str, Enum)`: `CRITICAL="critical"`, `WARNING="warning"`, `INFO="info"`; property `rank -> int` (critical 3, warning 2, info 1)
  - `class Status(str, Enum)`: `OK="ok"`, `FINDINGS="findings"`, `SKIPPED="skipped"`, `ERROR="error"`
  - `@dataclass Finding(severity: Severity, title: str, detail: str = "", evidence: list[str] = [], remediation: list[str] = [], references: list[str] = [])` (use `field(default_factory=list)`)
  - `@dataclass CheckResult(id: str, title: str, category: str, status: Status, findings: list[Finding] = [], baseline_diff: list[Finding] | None = None, skipped_reason: str | None = None, error: str | None = None)`
  - `@dataclass Host(hostname: str, os_id: str, os_version: str, codename: str, kernel: str, is_root: bool)`
  - `@dataclass BaselineInfo(path: str, created_at: str, os_version: str, hostname: str)`
  - `@dataclass Summary(critical: int, warning: int, info: int, ok: int, skipped: int, error: int, exit_code: int)`
  - `@dataclass Report(tool: dict[str, str], generated_at: str, host: Host, baseline: BaselineInfo | None, summary: Summary, results: list[CheckResult], schema_version: str = "1")` with `to_dict() -> dict[str, Any]` — key order exactly: schema_version, tool, generated_at, host, baseline, summary, results; enums as their `.value`.
  - `CATEGORY_ORDER = ("release", "packages", "boot", "services", "storage")`
  - `truncate_evidence(lines: list[str], limit: int = 20) -> list[str]`
  - `compute_summary(results: list[CheckResult]) -> Summary` — counts findings by severity across `findings` + `baseline_diff`; `ok/skipped/error` count results by status; exit code per Global Constraints.
  - `sort_results(results: list[CheckResult]) -> list[CheckResult]` — by `CATEGORY_ORDER` index, then id.
  - `sort_findings(findings: list[Finding]) -> list[Finding]` — severity rank desc, stable.

- [ ] **Step 1: Scaffold config.** `pyproject.toml`: setuptools backend (`setuptools>=59`), `[project]` name `pydebuprep`, `requires-python = ">=3.10"`, `dependencies = ["PyYAML"]`, `license = {text = "MIT"}`, dynamic version from `pydebuprep.__version__`, `[project.scripts] pydebuprep = "pydebuprep.cli:main"`, `[project.optional-dependencies] dev = ["pytest", "ruff", "flake8", "mypy", "types-PyYAML"]`, src layout. `[tool.ruff]` target py310, line-length 100, lint select `E,F,W,I,B,UP,SIM,RUF,PL` (ignore `PLR0913,PLR2004`). `[tool.mypy]` `python_version = "3.10"`, `strict = true`, `files = ["src"]`. `[tool.pytest.ini_options]` `testpaths = ["tests"]`, `pythonpath = ["src"]`. `.flake8`: `max-line-length = 100`, `extend-ignore = E203,W503`. `Makefile` targets: `lint` (ruff check, ruff format --check, flake8 src tests, mypy), `test` (pytest -q), `deb` (`dpkg-buildpackage -us -uc -b`). `LICENSE`: MIT text, `Copyright (c) 2026 Jostein Elvaker Haande`. `.gitignore`: Python + `debian/.debhelper/`, `debian/pydebuprep/`, `debian/files`, `debian/*.substvars`, `debian/*.log`, `*.deb`, `*.buildinfo`, `*.changes`.

- [ ] **Step 2: Write failing tests** in `tests/test_model.py`:

```python
def test_summary_exit_code_critical():
    r = [CheckResult("a", "A", "packages", Status.FINDINGS, [Finding(Severity.CRITICAL, "x")])]
    assert compute_summary(r).exit_code == 2

def test_summary_exit_code_warning_from_baseline_diff():
    r = [CheckResult("a", "A", "packages", Status.FINDINGS, [], baseline_diff=[Finding(Severity.WARNING, "x")])]
    s = compute_summary(r)
    assert (s.warning, s.exit_code) == (1, 1)

def test_summary_ignores_skipped_and_error():
    r = [CheckResult("a", "A", "boot", Status.SKIPPED, skipped_reason="requires root"),
         CheckResult("b", "B", "boot", Status.ERROR, error="boom"),
         CheckResult("c", "C", "boot", Status.OK)]
    s = compute_summary(r)
    assert (s.skipped, s.error, s.ok, s.exit_code) == (1, 1, 1, 0)

def test_info_only_exit_0(): ...  # one INFO finding -> exit_code 0

def test_truncate_evidence():
    out = truncate_evidence([str(i) for i in range(25)])
    assert len(out) == 21 and out[-1] == "... (+5 more)"
    assert truncate_evidence(["a"]) == ["a"]

def test_sort_results_by_category_then_id():
    ids = [r.id for r in sort_results([CheckResult("z", "", "storage", Status.OK),
                                       CheckResult("b", "", "release", Status.OK),
                                       CheckResult("a", "", "release", Status.OK)])]
    assert ids == ["a", "b", "z"]

def test_report_to_dict_key_order_and_enum_values():
    d = sample_report().to_dict()   # helper builds a Report with one finding
    assert list(d) == ["schema_version", "tool", "generated_at", "host", "baseline", "summary", "results"]
    assert d["results"][0]["findings"][0]["severity"] == "critical"
    assert d["results"][0]["status"] == "findings"
```

Put `sample_report()` in `tests/conftest.py` as a fixture-free helper function `make_sample_report() -> Report` (also used by Task 4): three results — one `findings` with a critical and an info finding (with evidence, remediation, references) and a `baseline_diff` with one warning; one `skipped`; one `ok` with `baseline_diff=None`.

- [ ] **Step 3: Run** `pytest tests/test_model.py -v` → FAIL (import errors).
- [ ] **Step 4: Implement `model.py`** per Interfaces.
- [ ] **Step 5: Run** `pytest -q && make lint` → all pass.
- [ ] **Step 6: Commit** `feat: project scaffold and report data model`.

---

### Task 2: System access layer and OS detection

**Files:**
- Create: `src/pydebuprep/system.py`, `src/pydebuprep/osinfo.py`, `tests/fakes.py`
- Test: `tests/test_system.py`, `tests/test_osinfo.py`

**Interfaces:**
- Produces (`pydebuprep.system`):
  - `APT_RO_OPTS: tuple[str, ...]` (value in Global Constraints)
  - `ALLOWED_PREFIXES: tuple[tuple[str, ...], ...]` — argv must start with one of these (after the program name, `APT_RO_OPTS` appearing right after it are skipped when matching):
    `("dpkg","--audit")`, `("dpkg","--compare-versions")`, `("dpkg-query","-W")`, `("apt-get","check")`, `("apt-get","-s","autoremove")`, `("apt","list")`, `("apt-cache","policy")`, `("apt-mark","showhold")`, `("debsums","-c")`, `("uname","-r")`, `("needrestart","-b","-r","l")`, `("dkms","status")`, `("efibootmgr","-v")`, `("systemctl","list-units")`, `("systemctl","list-timers")`, `("systemd-analyze",)` (enforced: argv must be exactly `("systemd-analyze",)` or `("systemd-analyze","blame","--no-pager")`), `("journalctl","-p")`, `("dmesg","--level=err")`, `("dmesg","--level=warn")`, `("findmnt","--verify")`, `("findmnt","-rn")`, `("df","-P")`
  - `class DisallowedCommandError(Exception)`
  - `check_allowed(argv: Sequence[str]) -> None` — raises `DisallowedCommandError`
  - `@dataclass CommandResult(argv: tuple[str, ...], returncode: int, stdout: str, stderr: str, timed_out: bool = False)`; property `ok -> bool` (`returncode == 0 and not timed_out`)
  - `class System`: `run(argv: Sequence[str], timeout: float = 30.0) -> CommandResult` (calls `check_allowed` first; on `TimeoutExpired` returns `returncode=-1, timed_out=True`; on `FileNotFoundError` returns `returncode=127`); `which(name: str) -> bool`; `read_text(path: str) -> str | None` (None if missing/unreadable); `exists(path: str) -> bool`; `glob(pattern: str) -> list[str]` (sorted); `mtime(path: str) -> float | None`; `walk_files(root: str) -> Iterator[str]` (os.walk, ignore permission errors, don't follow symlinks); `disk_usage(path: str) -> DiskUsage | None`; `is_root() -> bool`; `hostname() -> str`; `now() -> datetime` (UTC aware)
  - `@dataclass DiskUsage(total: int, free: int, inodes_total: int, inodes_free: int)` (from `os.statvfs`, free = `f_bavail * f_frsize`)
- Produces (`tests/fakes.py`): `class FakeSystem(System)` constructed with `commands: dict[tuple[str, ...], CommandResult | str]` (str = stdout, rc 0), `files: dict[str, str]`, `mtimes: dict[str, float]`, `disks: dict[str, DiskUsage]`, `root: bool = True`, `available: set[str] | None = None` (None = every command available), `hostname: str = "testhost"`, `now: datetime`. `run()` calls the real `check_allowed` then looks up the argv tuple with `APT_RO_OPTS` stripped; unknown argv → `AssertionError` naming it. Records calls in `self.calls`. `glob` uses `fnmatch` over `files` keys; `walk_files` yields `files` keys under root.
- Produces (`pydebuprep.osinfo`):
  - `@dataclass(frozen=True) Release(codename: str, version: str, family: str, previous: str, notes_url: str)`
  - `RELEASES: dict[str, Release]` — the five from Global Constraints; notes URLs: `https://www.debian.org/releases/<codename>/releasenotes`, `https://discourse.ubuntu.com/t/<codename>-release-notes` (planner's call; builder may correct to the canonical URL).
  - `@dataclass OsInfo(id: str, version_id: str, codename: str, pretty_name: str, release: Release | None)`; property `supported -> bool`
  - `parse_os_release(text: str) -> dict[str, str]` (handles quotes, comments, blank lines)
  - `detect_os(system: System) -> OsInfo` — reads `/etc/os-release`, falls back to `/usr/lib/os-release`; codename from `VERSION_CODENAME`, else `UBUNTU_CODENAME`.
  - `known_codenames(family: str) -> set[str]` — codenames in `RELEASES` plus their `previous` values for the family (used by apt-sources).

- [ ] **Step 1: Failing tests** `tests/test_system.py`:
  - `test_check_allowed_accepts_apt_with_ro_opts`: `check_allowed(("apt", *APT_RO_OPTS, "list", "--upgradable"))` no raise.
  - `test_check_allowed_rejects_writes`: each of `("apt","update")`, `("apt-get","install","x")`, `("update-grub",)`, `("systemctl","restart","ssh")`, `("systemd-analyze","set-log-level","debug")`, `("sh","-c","ls")` raises `DisallowedCommandError`.
  - `test_run_timeout_returns_result`: monkeypatch `system.ALLOWED_PREFIXES` to include `("sleep",)`; `System().run(["sleep","5"], timeout=0.1)` → `timed_out` True, `ok` False.
  - `test_run_missing_binary_returns_127` (allow a nonexistent program name via monkeypatch).
  - `test_run_decodes_invalid_utf8`: allow `("printf",)`; run `["printf", "\\377ok"]` → stdout endswith `"ok"`, contains `"\ufffd"`.
  - `test_run_sets_c_locale`: allow `("env",)`; stdout contains `LC_ALL=C`.
  `tests/test_osinfo.py`: parse real-shaped trixie, noble and jammy os-release texts → `codename`, `version_id`, `release.version`; unknown codename `"forky"` → `supported` False; missing `/etc/os-release` uses `/usr/lib/os-release`; `known_codenames("debian") == {"bookworm","trixie","bullseye"}`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** `system.py`, `osinfo.py`, `tests/fakes.py` per Interfaces.
- [ ] **Step 4: Run** `pytest -q && make lint` → pass.
- [ ] **Step 5: Commit** `feat: read-only system access layer and OS detection`.

---

### Task 3: Check base, registry and runner

**Files:**
- Create: `src/pydebuprep/checks/base.py`, `src/pydebuprep/checks/__init__.py`, `src/pydebuprep/runner.py`
- Test: `tests/test_runner.py`

**Interfaces:**
- Consumes: `System`, `OsInfo`, model types.
- Produces (`pydebuprep.checks.base`):
  - `@dataclass Context(system: System, osinfo: OsInfo, baseline: dict[str, Any] | None = None)`; property `is_root -> bool` (delegates to system); `baseline_for(check_id: str) -> Any | None` (returns `baseline["checks"].get(check_id)` or None)
  - `class Check`: class attrs `id: str`, `title: str`, `category: str`, `requires_root: bool = False`, `requires_commands: tuple[str, ...] = ()`, `install_hint: str | None = None`; methods `run(self, ctx: Context) -> list[Finding]` (abstract), `collect_baseline(self, ctx: Context) -> Any | None` (default None), `compare(self, ctx: Context, before: Any) -> list[Finding]` (default `[]`), `supports_baseline` property (True if subclass overrides `collect_baseline`).
- Produces (`pydebuprep.checks`): `ALL_CHECKS: list[type[Check]]` (empty now; each later task appends its class import), `get_checks(only: Sequence[str] | None = None, skip: Sequence[str] = ()) -> list[Check]` — raises `ValueError(f"unknown check: {id}")` for unknown ids.
- Produces (`pydebuprep.runner`): `run_check(check: Check, ctx: Context) -> CheckResult`, `run_checks(checks: Sequence[Check], ctx: Context) -> list[CheckResult]` (returns `sort_results`).
  Rules for `run_check`, in order: requires_root and not root → SKIPPED "requires root (run with sudo for this check)"; any missing command → SKIPPED `f"command not found: {cmd}"` + `f"; {install_hint}"` if set; run → exceptions → ERROR with `f"{type(e).__name__}: {e}"`; findings sorted; status FINDINGS if any findings, else OK; `baseline_diff`: if `ctx.baseline` is None or not `supports_baseline` → None; else `before = ctx.baseline_for(id)`; if before is None (older snapshot lacking this check) → None; else `compare()` result sorted (exceptions in compare → ERROR as above). Status becomes FINDINGS if baseline_diff non-empty.

- [ ] **Step 1: Failing tests** (define tiny `Check` subclasses inside the test file):
  - `test_non_root_skips_root_checks` — `FakeSystem(root=False)`, check with `requires_root=True` → `Status.SKIPPED`, reason startswith `"requires root"`, and `run` never called.
  - `test_missing_command_skips` — `available=set()`, `requires_commands=("dkms",)`, `install_hint="apt install dkms"` → reason `"command not found: dkms; apt install dkms"`.
  - `test_check_exception_becomes_error` — run raises `RuntimeError("boom")` → `ERROR`, `error == "RuntimeError: boom"`; `run_checks` on [that, an OK check] returns both.
  - `test_baseline_diff_none_without_baseline`, `test_baseline_diff_list_with_baseline` (compare returns one warning → status FINDINGS, diff length 1), `test_baseline_missing_key_gives_none`.
  - `test_get_checks_unknown_raises`, `test_get_checks_skip`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** `pytest -q && make lint` → pass.
- [ ] **Step 5: Commit** `feat: check interface, registry and isolated runner`.

---

### Task 4: Renderers

**Files:**
- Create: `src/pydebuprep/render/__init__.py`, `text.py`, `json_.py`, `yaml_.py`, `html.py`, `markdown.py`
- Test: `tests/test_render.py`

**Interfaces:**
- Consumes: `Report`, `make_sample_report()` (tests/conftest.py).
- Produces (`pydebuprep.render`): `FORMATS = ("text", "json", "yaml", "html", "markdown")`, `EXTENSIONS: dict[str, str]` (Global Constraints), `render(report: Report, fmt: str, *, color: bool = False) -> str` (ValueError on unknown fmt).
- Document order for text/html/markdown (identical): title line `pydebuprep report` + host/os/kernel/generated_at/baseline line (or "Baseline: none"); summary counts and exit code; then per category in `CATEGORY_ORDER` a heading; per check: `[STATUS] id — title`, skipped reason or error, findings each with `SEVERITY: title`, detail, evidence (code block / `<pre>`), "Remediation:" numbered list, references; then "Changes since baseline:" section — `no baseline` when `baseline_diff is None`, `no changes` when `[]`, otherwise findings in the same layout.
- JSON: `json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"`. YAML: `yaml.safe_dump(report.to_dict(), sort_keys=False, allow_unicode=True, default_flow_style=False)`.
- HTML: single document, inline `<style>` only, no `<script>`, no external URLs except `<a href>` in references; all text via `html.escape`; severity colour classes; `@media (prefers-color-scheme: dark)` block; `@media print` hides nothing essential.
- Text colour: ANSI only when `color=True` (critical red, warning yellow, info cyan, ok green).
- Markdown: `#` title, `##` category, `###` check; evidence in fenced blocks; escape `|`, `*`, `_`, backticks in inline text.

- [ ] **Step 1: Failing tests:**
  - `test_json_roundtrip_equals_to_dict` and `test_yaml_roundtrip_equals_to_dict` (`yaml.safe_load(render(r,"yaml")) == r.to_dict()`).
  - `test_all_formats_contain_same_items_in_same_order` — for each of text/html/markdown, collect positions of every check id, finding title, remediation line and the strings `"no baseline"`/`"no changes"` as applicable; assert every item present and positions strictly increasing in the same sequence as walking `to_dict()`.
  - `test_html_escapes_and_has_no_script` — a finding title `<script>alert(1)</script>` appears escaped; `"<script" not in output.lower()` except escaped form.
  - `test_text_no_ansi_without_color`, `test_text_ansi_with_color` (`"\x1b[" in out`).
  - `test_unknown_format_raises`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4:** `pytest -q && make lint` → pass.
- [ ] **Step 5: Commit** `feat: text, JSON, YAML, HTML and Markdown renderers`.

---

### Task 5: Snapshots

**Files:**
- Create: `src/pydebuprep/snapshot.py`
- Test: `tests/test_snapshot.py`

**Interfaces:**
- Consumes: `Check`, `Context`, `System`, `BaselineInfo`.
- Produces (`pydebuprep.snapshot`):
  - `DEFAULT_SNAPSHOT_DIR = "/var/lib/pydebuprep/snapshots"`, `SCHEMA_VERSION = "1"`
  - `class SnapshotError(Exception)`
  - `build_snapshot(checks: Sequence[Check], ctx: Context) -> dict[str, Any]` — `{"schema_version", "created_at" (ISO UTC), "hostname", "os": {"id","version_id","codename"}, "kernel", "checks": {id: data}}`; only checks with `supports_baseline`, skipping those whose root/command requirements fail (record their ids in `"skipped": [...]`); a `collect_baseline` exception records the id in `"skipped"` too.
  - `create_snapshot(checks, ctx, directory: str = DEFAULT_SNAPSHOT_DIR) -> Path` — `mkdir(parents=True, mode=0o750, exist_ok=True)`, writes `<timestamp>.json` with `indent=2`, never overwrites (append `-1`, `-2` if exists). Raises `SnapshotError` with a readable message on `OSError`.
  - `load_snapshot(path: str) -> dict[str, Any]` — raises `SnapshotError` on unreadable file, invalid JSON, or `schema_version != "1"`.
  - `find_latest(directory: str = DEFAULT_SNAPSHOT_DIR) -> tuple[str, dict[str, Any]] | None` — newest by filename that loads; skips bad files (logs a line to stderr).
  - `baseline_info(path: str, snap: dict[str, Any]) -> BaselineInfo`

- [ ] **Step 1: Failing tests** (use `tmp_path`, a FakeSystem, and two dummy checks — one with baseline data, one requiring root under `root=False`):
  - `test_create_and_load_roundtrip` — file exists, mode of dir `0o750`, `load_snapshot` equals written data, `"checks"` has only the baseline check, `"skipped"` lists the root one.
  - `test_create_never_overwrites` — two creates with same frozen `now` → two different files.
  - `test_load_invalid_json_raises`, `test_load_wrong_schema_raises`.
  - `test_find_latest_skips_corrupt` — files `20261001T000000Z.json` (good) and `20261002T000000Z.json` (corrupt) → returns the 1001 one.
  - `test_find_latest_empty_or_missing_dir_returns_none`.
  - `test_create_unwritable_dir_raises_snapshot_error` (dir path under a file).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4:** `pytest -q && make lint` → pass.
- [ ] **Step 5: Commit** `feat: pre-upgrade snapshot create/load/select`.

---

### Task 6: CLI

**Files:**
- Modify: `src/pydebuprep/cli.py` (replace stub)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: everything above.
- Produces (`pydebuprep.cli`):
  - `build_parser() -> argparse.ArgumentParser` — subcommands `report` (default when none given), `snapshot`, `list-checks`; `--version` prints `pydebuprep <version>`. Options exactly as spec §6; `--output` and `--output-dir` mutually exclusive; `--baseline` and `--no-baseline` mutually exclusive; `report` also accepts `--snapshot-dir DIR` (where auto-selection looks).
  - `resolve_output_path(output: str | None, output_dir: str | None, hostname: str, fmt: str, now: datetime) -> Path | None` — `output_dir` → `dir / f"pydebuprep-{hostname}-{ts}.{ext}"`; `output` not existing → as given; existing → `stem-{ts}{suffix}`; neither → None.
  - `main(argv: list[str] | None = None, *, system: System | None = None) -> int` — builds Context (`detect_os`), runs checks, builds Report (`tool={"name":"pydebuprep","version":__version__}`, host from system/osinfo, kernel from `uname -r`), applies `--min-severity` to a copy for rendering only, writes to stdout or file (prints `Report written to <path>` on stderr), returns `summary.exit_code`. `snapshot` prints the path and returns 0. Any `SnapshotError`, `ValueError` (unknown check), `OSError` writing output → message `pydebuprep: error: ...` on stderr, return 3. argparse errors also map to 3 (catch `SystemExit` with code 2 → return 3).
  - If `--baseline` given or auto-selected, `ctx.baseline` is the snapshot dict and `report.baseline = baseline_info(...)`.

- [ ] **Step 1: Failing tests** (register two dummy checks via `monkeypatch.setattr(checks, "ALL_CHECKS", [...])`, pass `FakeSystem` with `/etc/os-release` and `uname -r`):
  - `test_default_is_text_report_to_stdout(capsys)` — `main([])` output contains `"pydebuprep report"`; return code matches findings.
  - `test_json_format_parses` — `main(["report","--format","json"])` stdout `json.loads` works, `["summary"]["exit_code"]` equals return value.
  - `test_output_dir_writes_timestamped_file(tmp_path)` — filename `pydebuprep-testhost-20261028T120000Z.md` for `--format markdown` with frozen now.
  - `test_output_file_existing_gets_timestamp(tmp_path)`.
  - `test_unwritable_output_dir_exits_3`, `test_unknown_check_exits_3`, `test_bad_baseline_exits_3`, `test_bad_argument_exits_3`.
  - `test_report_as_non_root_exits_cleanly` — `root=False`, a root check → no traceback, exit reflects only the other check.
  - `test_min_severity_filters_display_not_exit_code` — info+warning findings, `--min-severity warning` → info title absent from output, exit 1.
  - `test_auto_baseline_used(tmp_path)` and `test_no_baseline_flag`.
  - `test_list_checks_prints_ids`, `test_version`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4:** `pytest -q && make lint` → pass; also `python -m pydebuprep --version`.
- [ ] **Step 5: Commit** `feat: command-line interface with exit codes and output handling`.

---

## Check tasks (7–12)

Every check task follows the same cycle: write `tests/checks/test_<module>.py` with `FakeSystem` fixtures using real-shaped command output → run, FAIL → implement the check class and append it to `ALL_CHECKS` → `pytest -q && make lint` → commit `feat(checks): <ids>`. Each finding must have at least one remediation line. Remediation is text; never auto-edits (prefer "edit FILE: change X → Y, then run `sudo apt update`" over sed one-liners).

Each table row gives: id / class name, category, root, commands, logic, findings, baseline data → compare, and the required tests (name: assertion).

### Task 7: Release and APT source checks

**Files:** `checks/os_release.py`, `checks/apt_sources.py`, `checks/apt_lists_age.py`; tests under `tests/checks/`.

- **`os-release` / `OsReleaseCheck`** (release; no root; no commands). Unsupported/unknown release → CRITICAL "Unsupported release <pretty_name>" with references to supported list. Supported → no findings. Baseline `{"id","version_id","codename","hostname"}` → compare: version changed → INFO "Upgraded from <before> to <now>" with current release notes URL in references; codename unchanged → WARNING "Baseline was taken on the same release; it may be a post-upgrade snapshot"; hostname differs → WARNING "Baseline is from host X".
  Tests: `test_unsupported_is_critical`, `test_supported_no_findings`, `test_compare_upgrade_info`, `test_compare_same_release_warns`, `test_compare_other_host_warns`.
- **`apt-sources` / `AptSourcesCheck`** (release; no root; files only). Parse `/etc/apt/sources.list`, `/etc/apt/sources.list.d/*` (any file name, including disabled suffixes). Expose `parse_sources(system: System) -> list[SourceEntry]` with `@dataclass SourceEntry(file: str, type: str, uri: str, suite: str, components: tuple[str, ...], enabled: bool, disabled_reason: str | None)`. One-line format: `deb|deb-src [opts] uri suite [components]`; a commented line counts as an entry only if it matches `^#\s*deb(-src)?\s` (enabled False, reason "commented out", or "disabled on upgrade to X" when the trailing comment says so). deb822: blank-line separated stanzas; `Types`, `URIs`, `Suites`, `Components` multi-valued; `Enabled: no` → disabled. Files ending `.distUpgrade`, `.save`, `.disabled`, `.dpkg-old`, `.bak` → all entries disabled, reason `f"file renamed to *{suffix}"`. Suite base = suite with `-updates/-security/-backports/-proposed/-proposed-updates` and `/updates` stripped.
  Findings: enabled entry whose suite base ∈ `known_codenames(family)` but ≠ current codename → WARNING "Repository still targets <suite>" (evidence `file: line`); disabled third-party entries (URI host not containing `debian.org`, `ubuntu.com`, `canonical.com`) → WARNING "Third-party repository disabled by upgrade" with remediation to check vendor support for `<codename>` and re-enable; duplicate (type, uri, suite, component) across files → INFO; no enabled entry for the distro's own archive → CRITICAL. Suites like `stable`/`testing` on Debian archive → INFO "uses suite alias".
  Baseline: list of dicts `{file, uri, suite, enabled}` → compare: entry (by uri) enabled before and now absent or disabled → WARNING "Repository <uri> was enabled before the upgrade".
  Tests: `test_parse_one_line_and_deb822`, `test_old_codename_warns` (noble host, jammy line), `test_ubuntu_disabled_on_upgrade_comment`, `test_distupgrade_file_disabled`, `test_debian_security_updates_suffix_ok` (`trixie-security`), `test_third_party_unknown_suite_ignored` (`deb https://download.docker.com/linux/ubuntu noble stable` → no finding; `... stable` suite on non-Debian host ignored), `test_missing_distro_archive_critical`, `test_compare_repo_disabled_since_baseline`.
- **`apt-lists-age` / `AptListsAgeCheck`** (release; no root). Newest `mtime` of `/var/lib/apt/lists/*_InRelease` and `*_Release`. None → WARNING "No downloaded package lists" (remediation `sudo apt update`). Older than 7 days → INFO "Package lists are N days old; upgradable/obsolete results may be stale". Tests: `test_no_lists_warns`, `test_old_lists_info`, `test_fresh_lists_ok`.

Commit: `feat(checks): os-release, apt-sources, apt-lists-age`.

### Task 8: Package state checks

**Files:** `checks/dpkg_audit.py`, `apt_upgradable.py`, `apt_held.py`, `apt_autoremove.py`, `dpkg_rc.py`, `obsolete_packages.py`.

All apt calls prefix `APT_RO_OPTS` right after the program name.

| id / class | cmds | logic → finding | tests |
|---|---|---|---|
| `dpkg-audit` / `DpkgAuditCheck` | `dpkg --audit`; `apt-get <RO> check` | non-empty audit stdout → CRITICAL "dpkg reports broken or half-configured packages" (remediation `sudo dpkg --configure -a`, then `sudo apt -f install`); check rc≠0 → CRITICAL with stderr evidence | `test_clean`, `test_audit_output_critical`, `test_apt_check_failure_critical` |
| `apt-upgradable` / `AptUpgradableCheck` | `apt <RO> list --upgradable` | drop `Listing...` and blank/`WARNING:` lines; any → WARNING "N packages can still be upgraded" (remediation `sudo apt update && sudo apt full-upgrade`) | `test_none`, `test_some_warns_with_count` |
| `apt-held` / `AptHeldCheck` | `apt-mark showhold` | any → WARNING list (remediation `sudo apt-mark unhold PKG` if no longer needed). Baseline: sorted list → held before and not now → INFO "no longer held"; held now not before → WARNING "newly held" | `test_held_warns`, `test_compare_new_hold` |
| `apt-autoremove` / `AptAutoremoveCheck` | `apt-get <RO> -s autoremove` | lines `^Remv (\S+)` → INFO "N packages are no longer needed" (remediation: review list, `sudo apt-mark manual PKG` for ones you want, then `sudo apt autoremove`) | `test_parses_remv_lines`, `test_none` |
| `dpkg-rc` / `DpkgRcCheck` | `dpkg-query -W -f=${db:Status-Abbrev} ${Package}\n` | lines starting `rc` → INFO (remediation `sudo apt purge <pkgs>` listing them, max 20 in one command) | `test_rc_packages_info` |
| `obsolete-packages` / `ObsoletePackagesCheck` | `apt <RO> list --installed`; `dpkg-query -W -f=${Package}\t${Version}\n` (baseline only) | lines whose bracket field contains `local` → WARNING "N installed packages are not available from any configured repository" (remediation: check `apt policy PKG`, replace or `sudo apt purge`). Baseline: `{pkg: version}` → compare: packages present before and missing now → INFO "N packages removed since baseline" (evidence list) | `test_local_packages_warn`, `test_compare_removed_packages` |

Commit: `feat(checks): package state checks`.

### Task 9: Config conflicts and debsums

**Files:** `checks/config_conflicts.py`, `checks/debsums.py`.

- **`config-conflicts` / `ConfigConflictsCheck`** (packages; no root, but if not root add an INFO "Some directories under /etc were not readable; run as root for complete results" only when `walk_files` reported permission errors — expose that via `System.walk_files(root, errors: list[str] | None = None)`; add the parameter in this task and in `FakeSystem`). Match file names ending `.dpkg-new`, `.dpkg-old`, `.dpkg-dist`, `.dpkg-bak`, `.ucf-new`, `.ucf-old`, `.ucf-dist`. Group by original path (suffix stripped). Original path `/etc/ssh/sshd_config`, `/etc/sudoers`, or under `/etc/sudoers.d/` → CRITICAL per file; others → one WARNING listing all. Remediation: `diff -u ORIGINAL ORIGINAL.dpkg-dist`, merge, then remove the leftover file.
  Tests: `test_sshd_conflict_critical`, `test_other_conflicts_single_warning`, `test_none_ok`.
- **`debsums` / `DebsumsCheck`** (packages; root; `debsums`, install_hint `sudo apt install debsums`). `debsums -c` (timeout 600). stdout paths → WARNING "N package files differ from their packaged checksums" with remediation `dpkg -S PATH` then `sudo apt install --reinstall PKG`. stderr lines containing `missing file` → included in evidence.
  Tests: `test_changed_files_warn`, `test_clean_ok`, `test_runner_skips_when_missing` (via `run_check`).

Commit: `feat(checks): config conflicts and debsums`.

### Task 10: Kernel and boot checks

**Files:** `checks/kernel_running.py`, `needrestart.py`, `dkms.py`, `bootloader.py`, `boot_space.py`, `checks/_diskutil.py`.

- Shared helper `installed_kernels(system: System) -> list[str]` in `kernel_running.py`: versions from `/boot/vmlinuz-*` (glob), sorted ascending via `dpkg --compare-versions a lt b` (`functools.cmp_to_key`). Used by `bootloader` too.
- **`kernel-running` / `KernelRunningCheck`** (boot). `uname -r` vs newest installed. Running ≠ newest → CRITICAL "Running kernel X is older than installed Y" (remediation `sudo reboot`). `/var/run/reboot-required` exists → CRITICAL "A reboot is required" with `.pkgs` file contents as evidence. Baseline `{"running": ..., "installed": [...]}` → compare: INFO "Kernel changed from A to B" or WARNING "Still running the pre-upgrade kernel A".
  Tests: `test_running_newest_ok`, `test_older_running_critical`, `test_reboot_required_critical`, `test_compare_same_kernel_warns`.
- **`needrestart` / `NeedrestartCheck`** (services category; root; `needrestart`, hint `sudo apt install needrestart`). `needrestart -b -r l`. `NEEDRESTART-SVC: x` lines → WARNING "N services run outdated libraries" (remediation `sudo systemctl restart <units>` or reboot). `NEEDRESTART-KSTA: 2|3` → WARNING "Kernel ABI/version upgrade pending" (avoid duplicating kernel-running: severity WARNING only). Tests: `test_services_warn`, `test_ksta_1_ok`.
- **`dkms` / `DkmsCheck`** (boot; `dkms`, hint none — skip means not used). Parse both `name/ver, kver, arch: status` and `name/ver, kver: status` (strip trailing `(WARNING ...)`); module with no `installed` entry for running kernel → CRITICAL "DKMS module NAME not built for running kernel" (remediation `sudo dkms autoinstall -k $(uname -r)` and check build log `/var/lib/dkms/NAME/VER/build/make.log`). Baseline: module names → compare: present before and absent now → WARNING. Tests: `test_new_format_installed_ok`, `test_old_format`, `test_missing_for_running_kernel_critical`, `test_added_status_only`.
- **`bootloader` / `BootloaderCheck`** (boot). If `/boot/grub/grub.cfg` readable: newest installed kernel version string absent from it → WARNING "grub.cfg does not reference newest kernel" (remediation `sudo update-grub`); unreadable as non-root → INFO note. If `/sys/firmware/efi` exists and `efibootmgr` available: run `efibootmgr -v`; no `BootCurrent:` line or `BootCurrent` id not in listed entries → WARNING; neither GRUB nor EFI data → INFO "No GRUB config found; bootloader not verified". Tests: `test_grub_references_kernel_ok`, `test_grub_missing_kernel_warns`, `test_efi_bootcurrent_missing_warns`, `test_efibootmgr_absent_still_checks_grub`.
- **`boot-space` / `BootSpaceCheck`** (boot). `_diskutil.py` exposes `space_findings(label: str, usage: DiskUsage) -> list[Finding]` applying Global Constraints thresholds to space and inodes (remediation for /boot: `sudo apt autoremove --purge` to drop old kernels). Check `/boot` and `/boot/efi` if `exists`; skip paths whose usage equals that of `/` (same filesystem — compare via `disk_usage` totals and free) to avoid double reporting with disk-space. Tests: `test_low_space_critical` (5 %), `test_warning_band` (20 %), `test_ok` (50 %), `test_low_inodes`.

Commit: `feat(checks): kernel and boot checks`.

### Task 11: Services and log checks

**Files:** `checks/systemd_failed.py`, `systemd_timers.py`, `journal_errors.py`, `dmesg_errors.py`, `boot_time.py`.

- **`systemd-failed` / `SystemdFailedCheck`** (services; `systemctl`). `systemctl list-units --state=failed --no-legend --plain --no-pager`; first column per line; strip leading `●`. Each → CRITICAL "Unit X failed" (remediation `systemctl status X`, `journalctl -u X -b`). Baseline: `systemctl list-units --type=service --state=active --no-legend --plain --no-pager` names → compare: active before, not active now → WARNING per unit (group if > 5 into one finding). Tests: `test_failed_units_critical`, `test_bullet_prefix_stripped`, `test_compare_service_no_longer_active`.
- **`systemd-timers` / `SystemdTimersCheck`** (services; `systemctl`). `systemctl list-units --type=timer --all --no-legend --plain --no-pager` → columns unit, load, active, sub. load `loaded` and active ≠ `active` → WARNING. Baseline: active timer names → compare: missing/inactive now → WARNING. (`systemctl list-timers` stays in the allowlist but isn't required.) Tests: `test_inactive_timer_warns`, `test_compare_missing_timer`.
- **`journal-errors` / `JournalErrorsCheck`** (services; `journalctl`). `journalctl -p err -b --no-pager -o json`. Parse JSON lines (skip unparsable); group by `(SYSLOG_IDENTIFIER or _COMM or "kernel", MESSAGE)` where MESSAGE may be a list of ints → decode bytes; count; evidence `"{n}x {ident}: {msg}"` sorted by count desc, truncated. Any → WARNING "N error messages in the current boot (M distinct)". stderr containing `insufficient permissions` or `not seeing messages from other users` → INFO "Journal partially readable; run as root or join the adm group". Tests: `test_groups_and_counts`, `test_message_as_byte_array`, `test_permission_hint_info`, `test_empty_ok`.
- **`dmesg-errors` / `DmesgErrorsCheck`** (services; root; `dmesg`). Run `dmesg --level=err --notime` and `dmesg --level=warn --notime` separately. err lines → WARNING; warn lines only → INFO. Dedupe identical lines with counts. Tests: `test_err_warns`, `test_warn_only_info`, `test_dedupe`.
- **`boot-time` / `BootTimeCheck`** (services; `systemd-analyze`). `systemd-analyze` (summary line) and `systemd-analyze blame --no-pager`. Always INFO "Boot took X" with top 10 blame lines as evidence; output containing `Bootup is not yet finished` → INFO with remediation `systemctl list-jobs`. Tests: `test_info_with_top10`, `test_not_finished`.

Commit: `feat(checks): services and log checks`.

### Task 12: Storage checks

**Files:** `checks/fstab.py`, `checks/disk_space.py`.

- **`fstab` / `FstabCheck`** (storage; `findmnt`). `findmnt --verify`. Lines starting `   [E]` → CRITICAL (one finding, all errors as evidence); `[W]` → WARNING; rc≠0 with no parsed lines → CRITICAL with stderr. Remediation: fix `/etc/fstab`, then `sudo findmnt --verify` and `sudo mount -a` (note mount -a mounts things — say "when ready"). Baseline: `findmnt -rn -o TARGET,SOURCE,FSTYPE` → list of targets excluding fstype in `{proc,sysfs,tmpfs,devtmpfs,cgroup2,cgroup,securityfs,pstore,bpf,debugfs,tracefs,configfs,fusectl,mqueue,hugetlbfs,devpts,autofs,binfmt_misc,efivarfs,squashfs,nsfs,overlay,ramfs,rpc_pipefs}` → compare: mounted before, not now → WARNING. Tests: `test_errors_critical`, `test_warnings_warn`, `test_clean_ok`, `test_compare_missing_mount`.
- **`disk-space` / `DiskSpaceCheck`** (storage; `df`). `df -P -T -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs` and `df -P -i -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs` (note `-T` needs to be after `-P`; the `("df","-P")` prefix covers both). Parse rows; skip `/boot*` mounts (boot-space owns them); feed into `space_findings` (build `DiskUsage` from df numbers; 1024-byte blocks). Tests: `test_root_full_critical`, `test_inodes_low_warns`, `test_boot_excluded`.

Commit: `feat(checks): storage checks`.

---

### Task 13: Allowlist and end-to-end safety tests

**Files:** Test: `tests/test_allowlist.py`. Modify: `src/pydebuprep/system.py` only if a test exposes a gap.

- [ ] **Step 1: Write tests:**
  - `test_every_check_command_is_allowed` — a `RecordingSystem(FakeSystem)` that returns `CommandResult(argv, 0, "", "")` for any allowed argv (not asserting unknown), `root=True`; run every check in `ALL_CHECKS` plus `collect_baseline`; assert no `DisallowedCommandError` raised and every recorded argv passes `check_allowed`.
  - `test_no_subprocess_outside_system` — scan `src/pydebuprep/**/*.py` text: `import subprocess` / `subprocess.` only in `system.py`; `open(` only in `system.py`, `snapshot.py`, `cli.py`.
  - `test_all_apt_calls_use_ro_opts` — from the recording above, every argv starting with `apt`, `apt-get`, `apt-cache` has `APT_RO_OPTS` right after the program.
  - `test_registry_ids_unique_and_kebab` — ids match `^[a-z0-9]+(-[a-z0-9]+)*$`, unique; every category in `CATEGORY_ORDER`; 23 checks total.
  - `test_full_report_on_empty_system_renders_all_formats` — `RecordingSystem` with no files; `main(["report","--format",f])` for each format returns 0–2, no exception.
- [ ] **Step 2: Run** `pytest -q` → fix any check that fails (they're bugs in earlier tasks). **Step 3:** `make lint` → pass.
- [ ] **Step 4: Live smoke run** on this machine (read-only): `python -m pydebuprep report` and `sudo -n python -m pydebuprep report --format json >/dev/null; echo $?` if sudo is available non-interactively; otherwise only the non-root run. Expected: report renders, exit code 0/1/2. Record anything surprising as a fix in the owning check with a regression test.
- [ ] **Step 5: Commit** `test: allowlist and end-to-end safety checks`.

---

### Task 14: Debian packaging and man page

**Files:**
- Create: `debian/control`, `debian/rules`, `debian/changelog`, `debian/copyright`, `debian/source/format`, `debian/pydebuprep.dirs`, `debian/pydebuprep.manpages`, `debian/tests/control`, `man/pydebuprep.1`

**Values:**
- `debian/control`: `Source: pydebuprep`, `Section: admin`, `Priority: optional`, Maintainer per Global Constraints, `Build-Depends: debhelper-compat (= 13), dh-python, pybuild-plugin-pyproject, python3-all, python3-setuptools, python3-yaml, python3-pytest`, `Standards-Version: 4.6.2`, `Rules-Requires-Root: no`, `Homepage:` omitted until there is one; `Package: pydebuprep`, `Architecture: all`, `Depends: ${python3:Depends}, ${misc:Depends}, python3-yaml`, `Recommends: debsums, needrestart`, `Suggests: efibootmgr, dkms`, description short "post-upgrade health report for Debian and Ubuntu" + long paragraph stating it is read-only.
  (debhelper-compat 13 and Standards-Version 4.6.2 exist on jammy and bookworm; planner's call.)
- `debian/rules`: `export PYBUILD_NAME=pydebuprep`; `%:\n\tdh $@ --with python3 --buildsystem=pybuild`; `export PYBUILD_TEST_PYTEST=1`.
- `debian/changelog`: `pydebuprep (0.1.0) unstable; urgency=medium` / `* Initial release.` / maintainer line with `Wed, 28 Oct 2026 12:00:00 +0000`.
- `debian/copyright`: DEP-5, `Files: *`, `Copyright: 2026 Jostein Elvaker Haande <jehaande@gmail.com>`, `License: Expat` + full text.
- `debian/source/format`: `3.0 (native)`. `debian/pydebuprep.dirs`: `var/lib/pydebuprep/snapshots`. `debian/pydebuprep.manpages`: `man/pydebuprep.1`.
- `debian/tests/control` (autopkgtest): `Test-Command: pydebuprep --version && pydebuprep list-checks && (pydebuprep report --format json > /dev/null; test $? -le 2)`, `Depends: @`, `Restrictions: allow-stderr`.
- `man/pydebuprep.1`: groff `man` macros, sections NAME, SYNOPSIS, DESCRIPTION (read-only promise), COMMANDS, OPTIONS (every flag from the parser), EXIT STATUS (0–3 table), FILES (`/var/lib/pydebuprep/snapshots`), EXAMPLES (incl. snapshot→upgrade→report), SEE ALSO `apt(8)`, `dpkg(1)`, `needrestart(1)`, `debsums(1)`.
- Snapshot dir permissions: postinst not needed; `dh_installdirs` creates 0755 — add `override_dh_fixperms` in rules: `dh_fixperms` then `chmod 0750 debian/pydebuprep/var/lib/pydebuprep/snapshots`.

- [ ] **Step 1:** Write the files. Also add `tests/test_manpage.py::test_manpage_mentions_every_option` — every long option string from `build_parser()` (walk subparsers) appears in `man/pydebuprep.1`.
- [ ] **Step 2:** `pytest -q && make lint` → pass. `man -l man/pydebuprep.1 | head` renders; `groff -man -Tutf8 -ww man/pydebuprep.1 >/dev/null` prints no warnings.
- [ ] **Step 3: Build.** Check build deps: `dpkg-checkbuilddeps`. If missing, stop and tell the user the exact `sudo apt install ...` line (do not install yourself). Then `dpkg-buildpackage -us -uc -b` → produces `../pydebuprep_0.1.0_all.deb`; `lintian ../pydebuprep_0.1.0_*.changes` → no E:/W: lines (I: allowed). Fix any warnings.
- [ ] **Step 4: Inspect** `dpkg-deb -c ../pydebuprep_0.1.0_all.deb` contains `/usr/bin/pydebuprep`, `/usr/lib/python3/dist-packages/pydebuprep/`, `/usr/share/man/man1/pydebuprep.1.gz`, `/var/lib/pydebuprep/snapshots/` (mode `drwxr-x---`). Do not install it on this machine without asking.
- [ ] **Step 5: Commit** `build: Debian packaging and man page`.

---

### Task 15: README and CI

**Files:** Create `README.md`, `.github/workflows/ci.yml`.

- README sections: what it is (read-only promise), install (`sudo apt install ./pydebuprep_*.deb`), usage (snapshot → upgrade → reboot → report; formats; output files), exit codes table, check list (generated by hand from `pydebuprep list-checks`), Ansible example playbook from spec §11 (`snapshot` pre-task with `changed_when: false`; `report --format json --output-dir /var/tmp/pydebuprep` registered, `failed_when: result.rc == 3`; `fetch` the newest file via `find` + `fetch` with `flat: true` to `reports/{{ inventory_hostname }}.json`), adding a check (subclass `Check`, add to `ALL_CHECKS`, add command prefix to `ALLOWED_PREFIXES`, write fixture tests), development (`make lint test deb`), license MIT.
- `ci.yml`: job `lint-test` matrix python `3.10 3.11 3.12 3.13` on `ubuntu-latest`: `pip install -e .[dev]`, `make lint test`. Job `deb` matrix container `debian:bookworm`, `debian:trixie`, `ubuntu:22.04`, `ubuntu:24.04`, `ubuntu:26.04`: `apt-get update && apt-get install -y --no-install-recommends build-essential devscripts lintian <Build-Depends>`, `dpkg-buildpackage -us -uc -b`, `lintian --fail-on error,warning ../*.changes`, `apt-get install -y ../*.deb && pydebuprep --version && pydebuprep list-checks`. Note: `lintian --fail-on` is unavailable on jammy's lintian; on that container use `lintian ../*.changes | (! grep -E '^[EW]:')`.
- [ ] **Step 1:** Write both files. **Step 2:** `python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))"` succeeds; README playbook block parses as YAML the same way (extract manually). **Step 3:** `make lint test` passes. **Step 4: Commit** `docs: README with Ansible usage; CI workflow`.

---

## Self-review notes

- Spec coverage: §6 CLI → T6; exit codes → T1/T6; §7 snapshot → T5 + per-check baselines (os-release, kernel, units, timers, sources, held, packages, mounts, dkms all covered in T7–T12); §8 architecture → T1–T4; §9 22 checks → T7 (3) + T8 (6) + T9 (2) + T10 (5) + T11 (5) + T12 (2) = 23, matching spec §9 (11 release/package, 5 kernel/boot, 5 services, 2 storage; the "22" said in chat was a miscount); §10 packaging → T14; §11 Ansible → T15; §12 hygiene/CI → T1, T15.
- The allowlist is final in T2; T13 verifies every check's commands against it.
