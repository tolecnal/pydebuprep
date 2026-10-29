# systemd-critical-services Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new `systemd-critical-services` check that validates the expected state of
designated critical units: built-in plus configured, against the configuration and
against the pre-upgrade snapshot.

**Architecture:** One `systemctl show` call reads the properties of every unit in the
effective list; a pure classifier turns each unit's properties into findings. Listening
ports per unit come from `/proc/net/*` joined to the unit's cgroup processes through
`/proc/<pid>/fd` links. They are stored only in the snapshot and compared afterwards.

**Tech Stack:** Python ≥3.10 stdlib, pytest with `FakeSystem`, existing `Check`/`Option`
framework.

**Spec:** `docs/superpowers/specs/2026-10-29-service-and-repository-assurance-design.md`,
part 1.

## Global Constraints

- Read-only.
  - Every command matches the allowlist in `src/pydebuprep/system.py` exactly; variable
    operands are validated by `UNIT_NAME`.
  - Nothing is written; remediation is text only.
- No new runtime dependencies.
- 100% line and branch coverage (`make coverage`).
- `make lint` is clean (ruff, ruff format, flake8, mypy).
- Docs in sync:
  - a README checks-table row and options-table row, in report order;
  - a man page CHECKS entry;
  - an `OPTION_TESTS` entry per option;
  - `make generated` re-run.
- Findings word "active" as process state, never as application health.
- `systemd-failed` is not changed.
- Work on branch `feat/systemd-critical-services` from `main`. Commit the spec and this
  plan first.

## Review Focus

- **Condition-skipped units** (for example `systemd-timesyncd` in a container or VM, where
  `ConditionResult=no`): not a finding. → Task 2, `test_condition_skipped_unit_is_not_a_finding`.
- **A unit both built-in and configured**, or configured twice: reported once. → Task 2,
  `test_duplicate_units_reported_once`.
- **An invalid unit name in the config** (`"ssh; rm"`, `"-H"`): a config error at load,
  never passed to systemctl. → Task 2, `test_invalid_unit_name_rejected`.
- **No systemd (plain container):** the check is skipped, not an error. → Task 2,
  `test_without_systemd_is_skipped`.
- **Non-root, or a process exiting mid-scan:** unreadable `/proc` fd links are ignored.
  Without root the snapshot stores no listeners, and compare reports nothing about them.
  → Task 3, `test_listeners_need_root` and `test_vanished_process_is_ignored`.

---

### Task 1: Multi-unit `systemctl show` and readlink support

**Files:**
- Modify: `src/pydebuprep/system.py` (next to `UNIT_QUERIES`, and `System`)
- Modify: `tests/fakes.py`
- Test: `tests/test_system.py`

**Interfaces:**
- Produces:
  - `SHOW_UNITS: tuple[str, ...]` in `system.py`:
    `("systemctl", "show", "--property=Id,Names,LoadState,ActiveState,SubState,UnitFileState,ConditionResult,TriggeredBy,Requires,BindsTo,ControlGroup", "--")`;
  - `MAX_UNITS = 256`;
  - `System.readlink(path: str) -> str | None` (`None` on `OSError`);
  - `FakeSystem(links: dict[str, str] | None = None)`: `readlink` returns
    `links.get(path)`, and `glob` also matches link paths.

- [ ] **Step 1: Write the failing tests** in `tests/test_system.py`:
  - `test_show_units_allows_unit_names`: `check_allowed((*SHOW_UNITS, "ssh.service",
    "cron.service"))` passes, and so does `getty@tty1.service`.
  - `test_show_units_rejects_bad_operands`: `DisallowedCommandError` for:
    - no unit after `--`;
    - an operand `-H`;
    - `a;b`;
    - 257 units;
    - `SHOW_UNITS` without `--`.
  - `test_fake_readlink_and_glob`: `FakeSystem(links={"/proc/1/fd/3": "socket:[42]"})` →
    `readlink` gives `"socket:[42]"`, and `glob("/proc/1/fd/*") == ["/proc/1/fd/3"]`.
  - `test_real_readlink` in `tests/test_system_real.py`: a symlink in `tmp_path` reads
    back, and a missing path gives `None`.
- [ ] **Step 2:** Run `.venv/bin/python -m pytest -q tests/test_system.py tests/test_system_real.py`.
  Expected: FAIL (`SHOW_UNITS` undefined).
- [ ] **Step 3:** Implement.
  - In `_is_allowed`, accept `argv[:len(SHOW_UNITS)] == SHOW_UNITS` followed by 1 to
    `MAX_UNITS` operands, each matching `UNIT_NAME` and not starting with `-`.
  - Add `System.readlink` (`os.readlink`).
  - Add the fake's `links`.
- [ ] **Step 4:** Rerun. Expected: PASS. Then `make lint`.
- [ ] **Step 5: Commit** `feat(system): allow systemctl show for several units; readlink`.

### Task 2: The check: configuration findings, registry and docs

**Files:**
- Create: `src/pydebuprep/checks/systemd_critical.py`
- Modify: `src/pydebuprep/checks/__init__.py` (import; place in `ALL_CHECKS` right after
  `SystemdFailedCheck`)
- Modify: `README.md` (checks table after `systemd-failed`; options table),
  `man/pydebuprep.1` (CHECKS, after systemd-failed), `tests/test_option_coverage.py`,
  then `make generated`
- Test: `tests/checks/test_systemd_critical.py`

**Interfaces:**
- Consumes: `SHOW_UNITS`, `run_systemctl` (`checks/_systemd.py`; raises `CheckSkipped`
  without systemd).
- Produces:
  - `class SystemdCriticalCheck(Check)`: `id = "systemd-critical-services"`,
    `title = "Critical systemd units"`, `category = "services"`,
    `requires_commands = ("systemctl",)`.
  - `parse_show(text: str) -> list[dict[str, str]]`: blocks separated by blank lines,
    `KEY=VALUE`, in argument order.
  - `unit_states(ctx: Context, units: Sequence[str]) -> list[dict[str, str]]`.
  - `BUILTIN = ("ssh.service", "cron.service", "systemd-journald.service")` and
    `TIME_SYNC = ("systemd-timesyncd.service", "chrony.service", "ntpsec.service")`.
  - `SystemdCriticalCheck.effective_units(self) -> list[str]`: (if `builtin`) BUILTIN + TIME_SYNC,
    + `required_active` + `required_enabled`, de-duplicated in order, minus
    `ignore_units` patterns.

**Options** (exact names and defaults; help text in the style of `systemd-failed`):

| Option | Default |
|---|---|
| `required_active` | `[]` |
| `required_enabled` | `[]` |
| `builtin` | `True` |
| `ignore_units` | `[]` (shell-style patterns) |

`validate()` raises `ValueError` for any configured name not matching `UNIT_NAME` or
starting with `-`.

**Rules.**

- **Which units are required.**
  - Built-in units are required active **and** enabled, but only when `LoadState` is
    not `not-found`.
  - TIME_SYNC is one requirement: if any is loaded, at least one loaded one must be
    active (or condition-skipped). Otherwise a single finding names the loaded ones.
  - Configured units are required as listed; `not-found` is critical.
  - A unit in both lists is checked against both; each problem is reported once.
- **Classification of a required-active unit**, in order, with the first match winning
  (severities and remediation from the spec table):
  1. `LoadState=not-found` → critical "UNIT does not exist".
     Remediation: `systemctl list-unit-files 'STEM*'`.
  2. `LoadState=masked` → critical "UNIT is masked". Remediation:
     `sudo systemctl unmask UNIT`.
  3. `ActiveState=failed` → critical "UNIT failed".
  4. `ActiveState=active`: no finding for state.
     - Then dependencies: any `Requires`/`BindsTo` unit (from a second `unit_states`
       call over their union) whose `ActiveState` is `inactive` or `failed` → warning
       "UNIT is running but needs DEP, which is STATE".
  5. `ActiveState` in activating/deactivating/reloading → warning "UNIT is STATE".
  6. inactive:
     - with `ConditionResult=no` → no finding;
     - with a `TriggeredBy` unit (from the same second call) that is `active` → no
       finding (socket-activated);
     - with a `TriggeredBy` unit that isn't active → critical "UNIT is socket-activated
       but SOCKET isn't listening", remediation `sudo systemctl start SOCKET`;
     - otherwise critical "UNIT is not running", remediation `sudo systemctl start UNIT`.
- **Required-enabled.**
  - `UnitFileState` in {enabled, enabled-runtime, static, indirect, generated, alias}
    passes, or a `TriggeredBy` socket is enabled.
  - `disabled` → warning "UNIT is not enabled", remediation `sudo systemctl enable UNIT`.
  - Masked and not-found units are already reported, so they are not reported again here.
- **Detail text:** every finding's detail ends with "An active unit shows the process is
  running, not that the service works."

- [ ] **Step 1: Write the failing tests** (`make_ctx(commands={(*SHOW_UNITS, *units): text})`;
  write a `show(**units)` helper that renders blocks):
  - `test_parse_show_blocks_in_order`
  - `test_all_builtin_units_healthy_no_findings`
  - `test_builtin_units_not_installed_are_ignored`: ssh not-found → none.
  - `test_configured_unit_not_found_is_critical`
  - `test_masked_unit_is_critical_with_unmask`
  - `test_failed_unit_is_critical`
  - `test_inactive_required_unit_is_critical`
  - `test_socket_activated_service_is_fine`: `ssh.service` inactive,
    `TriggeredBy=ssh.socket` active.
  - `test_socket_not_listening_is_critical`
  - `test_transitional_state_is_warning`: activating.
  - `test_running_with_inactive_dependency_warns`
  - `test_disabled_required_enabled_unit_warns`, and `static` and `indirect` pass.
  - `test_time_sync_one_active_is_enough`, and
    `test_time_sync_none_active_is_one_finding`.
  - `test_condition_skipped_unit_is_not_a_finding`
  - `test_duplicate_units_reported_once`
  - `test_invalid_unit_name_rejected`: `SystemdCriticalCheck({"required_active":
    ["ssh; rm"]})` raises `ValueError` matching `required_active`.
  - `test_without_systemd_is_skipped`: `run_check(...).status is Status.SKIPPED`.
  - `test_builtin_false_and_ignore_units`
  - `test_active_wording_is_process_state`: the detail contains "not that the service
    works".
- [ ] **Step 2:** Run `.venv/bin/python -m pytest -q tests/checks/test_systemd_critical.py`.
  Expected: FAIL (module missing).
- [ ] **Step 3:** Implement `systemd_critical.py` per the rules. Register it, and add:
  - README rows:
    - checks: `| \`systemd-critical-services\` | services | Critical units (built-in and
      configured) not running, masked, missing, disabled, or running without a
      required unit; units masked or missing since the snapshot; listeners lost since
      the snapshot |`
    - options: `| \`systemd-critical-services\` | \`required_active\` ([]),
      \`required_enabled\` ([]): units that must be running / enabled, added to the
      built-in ssh, cron, journald and time sync; \`builtin\` (true);
      \`ignore_units\` ([]) |`
  - The man entry.
  - `OPTION_TESTS` entries for all four options.
  - Run `make generated`.
- [ ] **Step 4:** Run `make lint coverage`. Expected: PASS at 100%, with
  `tests/test_docs.py` and `tests/test_option_coverage.py` green.
- [ ] **Step 5: Commit** `feat(checks): systemd-critical-services`.

### Task 3: Snapshot baseline: masked/missing units and lost listeners

**Files:**
- Create: `src/pydebuprep/checks/_listeners.py`
- Modify: `src/pydebuprep/checks/systemd_critical.py`
- Test: `tests/checks/test_systemd_critical.py`

**Interfaces:**
- Consumes: `unit_states`, `ENABLED_SERVICES` and `unit_rows` (`checks/_systemd.py`),
  `System.readlink` and `glob`.
- Produces:
  - `listening_sockets(system: System) -> dict[str, str]`: socket inode →
    `"tcp/PORT"` or `"udp/PORT"`.
    - From `/proc/net/tcp` and `tcp6` with state `0A`, and from `/proc/net/udp` and
      `udp6` with state `07` and remote address all zeros.
    - The port is the hex after `:` in `local_address`; the inode is field 10.
  - `unit_listeners(system: System, control_group: str, sockets: dict[str, str]) ->
    list[str]`: sorted, unique.
    - PIDs come from `/sys/fs/cgroup{control_group}/cgroup.procs`, falling back to
      `/sys/fs/cgroup/systemd{control_group}/cgroup.procs`.
    - For each PID, `glob(f"/proc/{pid}/fd/*")`, then `readlink`; `socket:[N]` maps
      through `sockets`.
- Baseline shape: `{"units": {UNIT: {"load": str, "active": str, "file": str}},
  "listeners": {UNIT: [str]}}`.
  - Units are the effective list plus all `ENABLED_SERVICES` rows.
  - Listeners cover only the effective list's active units, and only when
    `ctx.is_root`; otherwise `{}`.

- [ ] **Step 1: Write the failing tests:**
  - `test_listening_sockets_parses_proc_net`: a real-format tcp line with
    `0100007F:0016 ... 0A ... inode 12345` gives `{"12345": "tcp/22"}`, and a udp6
    bound line gives a udp port. ESTABLISHED (`01`) lines are excluded.
  - `test_unit_listeners_follow_cgroup_pids`
  - `test_baseline_records_units_and_listeners`
  - `test_compare_reports_newly_masked_and_missing_units`: was loaded, now masked →
    critical "UNIT was loaded before the upgrade and is now masked"; now not-found →
    warning "UNIT existed before the upgrade and is gone".
  - `test_compare_reports_lost_listeners`: warning
    `"nginx.service listened on tcp/443 before the upgrade, not now"`.
  - `test_compare_leaves_enablement_to_systemd_failed`: was enabled, now disabled → no
    finding from this check.
  - `test_listeners_need_root`: non-root baseline gives `listeners == {}`, and compare
    against a root baseline while not root reports no listener findings.
  - `test_vanished_process_is_ignored`: `readlink` `None`, or a missing `cgroup.procs`,
    gives no crash and no listeners.
- [ ] **Step 2:** Run the test file. Expected: FAIL.
- [ ] **Step 3:** Implement `_listeners.py` and `collect_baseline` / `compare`. Compare
  titles are "…before the upgrade…" and are kept separate from the config findings.
- [ ] **Step 4:** Run `make lint coverage`. Expected: PASS at 100%.
- [ ] **Step 5: Commit** `feat(checks): systemd-critical-services snapshot comparison`.

### Task 4: Read-only proof and release notes

**Files:**
- Modify: `docs/backlog.md` ("Changes waiting for the next changelog entry")

- [ ] **Step 1:** `make deb`, then
  `scripts/ci-systemd-container.sh debian:trixie ../pydebuprep_*_all.deb` and the same with
  `ubuntu:24.04` (socket-activated ssh).
  Expected:
  - `0 violation(s)` for report and snapshot;
  - no `SYSTEMD JOBS` or `PID 1 LOGGED` lines;
  - in the report JSON, `systemd-critical-services` shows no finding for ssh on 24.04.
- [ ] **Step 2:** Under "Changes waiting for the next changelog entry" in the backlog, add:
  "new check systemd-critical-services".
- [ ] **Step 3: Commit** `docs: backlog for systemd-critical-services`. Push, then open the PR.
