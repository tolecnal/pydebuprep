# journal-errors — Errors in the journal (current boot)

Services that fail partially — log errors but keep running — don't show up as
failed units. The journal does show them.

<!-- facts: journal-errors -->

## What it checks

- Messages at priority `err` or worse in the journal since boot, grouped by
  identifier and message (numbers and hex IDs are treated as the same, so repeats
  group together), most common first.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* error messages in the current boot (*M* distinct) | `journalctl -p err -b`; `journalctl -u UNIT -b` for one service. Some noise is normal — look for services you rely on and anything new since the upgrade. |
| info | Journal only partially readable | Run as root, or add your user to the `adm` group. |

## Commands it runs

```sh
journalctl -p err -b --no-pager -o json
```

## Limitations

- It counts messages; it doesn't judge them. Expected errors on your systems
  belong in `ignore` (matched against `IDENTIFIER: message`) or `logs: ignore:`.
- With a volatile journal (no `/var/log/journal`), only this boot is ever available
  anyway; with a persistent one, only the current boot is read.

<!-- options: journal-errors -->
