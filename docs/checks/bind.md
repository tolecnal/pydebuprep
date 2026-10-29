# bind — BIND configuration

Options are sometimes removed or renamed between BIND versions. An invalid
configuration means `named` won't start or reload.

<!-- facts: bind -->

## What it checks

- `named-checkconf`: the syntax and options of the BIND configuration.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | The BIND configuration is invalid | `sudo named-checkconf`, fix what it names, then `sudo systemctl status named`. The evidence shows its messages. |

## Commands it runs

```sh
named-checkconf
```

## Limitations

- Only the configuration is checked, not zone files.
- Skipped when BIND isn't installed, and without root (the configuration usually
  isn't readable).

<!-- options: bind -->
