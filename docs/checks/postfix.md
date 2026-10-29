# postfix — postfix configuration

New postfix versions rename or remove parameters; postfix then warns at every start,
or stops reading its configuration altogether.

<!-- facts: postfix -->

## What it checks

- `postconf -n`: whether postfix can read its configuration, and the warnings it
  prints about it (unknown or obsolete parameters).

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | postfix can't read its configuration | `sudo postconf -n`; `sudo systemctl status postfix`. |
| warning | postfix warns about its configuration | Fix or remove the parameters it names (the evidence lists them). |

## Commands it runs

```sh
postconf -n
```

`postfix check` would be more thorough but isn't used: it creates missing
directories and fixes permissions, which is a change.

## Limitations

- Only `main.cf` parameters are checked; `master.cf` services and lookup tables
  aren't validated.

<!-- options: postfix -->
