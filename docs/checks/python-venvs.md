# python-venvs — Python virtualenvs

A release upgrade replaces the system Python (3.11 → 3.13 on Debian 12 → 13, for
example). Virtualenvs built on the old one stop working — anything they run fails.

<!-- facts: python-venvs -->

## What it checks

- Virtualenvs (directories with a `pyvenv.cfg`) under `search_paths`, up to
  `max_depth` levels deep, except those matching `exclude_paths` (tools' throwaway
  environments under `~/.cache` by default).
- Whether each one's Python still exists, and whether it was built for an older
  Python than the system's.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* virtualenvs point to a Python that no longer exists | Recreate each: `python3 -m venv --clear PATH`, then reinstall its requirements. |
| info | *N* virtualenvs were built for an older Python than the system's | They work while that Python stays installed; recreate them with the current one when convenient. |

## Commands it runs

None: it reads `pyvenv.cfg` files and checks the interpreter each names.

## Limitations

- Only virtualenvs under the search paths are found; add yours (`/data`, …) to
  `search_paths`.
- Environments managed by conda, pyenv, Poetry's or pipx's own directories outside
  the search paths aren't covered.
- Packages installed with `pip` into the system Python
  (`/usr/local/lib/python3.X`) aren't checked.

<!-- options: python-venvs -->
