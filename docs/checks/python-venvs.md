# python-venvs — Python virtualenvs

A release upgrade replaces the system Python (3.11 → 3.13 on Debian 12 → 13, for
example). Virtualenvs built on the old one stop working — anything they run fails.

<!-- facts: python-venvs -->

## What it checks

Virtualenvs (directories with a `pyvenv.cfg`) under `search_paths`, up to `max_depth`
levels deep, except those matching `exclude_paths` (tools' throwaway environments
under `~/.cache` by default). For each:

- **Python:** does the Python it was built with still exist, and is it older than the
  system's?

For virtualenvs whose Python works:

- **Missing native libraries:** compiled extension modules (`*.so`) that need a shared
  library the dynamic linker can't find any more — `libssl.so.1.1` after an upgrade to
  OpenSSL 3 is the classic. The libraries a module needs are read from its ELF headers
  (`DT_NEEDED`), and each is looked up the way the linker would: the module's own
  `RUNPATH`/`RPATH` (with `$ORIGIN`, so libraries bundled in wheels count), the linker
  cache, and the default library directories. Modules built for another architecture
  are skipped.
- **Broken entry points:** scripts in `bin/` whose `#!` interpreter doesn't exist —
  usually a virtualenv that was moved or copied.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* virtualenvs point to a Python that no longer exists | Recreate each: `python3 -m venv --clear PATH`, then reinstall its requirements. |
| warning | *N* compiled modules in virtualenvs need libraries that are missing | Reinstall the package so it gets a build for this release: `VENV/bin/pip install --force-reinstall --no-cache-dir PACKAGE`; or install the library (`apt-file search LIBRARY`). |
| warning | *N* virtualenv scripts start an interpreter that doesn't exist | Recreate the virtualenv where it is, then reinstall its requirements. |
| info | *N* virtualenvs were built for an older Python than the system's | They work while that Python stays installed; recreate them with the current one when convenient. |

## Commands it runs

```sh
ldconfig -p
```

Only when a virtualenv has compiled modules: `-p` prints the linker cache
(`/etc/ld.so.cache`) and never rebuilds it. Everything else is read from files —
`pyvenv.cfg`, the first bytes of each script, and the ELF headers of each module.
`ldd` is never used: it can execute code from the file it inspects.

## Limitations

- Only virtualenvs under the search paths are found; add yours (`/data`, …) to
  `search_paths`.
- Environments managed by conda, pyenv, or Poetry's and pipx's own directories outside
  the search paths aren't covered.
- Packages installed with `pip` into the system Python (`/usr/local/lib/python3.X`)
  aren't checked.
- A library the linker finds but whose version or symbols changed (an ABI break) isn't
  detected; only missing libraries are. Libraries loaded at run time with `dlopen()`
  aren't listed in the headers either.
- Without `ldconfig` in `PATH` (as a normal user on some systems), the library check is
  skipped.

<!-- options: python-venvs -->
