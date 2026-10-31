# Install

pydebuprep ships as a Debian package (`Architecture: all`) that works on every
[supported release](../index.md#supported-systems). Releases are published on
[GitHub](https://github.com/tolecnal/pydebuprep/releases) with a `SHA256SUMS` file
and a signed build-provenance attestation.

## With the GitHub CLI (recommended)

Download the latest release, check its checksum and provenance, and install it:

```sh
gh release download -R tolecnal/pydebuprep --pattern '*.deb' --pattern SHA256SUMS
sha256sum -c SHA256SUMS
gh attestation verify pydebuprep_*_all.deb -R tolecnal/pydebuprep
sudo apt install ./pydebuprep_*_all.deb
```

`gh attestation verify` proves the package was built by this repository's release
workflow from a release tag, and not modified since. See
[Security and releases](../about/security.md).

## Without the GitHub CLI

```sh
VERSION=0.7.0
base=https://github.com/tolecnal/pydebuprep/releases/download/v$VERSION
wget $base/pydebuprep_${VERSION}_all.deb $base/SHA256SUMS
sha256sum -c SHA256SUMS && sudo apt install ./pydebuprep_${VERSION}_all.deb
```

Install with `apt` (not `dpkg -i`) so it pulls in `python3-yaml`.

## Recommended packages

| Package | Used by | Without it |
|---|---|---|
| `debsums` | [`debsums`](../checks/debsums.md) | that check is skipped |
| `needrestart` | [`needrestart`](../checks/needrestart.md) | that check is skipped |

Both are `Recommends:` of the package, so apt installs them by default. Other checks
use the tool they inspect (`docker`, `pg_lsclusters`, `sshd`, …) and are skipped on
hosts where it isn't installed.

## Shell completion

The package installs tab completion for **bash**
(`/usr/share/bash-completion/completions/pydebuprep`, active when the
`bash-completion` package is installed) and **zsh**
(`/usr/share/zsh/vendor-completions/_pydebuprep`). Without the package, add one of
these to your shell's startup file:

=== "bash (~/.bashrc)"

    ```sh
    source <(pydebuprep completion bash)
    ```

=== "zsh (~/.zshrc, after compinit)"

    ```sh
    source <(pydebuprep completion zsh)
    ```

## What gets installed

| Path | Contents |
|---|---|
| `/usr/bin/pydebuprep` | the command |
| `/usr/share/man/man1/pydebuprep.1.gz` | the manual page |
| `/usr/share/doc/pydebuprep/examples/pydebuprep.conf` | a commented [example configuration](../configuration/index.md) |
| `/var/lib/pydebuprep/snapshots/` | where snapshots go (mode 0700, root only) |

pydebuprep reads `/etc/pydebuprep.conf` if you create one; the package doesn't
install it.

## Uninstall

```sh
sudo apt purge pydebuprep    # also removes /var/lib/pydebuprep and its snapshots
```

`apt remove` keeps the snapshots.
