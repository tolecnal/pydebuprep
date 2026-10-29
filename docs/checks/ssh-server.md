# ssh-server — SSH server configuration

The one that can lock you out. New OpenSSH versions remove options; a configuration
that worked before the upgrade may be rejected — and sshd only notices when it
restarts, for example at the next reboot.

<!-- facts: ssh-server -->

## What it checks

- `sshd -t`: the configuration test sshd runs before starting, including warnings
  about deprecated options.
- `authorized_keys` files of root and users under `/home` for DSA (`ssh-dss`) keys,
  which current OpenSSH no longer accepts.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | The SSH server configuration is invalid | `sudo sshd -t`, fix it **before** restarting ssh or rebooting, and keep an existing session open while you do. |
| warning | sshd warns about its configuration | Remove or update the options it names. |
| warning | DSA keys in authorized_keys no longer work | Have each user switch to a new key (`ssh-keygen -t ed25519`). |

## Commands it runs

```sh
sshd -t
```

## Limitations

- Needs root: sshd reads its host keys during the test.
- If `/run/sshd` is missing (sshd isn't running, or is socket-activated), `sshd -t`
  complains about it; that alone isn't reported, since systemd creates the
  directory on start.
- `authorized_keys` outside `/root` and `/home` (custom `AuthorizedKeysFile`) isn't
  scanned.
- Leftover `sshd_config.dpkg-dist` files are reported by
  [`config-conflicts`](config-conflicts.md).

<!-- options: ssh-server -->
