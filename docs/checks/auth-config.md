# auth-config — sudoers, PAM and the name service

A valid SSH configuration doesn't help if the PAM module a login ends up in is gone. On a
remote server, that can lock everyone out at the next login.

<!-- facts: auth-config -->

## What it checks

- As root, `visudo -c`: every sudoers file is valid.
- Every module named in `/etc/pam.d/*` exists. A line starting with `-`, or with
  `module_unknown=ignore`, may name a missing module, by PAM's own rules, and is left out.
- Every service named for `passwd`, `group`, `shadow`, `gshadow`, `hosts` and `sudoers` in
  `/etc/nsswitch.conf` has its library (`libnss_NAME.so.2`). Others are left out: stock files
  name `db` and `nis` for `protocols`, `netgroup` and others, normally absent and harmless.
- With a snapshot: modules, other than `optional` ones, that login paths and the name service
  used and no longer do.

## Findings

| Severity | Finding | What to do |
|---|---|---|
| critical | The sudoers configuration is invalid | Keep a root session open; fix it with `sudo visudo`. |
| critical | PAM uses modules that don't exist (a line in a login path that isn't `optional`) | Keep a root session open. Install the module's package, or `sudo pam-auth-update`. |
| warning | PAM uses modules that don't exist (`optional` lines and other services) | It may be a leftover, such as `pam_lastlog.so` after an upgrade to Ubuntu 24.04: remove the line. |
| warning | The name service uses modules that don't exist | Install the module's package, such as `libnss-sss`. |
| warning | PAM login paths lost modules since the snapshot | `sudo pam-auth-update`: a profile such as LDAP or SSSD may have been dropped. |
| warning | The name service lost modules since the snapshot | Check `/etc/nsswitch.conf`. |

The login paths are `common-*`, `sshd`, `sudo`, `su`, `login` and `other`.

## Compared with a snapshot

The snapshot records the modules each PAM service uses, and the services of each name
service database.

## Commands it runs

```sh
visudo -c
```

It only parses the files, and writes nothing: measured with `strace`.

## Limitations

- It checks that the modules exist, not that logging in works: nothing logs in, and no
  directory server is contacted, so SSSD or LDAP being down isn't seen here. Use
  `required_active` in [`systemd-critical-services`](systemd-critical-services.md) for that.
- It doesn't follow `@include`: each file is checked by itself.

<!-- options: auth-config -->
