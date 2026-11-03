# Cleaning up after an upgrade

`pydebuprep-cleanup` purges what a release upgrade leaves behind: old kernels, their
modules and headers, directories DKMS leaves in them, and the configuration of
removed packages. Unlike `pydebuprep report`, it changes the system: on purpose, and
only when you ask it to (see [What pydebuprep changes](../about/read-only.md#the-cleanup-tool)).

## Commands it runs

To work out what it would remove, it only reads, like `pydebuprep report`:

```sh
dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${Installed-Size}\n'
uname -r
dpkg-query -S /lib/modules/VERSION /usr/src/linux-headers-VERSION
```
