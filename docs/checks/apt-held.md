# apt-held — Held packages

A held package stays on its old version. After a release upgrade that can block
dependencies or leave a package from the old release in place.

<!-- facts: apt-held -->

## What it checks

- The packages marked as held (`apt-mark showhold`).

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* packages are held back | If a hold is no longer needed: `sudo apt-mark unhold PACKAGE`. |
| warning | *N* packages newly held since baseline | Find out why they were held during the upgrade. |
| info | *N* packages no longer held since baseline | Hold them again if you still need to: `sudo apt-mark hold PACKAGE`. |

## Compared with a snapshot

The snapshot records the held packages; the report shows holds added and removed
since.

## Commands it runs

```sh
apt-mark showhold
```

## Limitations

- Only `apt-mark` holds are seen. Pinning with APT preferences
  (`/etc/apt/preferences.d`) has a similar effect and isn't reported here.

<!-- options: apt-held -->
