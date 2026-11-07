# upgrade-log — What happened during the upgrade

The state a machine ends up in doesn't always show what went wrong on the way. A package's
script can fail and be retried, leaving something half done that no other check sees.

<!-- facts: upgrade-log -->

## What it checks

It reads, rotated and compressed copies included:

- `/var/log/apt/history.log`: APT runs that reported errors or never finished, and packages
  removed or purged;
- `/var/log/apt/term.log`: packages whose scripts failed (`dpkg: error processing package`).
  With `/var/log/dpkg.log` it tells a failure that was put right later from one that wasn't;
- `/var/log/dist-upgrade/main.log`: errors from Ubuntu's release upgrader, where it ran.
  That upgrader keeps APT's logs there too (`history.log`, `apt-term.log`), not in
  `/var/log/apt`, and they're read the same way, those of earlier upgrades included.

With a snapshot it reads from the moment the snapshot was taken, so older problems aren't
blamed on the upgrade. Without one it reads the last `days` days (30).

## Findings

| Severity | Finding | What to do |
|---|---|---|
| warning | *N* APT runs reported errors | Read `/var/log/apt/term.log`. It may have been put right since; [`dpkg-audit`](dpkg-audit.md) shows the state now. |
| info | *N* APT runs reported errors | The same, when every package that failed installed correctly later. |
| warning | *N* APT runs didn't finish | Interrupted, or still running. `sudo dpkg --configure -a`, then `sudo apt -f install`. |
| warning | *N* packages failed during installation or upgrade | `sudo dpkg --configure -a`; read `/var/log/apt/term.log`. |
| info | *N* packages failed, then installed correctly later | For the record: check nothing was left half done. |
| info | *N* packages were removed or purged | Reinstall anything still needed. |
| warning | The release upgrader logged *N* errors | Read `/var/log/dist-upgrade/main.log`; not every error stops an upgrade. |
| info | *N* upgrade logs are missing | What they would show isn't known. |
| info | *N* upgrade logs can't be read | Run as root, or add your user to the `adm` group. |
| info | The upgrade logs begin after the snapshot | Older logs may have been rotated away. |

## Commands it runs

None; it reads the files above.

## Limitations

- **No finding doesn't prove nothing went wrong**: it only knows what the logs say, and only
  for as long as they're kept.
- It reads logs as messages from a package's scripts and dpkg wrote them; a failure worded
  differently isn't recognised, and warnings aren't reported.
- Without a snapshot, it can't tell the upgrade from other package changes in those days.
- The logs keep local time, so changing the time zone during the upgrade shifts the start.

<!-- options: upgrade-log -->
