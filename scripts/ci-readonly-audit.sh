#!/bin/sh
# CI wrapper around readonly-audit.sh for throwaway containers (as root, package installed).
# Sets up the worst case first: real apt cache settings and no cache yet, so any apt call
# that could write one would do it now; installs the optional tools so their checks run.
# Never run this on a real host: it deletes apt's cache files.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
rm -f /etc/apt/apt.conf.d/docker-clean
apt-get install -y --no-install-recommends strace debsums dkms needrestart efibootmgr
rm -f /var/cache/apt/*.bin
"$here/readonly-audit.sh" /tmp/audit
