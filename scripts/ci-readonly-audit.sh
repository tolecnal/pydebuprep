#!/bin/sh
# CI wrapper around readonly-audit.sh for throwaway containers (as root, package installed).
# Sets up the worst case first: real apt cache settings and no cache yet, so any apt call
# that could write one would do it now; installs the optional tools and the services the
# checks inspect, so their commands run too.
# Never run this on a real host: it deletes apt's cache files.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
rm -f /etc/apt/apt.conf.d/docker-clean
echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections
echo "postfix postfix/mailname string audit.example" | debconf-set-selections
apt-get install -y --no-install-recommends strace debsums dkms needrestart efibootmgr \
    nftables iptables ufw openssh-server cron unattended-upgrades apparmor iproute2 \
    postgresql mariadb-server postfix bind9 python3-venv
# A broken virtualenv for python-venvs to find.
python3 -m venv /opt/audit-venv && rm -f /opt/audit-venv/bin/python
rm -f /var/cache/apt/*.bin
"$here/readonly-audit.sh" /tmp/audit
