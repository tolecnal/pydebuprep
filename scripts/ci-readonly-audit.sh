#!/bin/sh
# CI wrapper around readonly-audit.sh for throwaway systems (as root, package installed):
# containers, with or without systemd as PID 1, and CI runner VMs.
# Sets up the worst case first: real apt cache settings and no cache yet, so any apt call
# that could write one would do it now; installs the optional tools and the services the
# checks inspect, so their commands run too.
# Never run this on a real host: it deletes apt's cache files.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
rm -f /etc/apt/apt.conf.d/docker-clean
# Container images forbid starting services on install; with systemd they should run.
[ ! -d /run/systemd/system ] || rm -f /usr/sbin/policy-rc.d
echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections
echo "postfix postfix/mailname string audit.example" | debconf-set-selections
tools="strace debsums dkms needrestart efibootmgr nftables iptables ufw iproute2 python3-venv"
services="openssh-server cron unattended-upgrades apparmor postgresql mariadb-server postfix bind9"
# AUDIT_TOOLS_ONLY=1 leaves the services out: CI runner VMs ship their own, conflicting
# MySQL and PostgreSQL, and the containers cover the services anyway.
[ -n "${AUDIT_TOOLS_ONLY:-}" ] || tools="$tools $services"
# shellcheck disable=SC2086 # word splitting intended: one package per word
apt-get install -y --no-install-recommends $tools
# Something for `apt-get -s autoremove` to plan: apt writes its solver log then, unless
# told not to.
apt-get install -y --no-install-recommends hello && apt-mark auto hello
# A broken virtualenv for python-venvs to find.
python3 -m venv /opt/audit-venv && rm -f /opt/audit-venv/bin/python
rm -f /var/cache/apt/*.bin

if [ -d /run/systemd/system ]; then
    # Let the services just installed finish starting, so they are running during the
    # audit and their start-up writes are over.
    while [ -n "$(systemctl list-jobs --no-legend)" ]; do sleep 1; done
    # Timers would start their services mid-audit; nothing the checks inspect needs them.
    timers=$(systemctl list-units --type=timer --state=active --no-legend --plain | awk '{print $1}')
    # shellcheck disable=SC2086 # one unit per word
    [ -z "$timers" ] || systemctl stop $timers
    sleep 10
    # Where the running services keep writing on their own; strace still covers
    # pydebuprep's own processes everywhere.
    AUDIT_IGNORE="/var/log/ /var/lib/postgresql/ /var/lib/mysql/ /var/cache/bind/ \
/var/spool/postfix/ /var/lib/systemd/ /var/lib/docker/ /var/lib/containerd/ \
/home/runner/ /tmp/ ${AUDIT_IGNORE:-}"
    AUDIT_EXPECT="systemctl journalctl systemd-analyze"
    if [ -z "${AUDIT_TOOLS_ONLY:-}" ]; then
        AUDIT_EXPECT="$AUDIT_EXPECT sshd pg_lsclusters mariadbd postconf named-checkconf"
    fi
    [ ! -d /sys/firmware/efi/efivars ] || AUDIT_EXPECT="$AUDIT_EXPECT efibootmgr"
    if grep -q '^nameserver 127\.0\.0\.5[34]' /etc/resolv.conf; then
        AUDIT_EXPECT="$AUDIT_EXPECT resolvectl"
    fi
    if systemctl -q is-active docker.service; then
        AUDIT_EXPECT="$AUDIT_EXPECT docker"
    fi
    export AUDIT_IGNORE AUDIT_EXPECT
fi
"$here/readonly-audit.sh" /tmp/audit
