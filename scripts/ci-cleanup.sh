#!/bin/sh
# pydebuprep-cleanup against real dpkg and apt, in a throwaway container: three kernel
# versions (small packages built here, in Ubuntu's naming, with a meta package that
# depends on the newest), a removed package whose config file stays (state rc), and a
# directory DKMS left behind. A dry run must change nothing; --all --apply --yes must
# purge exactly the oldest kernel's packages and the rc package, back up its config
# file, remove the leftover directory and log it all. Usage, from the repository:
#   docker run --rm -v "$PWD:/src:ro" debian:trixie sh /src/scripts/ci-cleanup.sh
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq install -y --no-install-recommends python3 python3-yaml >/dev/null
work=$(mktemp -d)

fake() {  # NAME VERSION [DEPENDS] [FILE] [CONFFILE]: build and install a small package
    dir="$work/$1"
    mkdir -p "$dir/DEBIAN"
    {
        echo "Package: $1"; echo "Version: $2"; echo "Architecture: all"
        echo "Maintainer: pydebuprep CI <ci@example.org>"; echo "Description: test package"
        [ -z "${3:-}" ] || echo "Depends: $3"
    } > "$dir/DEBIAN/control"
    if [ -n "${4:-}" ]; then mkdir -p "$dir$(dirname "$4")" && echo "$1" > "$dir$4"; fi
    if [ -n "${5:-}" ]; then
        mkdir -p "$dir$(dirname "$5")" && echo "setting = $1" > "$dir$5"
        echo "$5" > "$dir/DEBIAN/conffiles"
    fi
    dpkg-deb -Zxz --build "$dir" "$work/$1.deb" >/dev/null
    dpkg -i "$work/$1.deb" >/dev/null
}

for n in 10 20 30; do
    fake "linux-image-6.8.0-$n-generic" "6.8.0-$n.$n" "" "/lib/modules/6.8.0-$n-generic/kernel/x.ko"
    fake "linux-headers-6.8.0-$n-generic" "6.8.0-$n.$n" "" "/usr/src/linux-headers-6.8.0-$n-generic/Makefile"
done
fake linux-image-generic "6.8.0.30.30" "linux-image-6.8.0-30-generic"
# Older kernels that must stay: one held, and one kept with --keep-package whose files
# dpkg records under /usr/lib/modules (as Debian 13's kernels are).
fake linux-image-6.8.0-1-generic "6.8.0-1.1" "" "/lib/modules/6.8.0-1-generic/kernel/x.ko"
apt-mark hold linux-image-6.8.0-1-generic >/dev/null
fake linux-image-6.8.0-5-generic "6.8.0-5.5" "" "/usr/lib/modules/6.8.0-5-generic/kernel/x.ko"
fake fake-tool 1.0 "" "" /etc/fake-tool/fake-tool.conf
dpkg -r fake-tool >/dev/null
mkdir -p /lib/modules/6.8.0-10-generic/updates/dkms
echo built > /lib/modules/6.8.0-10-generic/updates/dkms/zfs.ko
mkdir -p /var/log/pydebuprep /var/backups/pydebuprep  # the package's postinst does this

cleanup() {
    PYTHONPATH=/src/src python3 -c 'import sys; from pydebuprep.cleanup.cli import main; sys.exit(main())' "$@"
}
state() {  # what the cleanup may change
    dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' | sort
    find /lib/modules /usr/src /etc/fake-tool | sort
}
expect() {  # TEXT PATTERN
    if printf "%s\n" "$1" | grep -q -- "$2"; then echo "ok: $2"; else
        echo "FAILED: expected $2 in:"; printf "%s\n" "$1"; exit 1
    fi
}
absent() {  # TEXT PATTERN
    if printf "%s\n" "$1" | grep -q -- "$2"; then
        echo "FAILED: unexpected $2 in:"; printf "%s\n" "$1"; exit 1
    else echo "ok: no $2"; fi
}

echo "== dry run"
before=$(state)
out=$(cleanup --all --no-config --keep-package linux-image-6.8.0-5-generic)
expect "$out" "linux-image-6.8.0-10-generic"
expect "$out" "linux-headers-6.8.0-10-generic"
expect "$out" "fake-tool"
expect "$out" "/lib/modules/6.8.0-10-generic"
expect "$out" "Dry run: nothing changed"
absent "$out" "linux-image-generic$"
if [ "$before" = "$(state)" ]; then echo "ok: the dry run changed nothing"; else
    echo "FAILED: the dry run changed something"; exit 1
fi

echo "== apply"
cleanup --all --no-config --keep-package linux-image-6.8.0-5-generic --apply --yes
after=$(state)
absent "$after" "linux-image-6.8.0-10-generic"
absent "$after" "linux-headers-6.8.0-10-generic"
absent "$after" "fake-tool"
absent "$after" "/lib/modules/6.8.0-10-generic"
absent "$after" "/etc/fake-tool"
expect "$after" "ii  linux-image-6.8.0-20-generic"
expect "$after" "ii  linux-image-6.8.0-30-generic"
expect "$after" "ii  linux-image-generic"
expect "$after" "/lib/modules/6.8.0-30-generic"
expect "$after" "hi  linux-image-6.8.0-1-generic"  # held
expect "$after" "/lib/modules/6.8.0-1-generic/kernel/x.ko"
expect "$after" "ii  linux-image-6.8.0-5-generic"  # --keep-package, files under /usr/lib
expect "$after" "/lib/modules/6.8.0-5-generic/kernel/x.ko"
expect "$after" "/lib/modules/6.8.0-20-generic/kernel/x.ko"
expect "$after" "/usr/src/linux-headers-6.8.0-20-generic/Makefile"

echo "== backup and log"
backup=$(ls /var/backups/pydebuprep/rc-*.tar.gz)
expect "$(tar -tzf "$backup")" "etc/fake-tool/fake-tool.conf"
log=$(cat /var/log/pydebuprep/cleanup.log)
expect "$log" "dry run"
expect "$log" "config files backed up to $backup"
expect "$log" "purge kernels (linux-image-6.8.0-10-generic)"
expect "$log" "removed /lib/modules/6.8.0-10-generic"
expect "$log" "done"

echo "== nothing left to do"
expect "$(cleanup --all --no-config --keep-package linux-image-6.8.0-5-generic --apply --yes)" \
    "Nothing to clean up."

echo "== apt would remove more than planned: refused, nothing changed"
fake linux-image-6.8.0-15-generic "6.8.0-15.15" "" "/lib/modules/6.8.0-15-generic/kernel/x.ko"
fake old-kernel-meta 1.0 "linux-image-6.8.0-15-generic"
before=$(state)
code=0
out=$(cleanup --kernels --no-config --keep-package linux-image-6.8.0-5-generic --apply --yes 2>&1) || code=$?
expect "$out" "apt would also change: old-kernel-meta"
if [ "$code" = 1 ]; then echo "ok: exit 1"; else echo "FAILED: exit $code"; exit 1; fi
if [ "$before" = "$(state)" ]; then echo "ok: nothing changed"; else
    echo "FAILED: the refused run changed something"; exit 1
fi
echo "cleanup: ok"
