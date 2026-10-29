#!/bin/sh
# Prove that pydebuprep leaves the system unchanged: run it as root under strace and
# compare filesystem timestamps before and after. Usage (as root, pydebuprep installed):
#   scripts/readonly-audit.sh [OUTDIR]
# Exits non-zero if `report` changed anything, or `snapshot` changed anything besides
# its snapshot file.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$(mktemp -d)}
mkdir -p "$out"
mkdir -p "$out"
syscalls=execve,open,openat,openat2,creat,unlink,unlinkat,rename,renameat,renameat2,mkdir,mkdirat,rmdir,link,linkat,symlink,symlinkat,chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown,truncate,ftruncate,utime,utimes,utimensat,futimesat,mknod,mknodat,mount,umount2,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,kill,tkill,tgkill,reboot,init_module,finit_module,delete_module,sethostname,setdomainname,settimeofday,clock_settime,adjtimex,clock_adjtime,swapon,swapoff,pivot_root,chroot,acct,quotactl,syslog,fallocate
status=0

changed_since() {
    find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path "$out" \) -prune \
        -o \( -newer "$1" -o -cnewer "$1" \) -print 2>/dev/null | grep -vx "$1" | grep -vx /tmp || true
}

audit() {  # NAME ALLOWED_PREFIX COMMAND...
    name=$1; allow=$2; shift 2
    marker=$(mktemp); sleep 1.1
    strace -f -qq -s 256 -o "$out/$name.strace" -e trace=$syscalls "$@" >/dev/null 2>&1 || true
    changed=$(changed_since "$marker" | grep -v "^${allow:-/nonexistent}" || true)
    rm -f "$marker"
    if [ -n "$changed" ]; then
        echo "CHANGED FILES after '$*':"; echo "$changed"; status=1
    fi
    set -- --allow /var/lib/pydebuprep/snapshots
    [ -n "$allow" ] || set --
    python3 "$here/readonly-audit.py" "$out/$name.strace" "$@" || status=1
}

audit report "" pydebuprep report --no-baseline --format json -o -
audit snapshot /var/lib/pydebuprep/snapshots pydebuprep snapshot
exit $status
