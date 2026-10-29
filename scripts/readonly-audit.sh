#!/bin/sh
# Prove that pydebuprep leaves the system unchanged: run it as root under strace and
# compare filesystem timestamps before and after. Usage (as root, pydebuprep installed):
#   scripts/readonly-audit.sh [OUTDIR]
# Exits non-zero if `report` changed anything, or `snapshot` changed anything besides
# its snapshot file.
#
# With systemd as PID 1 it also fails if the service manager queued a job, or logged
# starting, stopping or reloading anything during the run: those happen inside PID 1,
# where strace on the run can't see them.
#
# Environment:
#   AUDIT_IGNORE  space-separated path prefixes that background services write to
#                 (journal, databases); changes there are listed but don't fail the
#                 audit. strace still covers every write by pydebuprep itself.
#   AUDIT_EXPECT  space-separated programs `report` must have run, so a check that
#                 silently skipped its command can't pass the audit unexercised.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$(mktemp -d)}
mkdir -p "$out"
syscalls=execve,open,openat,openat2,creat,unlink,unlinkat,rename,renameat,renameat2,mkdir,mkdirat,rmdir,link,linkat,symlink,symlinkat,chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown,truncate,ftruncate,utime,utimes,utimensat,futimesat,mknod,mknodat,mount,umount2,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,kill,tkill,tgkill,reboot,init_module,finit_module,delete_module,sethostname,setdomainname,settimeofday,clock_settime,adjtimex,clock_adjtime,swapon,swapoff,pivot_root,chroot,acct,quotactl,syslog,fallocate
status=0
systemd=
[ -d /run/systemd/system ] && systemd=1

changed_between() {  # START END: changed after START and not after END (some files carry
    # future mtimes, e.g. bazel's; ctime can't be set, so it can't hide a change)
    find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path "$out" \) -prune \
        -o \( \( -newer "$1" ! -newer "$2" \) -o \( -cnewer "$1" ! -cnewer "$2" \) \) -print \
        2>/dev/null | grep -vx "$1" | grep -vx "$2" | grep -vx /tmp || true
}

ignored() {  # 1|0: print the stdin paths that are (1) or aren't (0) under AUDIT_IGNORE
    awk -v want="$1" -v prefixes="${AUDIT_IGNORE:-}" '
        BEGIN { n = split(prefixes, p, " ") }
        NF { hit = 0
             for (i = 1; i <= n; i++) if (index($0, p[i]) == 1 || $0 "/" == p[i]) hit = 1
             if (hit == want) print }'
}

jobs_queued() {  # jobs PID 1 has queued since boot
    systemctl show -p NInstalledJobs --value
}

audit() {  # NAME ALLOWED_PREFIX COMMAND...
    name=$1; allow=$2; shift 2
    marker=$(mktemp); sleep 1.1
    if [ -n "$systemd" ]; then
        jobs_before=$(jobs_queued)
        cursor=$(journalctl -q -n 0 --show-cursor | sed -n 's/^-- cursor: //p')
        if [ -z "$cursor" ]; then
            echo "Can't read the journal cursor, so PID 1's log can't be checked"; status=1
        fi
    fi
    strace -f -qq -s 256 -o "$out/$name.strace" -e trace=$syscalls "$@" >/dev/null 2>&1 || true
    sleep 1.1; end=$(mktemp)
    changed=$(changed_between "$marker" "$end" | grep -v "^${allow:-/nonexistent}" || true)
    rm -f "$marker" "$end"
    noise=$(printf '%s\n' "$changed" | ignored 1)
    real=$(printf '%s\n' "$changed" | ignored 0)
    if [ -n "$noise" ]; then
        echo "Changed by background services (AUDIT_IGNORE), not counted:"; echo "$noise"
    fi
    if [ -n "$real" ]; then
        echo "CHANGED FILES after '$*':"; echo "$real"; status=1
    fi
    if [ -n "$systemd" ]; then
        jobs=$(( $(jobs_queued) - jobs_before ))
        pid1=$(journalctl -q --no-pager -o short-iso _PID=1 --after-cursor="$cursor")
        # Starting, stopping and reloading are changes. Mounts and scopes (container
        # layers, processes other agents start with systemd-run) come and go on their
        # own, and other messages (a unit file loaded on demand warning about its
        # permissions) aren't actions: those are listed only.
        acted=$(printf '%s\n' "$pid1" | grep -vE '\.(mount|scope)[: ]' \
            | grep -E "\]: (Start|Stopp|Reload|Reexecut|Finished|Deactivated)" || true)
        if [ -n "$acted" ]; then
            echo "PID 1 STARTED, STOPPED OR RELOADED during '$*':"; echo "$acted"; status=1
        elif [ "$jobs" -gt 0 ] && [ -z "$pid1" ]; then
            # A job PID 1 didn't log about can't be told apart from one we caused.
            echo "SYSTEMD JOBS: PID 1 queued $jobs job(s) during '$*' and logged nothing"
            status=1
        elif [ -n "$pid1" ]; then
            echo "PID 1 logged during '$*' ($jobs job(s); mounts, scopes or no action:" \
                "not counted):"
            echo "$pid1"
        fi
    fi
    set -- --strict /sys/firmware/efi/efivars
    [ -z "$allow" ] || set -- "$@" --allow "$allow"
    python3 "$here/readonly-audit.py" "$out/$name.strace" "$@" || status=1
}

audit report "" pydebuprep report --no-baseline --format json -o -
audit snapshot /var/lib/pydebuprep/snapshots pydebuprep snapshot

for program in ${AUDIT_EXPECT:-}; do
    if grep -Eq "execve\(\"[^\"]*/$program\", .*\) = 0$" "$out/report.strace"; then
        echo "exercised: $program"
    else
        echo "NOT EXERCISED: report never ran $program"; status=1
    fi
done
exit $status
