#!/bin/sh
# Install and audit a pydebuprep .deb inside a container booted with systemd as PID 1,
# so systemctl, journalctl and systemd-analyze meet a real service manager. The host's
# UEFI variables, if it has them, are mounted in so efibootmgr runs too.
# Usage (on a throwaway CI runner with Docker): ci-systemd-container.sh IMAGE FILE.deb
# Runs a privileged container: never use it on a machine you care about.
# The console gettys are masked: with no console they restart in a loop, and the audit
# would rightly report PID 1 starting jobs during the run.
set -eu
image=$1
deb=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
repo=$(cd "$(dirname "$0")/.." && pwd)
name=pydebuprep-systemd

docker build -t "$name" --build-arg IMAGE="$image" - <<'EOF'
ARG IMAGE
FROM $IMAGE
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus \
 && rm -rf /var/lib/apt/lists/* \
 && systemctl mask getty.target console-getty.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF

set --
if [ -d /sys/firmware/efi/efivars ]; then
    set -- -v /sys/firmware/efi/efivars:/sys/firmware/efi/efivars
fi
docker run -d --name "$name" --privileged --cgroupns=private \
    -v "$repo:/src:ro" -v "$deb:/pkg/$(basename "$deb"):ro" "$@" "$name" >/dev/null
trap 'docker rm -f "$name" >/dev/null' EXIT

# "degraded" is fine: some units (getty, kernel modules) can't start in a container.
for _ in $(seq 60); do
    state=$(docker exec "$name" systemctl is-system-running --wait 2>/dev/null || true)
    case $state in running | degraded) break ;; esac
    sleep 1
done
echo "systemd: $state"
docker exec "$name" systemctl --failed --no-legend --plain || true

docker exec -e DEBIAN_FRONTEND=noninteractive "$name" sh -eu -c "
    apt-get update
    /src/scripts/smoke-test.sh /pkg/$(basename "$deb")
    /src/scripts/ci-readonly-audit.sh
"
