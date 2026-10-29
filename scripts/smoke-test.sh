#!/bin/sh
# Install a built pydebuprep .deb and check it runs. Usage (as root): smoke-test.sh FILE.deb
set -eu
apt-get install -y "$1"
pydebuprep --version
pydebuprep list-checks
rc=0
pydebuprep report --no-baseline > /dev/null || rc=$?
test "$rc" -le 2
pydebuprep configtest
pydebuprep snapshot
test "$(stat -c %a /var/lib/pydebuprep/snapshots)" = 700
test "$(stat -c %a /var/lib/pydebuprep/snapshots/*.json)" = 600
test -f /usr/share/bash-completion/completions/pydebuprep
test -f /usr/share/zsh/vendor-completions/_pydebuprep
