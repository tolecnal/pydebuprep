#!/bin/sh
# The nginx and apache checks against the configurations Debian and Ubuntu install, in a
# throwaway container (nothing is started): clean on the defaults, and finding what an
# upgrade typically breaks. Usage, from the repository:
#   docker run --rm -v "$PWD:/src:ro" debian:trixie sh /src/scripts/ci-web-configs.sh
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq install -y --no-install-recommends python3 python3-yaml nginx apache2 >/dev/null

report() {  # the nginx and apache results as "id status title|title"
    PYTHONPATH=/src/src python3 -m pydebuprep report --no-baseline --checks nginx,apache \
        --format json | python3 -c '
import json, sys
for r in json.load(sys.stdin)["results"]:
    print(r["id"], r["status"], "|".join(f["title"] for f in r["findings"]))'
}
expect() {  # TEXT PATTERN
    if printf "%s\n" "$1" | grep -q -- "$2"; then echo "ok: $2"; else
        echo "FAILED: expected $2 in:"; printf "%s\n" "$1"; exit 1
    fi
}

echo "== the installed configurations"
out=$(report)
expect "$out" "^nginx ok"
expect "$out" "^apache ok"

echo "== after an upgrade broke them"
ln -s /usr/share/nginx/modules-available/mod-gone.conf /etc/nginx/modules-enabled/50-mod-gone.conf
printf 'server { listen 81; location ~ \\.php$ { fastcgi_pass unix:/run/php/php7.4-fpm.sock; } }\n' \
    > /etc/nginx/sites-enabled/php
echo "LoadModule php7_module /usr/lib/apache2/modules/libphp7.4.so" > /etc/apache2/mods-available/php7.4.load
ln -s ../mods-available/php7.4.load /etc/apache2/mods-enabled/php7.4.load
out=$(report)
expect "$out" "^nginx findings .*nginx includes files that don't exist"
expect "$out" "^nginx findings .*nginx passes requests to sockets that don't exist"
expect "$out" "^apache findings .*Apache loads modules that don't exist"
echo "web configs: ok"
