#!/bin/sh
# The nginx and apache checks against the configurations Debian and Ubuntu install, in a
# throwaway container: clean on the defaults with TLS enabled, comparing what a running
# nginx serves with its files, and finding what an upgrade typically breaks. As root, so
# the servers' own configuration tests run too. Usage, from the repository:
#   docker run --rm -v "$PWD:/src:ro" debian:trixie sh /src/scripts/ci-web-configs.sh
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq install -y --no-install-recommends python3 python3-yaml nginx apache2 ssl-cert \
    openssl >/dev/null

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

selfsigned() {  # CERT KEY BITS: a new self-signed certificate for this host's name
    openssl req -x509 -newkey "rsa:$3" -nodes -days 365 -subj "/CN=$host" \
        -addext "subjectAltName=DNS:$host" -keyout "$2" -out "$1" 2>/dev/null
}

host=$(hostname)
# TLS on both, with the snakeoil certificate ssl-cert made for this host's name.
printf 'server { listen 443 ssl; server_name %s; include snippets/snakeoil.conf; }\n' "$host" \
    > /etc/nginx/sites-enabled/tls
a2enmod -q ssl && a2ensite -q default-ssl
echo "ServerName localhost" > /etc/apache2/conf-enabled/servername.conf  # no AH00558

echo "== the installed configurations, with TLS"
out=$(report)
expect "$out" "^nginx ok"
expect "$out" "^apache ok"

echo "== a running nginx serves the certificate it names"
nginx
out=$(report)
expect "$out" "^nginx ok"

echo "== the certificate was renewed, nginx wasn't reloaded"
selfsigned /etc/ssl/certs/ssl-cert-snakeoil.pem /etc/ssl/private/ssl-cert-snakeoil.key 2048
out=$(report)
expect "$out" "^nginx findings .*nginx serves different certificates than its configuration names"
nginx -s quit

echo "== crypto OpenSSL refuses, a site Apache skips, a configuration nginx rejects"
selfsigned /etc/ssl/certs/weak.pem /etc/ssl/private/weak.key 1024
printf 'server { listen 8443 ssl; ssl_certificate /etc/ssl/certs/weak.pem;\n  ssl_certificate_key /etc/ssl/private/weak.key; }\n' \
    > /etc/nginx/sites-enabled/weak
printf '<VirtualHost *:8080>\n  ServerName legacy.example\n</VirtualHost>\n' > /etc/apache2/sites-available/legacy
ln -s ../sites-available/legacy /etc/apache2/sites-enabled/legacy
out=$(report)
expect "$out" "^nginx findings .*nginx uses keys or signatures OpenSSL refuses"
expect "$out" "^nginx findings .*nginx rejects its configuration"
expect "$out" "^apache findings .*Apache ignores files in sites-enabled or conf-enabled"
rm /etc/nginx/sites-enabled/weak
echo "bogus_directive on;" >> /etc/nginx/sites-enabled/tls
out=$(report)
expect "$out" "^nginx findings .*nginx rejects its configuration"

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
