#!/bin/sh
# Regenerate the TLS fixtures in tests/data/tls/ (certificates with fixed dates, keys
# and DH parameters). The tests compare against tests/fakes.py's FROZEN_NOW
# (2026-10-28T12:00:00Z), so the dates here are absolute. Needs openssl; run from the
# repository: scripts/make-test-certs.sh
set -eu
export SAN=DNS:unused  # the config refers to it; each leaf sets its own
out=tests/data/tls
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out" "$work/new"
: > "$work/index"
echo 1000 > "$work/serial"
cat > "$work/ca.cnf" <<EOF
[ca]
default_ca = test
[test]
dir = $work
database = $work/index
new_certs_dir = $work/new
serial = $work/serial
policy = any
unique_subject = no
copy_extensions = none
[any]
commonName = supplied
[ca_ext]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign
[leaf]
basicConstraints = CA:false
[san]
basicConstraints = CA:false
subjectAltName = \$ENV::SAN
EOF

# A CA to sign the leaves, valid 2020..2040.
openssl genrsa -out "$work/ca.key" 2048 2>/dev/null
openssl req -new -key "$work/ca.key" -subj "/CN=pydebuprep test CA" -out "$work/ca.csr"
openssl ca -batch -notext -config "$work/ca.cnf" -selfsign -keyfile "$work/ca.key" \
    -in "$work/ca.csr" -out "$work/ca.pem" -extensions ca_ext -md sha256 \
    -startdate 20200101000000Z -enddate 20400101000000Z 2>/dev/null

leaf() {  # NAME KEYSPEC MD START END CN [SAN]
    name=$1 keyspec=$2 md=$3 start=$4 end=$5 cn=$6 san=${7:-}
    case $keyspec in
        rsa:*) openssl genrsa -out "$work/$name.key" "${keyspec#rsa:}" 2>/dev/null ;;
        ec:*) openssl ecparam -genkey -noout -name "${keyspec#ec:}" -out "$work/$name.key" ;;
    esac
    openssl req -new -key "$work/$name.key" -subj "/CN=$cn" -out "$work/$name.csr"
    ext=leaf
    [ -z "$san" ] || ext=san
    SAN=${san:-DNS:unused} openssl ca -batch -notext -config "$work/ca.cnf" \
        -cert "$work/ca.pem" -keyfile "$work/ca.key" -in "$work/$name.csr" \
        -out "$out/$name.pem" -extensions "$ext" -md "$md" \
        -startdate "$start" -enddate "$end" 2>/dev/null
}

names="DNS:www.example.org,DNS:example.org,DNS:*.example.net"
leaf good rsa:2048 sha256 20260101000000Z 20270601000000Z www.example.org "$names"
cp "$work/good.key" "$out/good.key"
leaf soon rsa:2048 sha256 20260101000000Z 20261120000000Z soon.example.org DNS:soon.example.org
leaf critical rsa:2048 sha256 20260101000000Z 20261105000000Z crit.example.org DNS:crit.example.org
leaf expired rsa:2048 sha256 20250101000000Z 20261001000000Z old.example.org DNS:old.example.org
leaf future rsa:2048 sha256 20261201000000Z 20271201000000Z new.example.org DNS:new.example.org
leaf weak-rsa rsa:1024 sha256 20260101000000Z 20270601000000Z weak.example.org DNS:weak.example.org
leaf sha1 rsa:2048 sha1 20260101000000Z 20270601000000Z sha1.example.org DNS:sha1.example.org
leaf ec ec:prime256v1 sha256 20260101000000Z 20270601000000Z ec.example.org DNS:ec.example.org
leaf cn-only rsa:2048 sha256 20260101000000Z 20270601000000Z legacy.example.org
cat "$out/good.pem" "$work/ca.pem" > "$out/chain.pem"
cat "$work/good.key" "$out/good.pem" > "$out/with-key.pem"
openssl dhparam -out "$out/dh1024.pem" 1024 2>/dev/null
openssl dhparam -out "$out/dh2048.pem" 2048 2>/dev/null
echo "written to $out"
