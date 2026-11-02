"""The minimal X.509 reader: what the TLS findings need, from PEM bytes."""

from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timezone

import pytest

from checks.helpers import tls_fixture
from pydebuprep.checks._x509 import CertificateError, dh_bits, parse_der, parse_pem


def first_der(pem: bytes) -> bytes:
    body = re.search(rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem, re.S)
    assert body
    return base64.b64decode(body.group(1))


def test_reads_validity_names_and_digest() -> None:
    data = tls_fixture("good.pem")
    [cert] = parse_pem(data)
    assert cert.not_before == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert cert.not_after == datetime(2027, 6, 1, tzinfo=timezone.utc)
    assert cert.subject_cn == "www.example.org"
    assert cert.dns_names == ("www.example.org", "example.org", "*.example.net")
    assert (cert.key_type, cert.key_bits, cert.signature_hash) == ("rsa", 2048, "sha256")
    assert cert.sha256 == hashlib.sha256(first_der(data)).hexdigest()
    assert parse_der(first_der(data)) == cert


def test_weak_rsa_and_sha1() -> None:
    assert parse_pem(tls_fixture("weak-rsa.pem"))[0].key_bits == 1024
    assert parse_pem(tls_fixture("sha1.pem"))[0].signature_hash == "sha1"


def test_ec_key_size_from_curve() -> None:
    cert = parse_pem(tls_fixture("ec.pem"))[0]
    assert (cert.key_type, cert.key_bits) == ("ec", 256)


def test_cn_without_san() -> None:
    cert = parse_pem(tls_fixture("cn-only.pem"))[0]
    assert cert.subject_cn == "legacy.example.org"
    assert cert.dns_names == ()


def test_chain_keeps_order() -> None:
    leaf, ca = parse_pem(tls_fixture("chain.pem"))
    assert leaf.subject_cn == "www.example.org"
    assert ca.subject_cn == "pydebuprep test CA"


def test_private_key_blocks_are_skipped() -> None:
    assert [c.subject_cn for c in parse_pem(tls_fixture("with-key.pem"))] == ["www.example.org"]


def test_validity_after_2049_uses_generalized_time() -> None:
    # Dates from 2050 on are GeneralizedTime (4-digit year); UTCTime years 50..99 are 19xx.
    from pydebuprep.checks._x509 import _time

    assert _time(0x18, b"20500101000000Z") == datetime(2050, 1, 1, tzinfo=timezone.utc)
    assert _time(0x17, b"990101000000Z") == datetime(1999, 1, 1, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"no certificate here",
        b"-----BEGIN CERTIFICATE-----\nMIIB!!\n-----END CERTIFICATE-----\n",
        b"-----BEGIN CERTIFICATE-----\n"
        + base64.b64encode(b"\x30\x82\xff\xff\x00")
        + b"\n-----END CERTIFICATE-----\n",
        b"-----BEGIN CERTIFICATE-----\n"
        + base64.b64encode(b"\x30\x80" * 40)
        + b"\n-----END CERTIFICATE-----\n",
        b"-----BEGIN CERTIFICATE-----\n"
        + base64.b64encode(b"\x30\x03\x02\x01\x00")
        + b"\n-----END CERTIFICATE-----\n",
    ],
    ids=["empty", "text", "bad-base64", "length-past-end", "indefinite", "not-a-certificate"],
)
def test_malformed_raises(data: bytes) -> None:
    with pytest.raises(CertificateError):
        parse_pem(data)


def test_truncated_certificate_raises() -> None:
    der = first_der(tls_fixture("good.pem"))
    for cut in (1, 2, 10, len(der) // 2, len(der) - 1):
        with pytest.raises(CertificateError):
            parse_der(der[:cut])


def test_dh_bits() -> None:
    assert dh_bits(tls_fixture("dh1024.pem")) == 1024
    assert dh_bits(tls_fixture("dh2048.pem")) == 2048
    assert dh_bits(tls_fixture("good.pem")) is None


# --- hand-built certificates, for what the fixtures don't have ------------------------


def enc(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + content


def seq(*parts: bytes) -> bytes:
    return enc(0x30, b"".join(parts))


def oid(dotted: str) -> bytes:
    first, second, *rest = map(int, dotted.split("."))
    body = bytes([40 * first + second])
    for value in rest:
        chunk = [value & 0x7F]
        while value := value >> 7:
            chunk.append(0x80 | (value & 0x7F))
        body += bytes(reversed(chunk))
    return enc(0x06, body)


def integer(value: int) -> bytes:
    return enc(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def name(attribute: str = "2.5.4.3", value: str = "hand.example.org") -> bytes:
    return seq(enc(0x31, seq(oid(attribute), enc(0x0C, value.encode()))))


RSA_ALG = seq(oid("1.2.840.113549.1.1.1"), enc(0x05, b""))
RSA_KEY = seq(RSA_ALG, enc(0x03, b"\x00" + seq(integer(2**2047 + 1), integer(65537))))
SHA256_RSA = "1.2.840.113549.1.1.11"


def build(
    *,
    spki: bytes = RSA_KEY,
    subject: bytes | None = None,
    extensions: bytes | None = None,
    sig: str = SHA256_RSA,
    version: bool = True,
    validity: bytes | None = None,
) -> bytes:
    fields = [
        enc(0xA0, integer(2)) if version else b"",
        integer(1),
        seq(oid(sig)),
        name(value="issuer"),
        validity or seq(enc(0x17, b"260101000000Z"), enc(0x18, b"20270101000000Z")),
        subject if subject is not None else name(),
        spki,
        enc(0xA3, seq(extensions)) if extensions is not None else b"",
    ]
    return seq(seq(*fields), seq(oid(sig)), enc(0x03, b"\x00sig"))


def test_hand_built_certificate_reads() -> None:
    cert = parse_der(build(version=False))
    assert cert.subject_cn == "hand.example.org"
    assert (cert.key_type, cert.key_bits, cert.signature_hash) == ("rsa", 2048, "sha256")
    assert cert.not_after == datetime(2027, 1, 1, tzinfo=timezone.utc)


def test_dsa_key_size_from_p() -> None:
    params = seq(integer(2**2047 + 3), integer(2**255 + 1), integer(2))
    spki = seq(seq(oid("1.2.840.10040.4.1"), params), enc(0x03, b"\x00" + integer(5)))
    cert = parse_der(build(spki=spki, sig="1.2.840.10040.4.3"))
    assert (cert.key_type, cert.key_bits, cert.signature_hash) == ("dsa", 2048, "sha1")


def test_ed25519_and_unknown_algorithms() -> None:
    ed = seq(seq(oid("1.3.101.112")), enc(0x03, b"\x00" + bytes(32)))
    cert = parse_der(build(spki=ed, sig="1.3.101.112"))
    assert (cert.key_type, cert.key_bits, cert.signature_hash) == ("ed25519", 256, "none")
    odd = seq(seq(oid("1.2.3.4")), enc(0x03, b"\x00"))
    cert = parse_der(build(spki=odd, sig="1.2.3.5"))
    assert (cert.key_type, cert.key_bits, cert.signature_hash) == ("unknown", 0, "unknown")
    curve = seq(seq(oid("1.2.840.10045.2.1"), oid("1.3.132.0.10")), enc(0x03, b"\x00\x04"))
    assert parse_der(build(spki=curve)).key_bits == 0  # secp256k1: not a curve we size


def test_subject_without_common_name() -> None:
    assert parse_der(build(subject=name("2.5.4.10", "An Org"))).subject_cn is None
    assert parse_der(build(subject=seq())).subject_cn is None


def test_extensions_without_san_and_other_general_names() -> None:
    basic = seq(oid("2.5.29.19"), enc(0x01, b"\xff"), enc(0x04, seq()))
    assert parse_der(build(extensions=basic)).dns_names == ()
    san = seq(
        oid("2.5.29.17"), enc(0x04, seq(enc(0x87, b"\x7f\x00\x00\x01"), enc(0x82, b"a.example")))
    )
    assert parse_der(build(extensions=basic + san)).dns_names == ("a.example",)


@pytest.mark.parametrize(
    "der",
    [
        build() + b"\x00",
        build(subject=integer(1)),
        build(validity=seq(enc(0x04, b"260101000000Z"), enc(0x17, b"270101000000Z"))),
        build(spki=seq(seq(enc(0x06, b"")), enc(0x03, b"\x00"))),
    ],
    ids=["trailing-data", "subject-not-a-sequence", "time-not-a-time", "empty-oid"],
)
def test_hand_built_malformed_raises(der: bytes) -> None:
    with pytest.raises(CertificateError):
        parse_der(der)


def test_empty_dh_parameters_raise() -> None:
    pem = (
        b"-----BEGIN DH PARAMETERS-----\n"
        + base64.b64encode(seq())
        + b"\n-----END DH PARAMETERS-----\n"
    )
    with pytest.raises(CertificateError):
        dh_bits(pem)


def test_many_begin_lines_without_an_end_are_fast() -> None:
    # Was quadratic: a 16 MiB file of BEGIN lines would have taken hours as root.
    import time

    data = b"-----BEGIN CERTIFICATE-----\n" * 80_000  # ~2.2 MB
    start = time.monotonic()
    with pytest.raises(CertificateError):
        parse_pem(data)
    assert time.monotonic() - start < 2


def test_oversized_oid_is_rejected() -> None:
    with pytest.raises(CertificateError, match="OID"):
        parse_der(build(sig="1.2." + ".".join(["1" * 30] * 20)))


def test_parse_leaf() -> None:
    from pydebuprep.checks._x509 import parse_leaf

    assert parse_leaf(tls_fixture("chain.pem")).subject_cn == "www.example.org"
    with pytest.raises(CertificateError, match="no certificate"):
        parse_leaf(tls_fixture("dh2048.pem"))
