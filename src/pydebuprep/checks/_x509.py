"""Just enough of X.509 for the TLS findings: validity, names, key and signature.

A tiny DER reader instead of a dependency (python3-cryptography) or a command
(`openssl x509 -in FILE` would open the file itself, outside System's safe reads). It
walks the fixed structure of a certificate, so its depth is bounded by that structure;
every length is checked against the bytes that remain, and anything unexpected raises
CertificateError.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

MAX_OID_BYTES = 64  # real OIDs are under 20; longer ones only cost time to decode

SEQUENCE, SET, INTEGER, BIT_STRING, OCTET_STRING, OID = 0x30, 0x31, 0x02, 0x03, 0x04, 0x06
UTC_TIME, GENERALIZED_TIME = 0x17, 0x18
VERSION, EXTENSIONS = 0xA0, 0xA3  # [0] and [3], constructed
DNS_NAME = 0x82  # GeneralName dNSName: [2], primitive

COMMON_NAME = "2.5.4.3"
SUBJECT_ALT_NAME = "2.5.29.17"
SIGNATURE_HASHES = {
    "1.2.840.113549.1.1.4": "md5",
    "1.2.840.113549.1.1.5": "sha1",
    "1.2.840.113549.1.1.14": "sha224",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
    "1.2.840.10045.4.1": "sha1",
    "1.2.840.10045.4.3.1": "sha224",
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512",
    "1.2.840.10040.4.3": "sha1",
    "2.16.840.1.101.3.4.3.1": "sha224",
    "2.16.840.1.101.3.4.3.2": "sha256",
    "1.3.101.112": "none",  # Ed25519 signs without a separate hash
    "1.3.101.113": "none",  # Ed448
}
KEY_TYPES = {
    "1.2.840.113549.1.1.1": "rsa",
    "1.2.840.113549.1.1.10": "rsa",  # RSASSA-PSS key
    "1.2.840.10040.4.1": "dsa",
    "1.2.840.10045.2.1": "ec",
    "1.3.101.112": "ed25519",
    "1.3.101.113": "ed448",
}
CURVE_BITS = {
    "1.2.840.10045.3.1.1": 192,  # prime192v1
    "1.3.132.0.33": 224,  # secp224r1
    "1.2.840.10045.3.1.7": 256,  # prime256v1
    "1.3.132.0.34": 384,  # secp384r1
    "1.3.132.0.35": 521,  # secp521r1
}
FIXED_BITS = {"ed25519": 256, "ed448": 456}


class CertificateError(ValueError):
    """The data isn't a certificate this reader understands."""


@dataclass(frozen=True)
class Certificate:
    not_before: datetime
    not_after: datetime
    subject_cn: str | None
    dns_names: tuple[str, ...]
    signature_hash: str
    key_type: str
    key_bits: int
    sha256: str


Tlv = tuple[int, int, int]  # tag, first content byte, end of content


def _tlv(data: bytes, pos: int, end: int) -> Tlv:
    if pos + 2 > end:
        raise CertificateError("truncated")
    tag, first = data[pos], data[pos + 1]
    pos += 2
    if first & 0x80:
        count = first & 0x7F
        if not 1 <= count <= 4 or pos + count > end:
            raise CertificateError("unsupported length")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    else:
        length = first
    if pos + length > end:
        raise CertificateError("length past the end")
    return tag, pos, pos + length


def _children(data: bytes, parent: Tlv) -> list[Tlv]:
    _, pos, end = parent
    found = []
    while pos < end:
        child = _tlv(data, pos, end)
        found.append(child)
        pos = child[2]
    return found


def _expect(item: Tlv, tag: int) -> Tlv:
    if item[0] != tag:
        raise CertificateError(f"expected tag {tag:#x}, got {item[0]:#x}")
    return item


def _oid(data: bytes, item: Tlv) -> str:
    raw = data[_expect(item, OID)[1] : item[2]]
    if not raw or len(raw) > MAX_OID_BYTES:
        raise CertificateError(f"OID of {len(raw)} bytes")
    parts = [min(raw[0] // 40, 2), raw[0] - 40 * min(raw[0] // 40, 2)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(map(str, parts))


def _bits(data: bytes, item: Tlv) -> int:
    return int.from_bytes(data[_expect(item, INTEGER)[1] : item[2]], "big").bit_length()


def _time(tag: int, raw: bytes) -> datetime:
    text = raw.decode("ascii")
    if tag == UTC_TIME:
        year = int(text[:2])
        text = f"{1900 + year if year >= 50 else 2000 + year}{text[2:]}"
    elif tag != GENERALIZED_TIME:
        raise CertificateError("not a time")
    return datetime.strptime(text, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)


def _common_name(data: bytes, name: Tlv) -> str | None:
    for rdn in _children(data, _expect(name, SEQUENCE)):
        for attribute in _children(data, _expect(rdn, SET)):
            oid, value = _children(data, _expect(attribute, SEQUENCE))[:2]
            if _oid(data, oid) == COMMON_NAME:
                return data[value[1] : value[2]].decode("utf-8", "replace")
    return None


def _dns_names(data: bytes, extensions: Tlv) -> tuple[str, ...]:
    [inner] = _children(data, extensions)
    for extension in _children(data, _expect(inner, SEQUENCE)):
        parts = _children(data, _expect(extension, SEQUENCE))
        if _oid(data, parts[0]) != SUBJECT_ALT_NAME:
            continue
        value = _expect(parts[-1], OCTET_STRING)
        [names] = _children(data, value)
        return tuple(
            data[n[1] : n[2]].decode("ascii", "replace")
            for n in _children(data, _expect(names, SEQUENCE))
            if n[0] == DNS_NAME
        )
    return ()


def _key(data: bytes, spki: Tlv) -> tuple[str, int]:
    algorithm, key = _children(data, _expect(spki, SEQUENCE))
    alg_parts = _children(data, _expect(algorithm, SEQUENCE))
    key_type = KEY_TYPES.get(_oid(data, alg_parts[0]), "unknown")
    if key_type == "rsa":
        _, start, end = _expect(key, BIT_STRING)
        inner = _tlv(data, start + 1, end)  # skip the unused-bits byte
        return key_type, _bits(data, _children(data, _expect(inner, SEQUENCE))[0])
    if key_type == "dsa":
        return key_type, _bits(data, _children(data, _expect(alg_parts[1], SEQUENCE))[0])
    if key_type == "ec":
        return key_type, CURVE_BITS.get(_oid(data, alg_parts[1]), 0)
    return key_type, FIXED_BITS.get(key_type, 0)


def parse_der(der: bytes) -> Certificate:
    """The certificate in DER; raises CertificateError if it isn't one."""
    try:
        top = _expect(_tlv(der, 0, len(der)), SEQUENCE)
        if top[2] != len(der):
            raise CertificateError("trailing data")
        tbs, signature_alg, _ = _children(der, top)
        fields = _children(der, _expect(tbs, SEQUENCE))
        if fields[0][0] == VERSION:
            fields = fields[1:]
        _serial, _alg, _issuer, validity, subject, spki, *rest = fields
        not_before, not_after = _children(der, _expect(validity, SEQUENCE))
        extensions = next((f for f in rest if f[0] == EXTENSIONS), None)
        key_type, key_bits = _key(der, spki)
        sig_oid = _oid(der, _children(der, _expect(signature_alg, SEQUENCE))[0])
        return Certificate(
            not_before=_time(not_before[0], der[not_before[1] : not_before[2]]),
            not_after=_time(not_after[0], der[not_after[1] : not_after[2]]),
            subject_cn=_common_name(der, subject),
            dns_names=_dns_names(der, extensions) if extensions else (),
            signature_hash=SIGNATURE_HASHES.get(sig_oid, "unknown"),
            key_type=key_type,
            key_bits=key_bits,
            sha256=hashlib.sha256(der).hexdigest(),
        )
    except CertificateError:
        raise
    except (ValueError, IndexError) as exc:  # unpacking, decoding, dates
        raise CertificateError(f"not a certificate: {exc}") from None


def _blocks(data: bytes, label: bytes) -> list[bytes]:
    """The decoded bodies of the PEM blocks labelled LABEL, in order. A linear scan:
    a file of BEGIN lines without an END must not cost quadratic time as root."""
    begin, end = b"-----BEGIN " + label + b"-----", b"-----END " + label + b"-----"
    found, pos = [], 0
    while (start := data.find(begin, pos)) != -1:
        body_start = start + len(begin)
        stop = data.find(end, body_start)
        if stop == -1:
            break
        try:
            found.append(base64.b64decode(b"".join(data[body_start:stop].split()), validate=True))
        except binascii.Error:
            raise CertificateError("bad base64 in a PEM block") from None
        pos = stop + len(end)
    return found


def parse_pem(data: bytes) -> list[Certificate]:
    """Every certificate in a PEM file, in order (the leaf first, then its chain).
    Other blocks, such as a private key, are skipped without being decoded."""
    certificates = [parse_der(der) for der in _blocks(data, b"CERTIFICATE")]
    if not certificates:
        raise CertificateError("no certificate in the file")
    return certificates


def dh_bits(data: bytes) -> int | None:
    """The prime size of the first DH PARAMETERS block, or None without one."""
    blocks = _blocks(data, b"DH PARAMETERS")
    if not blocks:
        return None
    der = blocks[0]
    try:
        top = _expect(_tlv(der, 0, len(der)), SEQUENCE)
        return _bits(der, _children(der, top)[0])
    except IndexError:
        raise CertificateError("empty DH parameters") from None
