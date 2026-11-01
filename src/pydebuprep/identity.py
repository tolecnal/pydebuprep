"""The machine ID a report carries, to tell apart machines that report the same host name.

/etc/machine-id is meant to stay on the machine (machine-id(5): "should not be exposed
in untrusted environments, in particular on the network"), so a report carries the
ID systemd derives for an application instead: HMAC-SHA256 keyed with the machine ID
over pydebuprep's own APP_ID, cut to 128 bits and marked as a version 4 UUID, exactly
as sd_id128_get_machine_app_specific() does. On the host,
`systemd-id128 machine-id -a e44561703c184c26a2c15fb541fc276a` prints the same value.
"""

from __future__ import annotations

import hashlib
import hmac
import re

from pydebuprep.system import System

# Fixed for good: a new one would give every host a new machine ID.
APP_ID = "e44561703c184c26a2c15fb541fc276a"
MACHINE_ID_FILES = ("/etc/machine-id", "/var/lib/dbus/machine-id")
MACHINE_ID = re.compile(r"[0-9a-f]{32}")


def app_specific_id(text: str) -> str | None:
    """pydebuprep's ID for the machine whose machine-id file holds TEXT; None if it holds
    no usable ID (empty, "uninitialized", all zeros)."""
    value = text.strip().lower()
    if not MACHINE_ID.fullmatch(value) or value == "0" * 32:
        return None
    digest = bytearray(
        hmac.new(bytes.fromhex(value), bytes.fromhex(APP_ID), hashlib.sha256).digest()[:16]
    )
    digest[6] = (digest[6] & 0x0F) | 0x40  # UUID version 4
    digest[8] = (digest[8] & 0x3F) | 0x80  # RFC 4122 variant
    return digest.hex()


def machine_id(system: System) -> str | None:
    """This machine's ID for reports, or None if it has no machine ID."""
    for path in MACHINE_ID_FILES:
        text = system.read_text(path)
        if text is not None:
            return app_specific_id(text)
    return None
