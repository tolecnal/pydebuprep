"""libvirt: virtual machines set to start at boot, and the files they need."""

from __future__ import annotations

import pytest

from checks.helpers import make_ctx
from pydebuprep.checks.base import CheckSkipped
from pydebuprep.checks.libvirt import LibvirtCheck
from pydebuprep.model import Severity


def domain(
    name: str,
    disk: str = "/var/lib/libvirt/images/{name}.qcow2",
    emulator: str = "/usr/bin/qemu-system-x86_64",
) -> str:
    return f"""<domain type='kvm'>
  <name>{name}</name>
  <devices>
    <emulator>{emulator}</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='{disk.format(name=name)}'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <target dev='sda' bus='sata'/>
    </disk>
  </devices>
</domain>
"""


def libvirt_ctx(files: dict[str, str | None] | None = None, links: dict[str, str] | None = None):  # type: ignore[no-untyped-def]
    base: dict[str, str | None] = {
        "/etc/libvirt/qemu/web.xml": domain("web"),
        "/etc/libvirt/qemu/test.xml": domain("test"),
        "/var/lib/libvirt/images/web.qcow2": "",
        "/var/lib/libvirt/images/test.qcow2": "",
        "/usr/bin/qemu-system-x86_64": "",
        "/run/libvirt/qemu/web.xml": "<domstatus/>",
    }
    base.update(files or {})
    base_links = {"/etc/libvirt/qemu/autostart/web.xml": "/etc/libvirt/qemu/web.xml"}
    base_links.update(links or {})
    return make_ctx(files={k: v for k, v in base.items() if v is not None}, links=base_links)


def test_libvirt_skipped_without_qemu_domains() -> None:
    with pytest.raises(CheckSkipped, match="no libvirt QEMU domains"):
        LibvirtCheck().run(make_ctx())


def test_libvirt_needs_root() -> None:
    assert LibvirtCheck.requires_root


def test_libvirt_healthy() -> None:
    assert LibvirtCheck().run(libvirt_ctx()) == []


def test_libvirt_autostart_domain_not_running() -> None:
    (f,) = LibvirtCheck().run(libvirt_ctx(files={"/run/libvirt/qemu/web.xml": None}))
    assert (f.severity, f.title) == (
        Severity.WARNING,
        "Virtual machines set to start at boot aren't running",
    )
    assert f.evidence == ["web"]
    assert "sudo virsh start web" in f.remediation


def test_libvirt_missing_disk_of_an_autostart_domain_is_critical() -> None:
    (f,) = LibvirtCheck().run(libvirt_ctx(files={"/var/lib/libvirt/images/web.qcow2": None}))
    assert (f.severity, f.title) == (
        Severity.CRITICAL,
        "Virtual machines use files that don't exist",
    )
    assert f.evidence == ["web (starts at boot): disk /var/lib/libvirt/images/web.qcow2"]


def test_libvirt_missing_emulator_of_other_domains_is_a_warning() -> None:
    xml = domain("test", emulator="/usr/bin/kvm")
    (f,) = LibvirtCheck().run(libvirt_ctx(files={"/etc/libvirt/qemu/test.xml": xml}))
    assert f.severity == Severity.WARNING
    assert f.evidence == ["test: emulator /usr/bin/kvm"]


def test_libvirt_block_devices_and_escaped_paths() -> None:
    xml = domain("test", disk="/srv/a&amp;b.img").replace(
        "<disk type='file' device='cdrom'>",
        "<disk type='block' device='disk'><source dev=\"/dev/vg0/test\"/></disk>\n"
        "<disk type='file' device='cdrom'>",
    )
    (f,) = LibvirtCheck().run(libvirt_ctx(files={"/etc/libvirt/qemu/test.xml": xml}))
    assert f.evidence == ["test: disk /dev/vg0/test", "test: disk /srv/a&b.img"]
