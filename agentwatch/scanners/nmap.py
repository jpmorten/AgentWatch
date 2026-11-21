"""Kør nmap og parse XML-output."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from ..models import Service


class NmapError(RuntimeError):
    pass


@dataclass
class NmapHost:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    up: bool = True
    services: list[Service] = field(default_factory=list)
    os_name: str | None = None
    os_accuracy: int | None = None
    os_cpe: list[str] = field(default_factory=list)
    device_type: str | None = None


IS_WINDOWS = sys.platform == "win32"

# Standard-installationssteder for nmap på Windows (nmap.org-installeren)
WINDOWS_NMAP_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
]


def is_root() -> bool:
    """Root på macOS/Linux, administrator på Windows (giver raw sockets via Npcap)."""
    if IS_WINDOWS:
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def find_nmap(nmap_path: str = "nmap") -> str | None:
    found = shutil.which(nmap_path)
    if found:
        return found
    if os.path.isfile(nmap_path):
        return nmap_path
    if IS_WINDOWS:
        return next((p for p in WINDOWS_NMAP_PATHS if os.path.isfile(p)), None)
    return None


def install_hint() -> str:
    if IS_WINDOWS:
        return "Installer med: winget install Insecure.Nmap  (eller hent installeren fra nmap.org)"
    if sys.platform == "darwin":
        return "Installer med: brew install nmap"
    return "Installer med: sudo apt install nmap"


def run_nmap(args: list[str], nmap_path: str = "nmap", timeout: int = 1800) -> str:
    exe = find_nmap(nmap_path)
    if not exe:
        raise NmapError(f"nmap blev ikke fundet. {install_hint()}")
    cmd = [exe, "-oX", "-", *args]
    if IS_WINDOWS and not is_root() and "--unprivileged" not in args:
        # Uden administrator kan nmap på Windows ikke bruge raw sockets (Npcap) – brug TCP connect
        cmd.insert(1, "--unprivileged")
    kwargs = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # intet konsolvindue fra GUI'en
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, **kwargs)
    if proc.returncode != 0 and not proc.stdout.strip():
        raise NmapError(proc.stderr.strip() or f"nmap fejlede: {' '.join(cmd)}")
    return proc.stdout


def parse_nmap_xml(xml_text: str) -> list[NmapHost]:
    root = ET.fromstring(xml_text)
    hosts: list[NmapHost] = []
    for h in root.findall("host"):
        status = h.find("status")
        up = status is None or status.get("state") == "up"
        ip = mac = vendor = None
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6") and ip is None:
                ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac = a.get("addr")
                vendor = a.get("vendor")
        if not ip:
            continue
        hn = h.find("hostnames/hostname")
        host = NmapHost(ip=ip, mac=mac, vendor=vendor, hostname=hn.get("name") if hn is not None else None, up=up)

        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") not in ("open", "open|filtered"):
                continue
            svc = p.find("service")
            host.services.append(
                Service(
                    port=int(p.get("portid", "0")),
                    protocol=p.get("protocol", "tcp"),  # type: ignore[arg-type]
                    state=st.get("state", "open"),
                    name=svc.get("name") if svc is not None else None,
                    product=svc.get("product") if svc is not None else None,
                    version=svc.get("version") if svc is not None else None,
                    extra_info=_join(svc.get("extrainfo"), svc.get("ostype")) if svc is not None else None,
                    cpe=[c.text for c in svc.findall("cpe") if c.text] if svc is not None else [],
                )
            )
            if svc is not None and svc.get("devicetype") and not host.device_type:
                host.device_type = svc.get("devicetype")

        best = None
        for m in h.findall("os/osmatch"):
            acc = int(m.get("accuracy", "0"))
            if best is None or acc > best[0]:
                best = (acc, m)
        if best:
            acc, m = best
            host.os_name, host.os_accuracy = m.get("name"), acc
            for oc in m.findall("osclass"):
                host.os_cpe += [c.text for c in oc.findall("cpe") if c.text]
                if oc.get("type") and not host.device_type:
                    host.device_type = oc.get("type")
            host.os_cpe = sorted(set(host.os_cpe))
        hosts.append(host)
    return hosts


def _join(*parts: str | None) -> str | None:
    s = "; ".join(p for p in parts if p)
    return s or None
