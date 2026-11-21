"""Kør nmap og parse XML-output."""

from __future__ import annotations

import os
import shutil
import subprocess
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


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def run_nmap(args: list[str], nmap_path: str = "nmap", timeout: int = 1800) -> str:
    exe = shutil.which(nmap_path) or nmap_path
    if not shutil.which(exe):
        raise NmapError("nmap blev ikke fundet. Installer med: brew install nmap")
    cmd = [exe, "-oX", "-", *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
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
