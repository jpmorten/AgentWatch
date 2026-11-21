"""Service- og OS-agent: åbne porte, softwareversioner (med CPE) og OS-gæt."""

from __future__ import annotations

import logging
import time

from ..scope import ensure_in_scope
from ..store import Store
from .nmap import NmapHost, is_root, parse_nmap_xml, run_nmap

# NSE-scripts som kun indsamler information (ingen brute force, ingen exploits).
SAFE_SCRIPTS = [
    "banner", "http-title", "http-server-header", "http-headers", "ssl-cert", "ssh-hostkey",
    "ssh2-enum-algos", "upnp-info", "rtsp-methods", "smb-os-discovery", "smb-protocols",
    "ssl-enum-ciphers", "http-generator", "mqtt-subscribe",
]


log = logging.getLogger("agentwatch")

UDP_PORTS = "53,67,69,123,137,161,500,1900,3478,5353,5683,10001"


def build_args(profile: str, ports: str | None = None, scripts: list[str] | None = None) -> list[str]:
    args = ["-sV", "-T4", "--open", "-Pn"]  # -Pn: discovery er allerede gjort
    root = is_root()
    if ports:
        args += ["-p", ports]
    elif profile == "full" and root:
        # TCP 1-10000 + de UDP-porte der typisk afslører IoT/router-services
        args += ["-sS", "-sU", "-p", f"T:1-10000,U:{UDP_PORTS}", "--max-retries", "2"]
    elif profile == "full":
        args += ["--top-ports", "1000"]
    else:
        args += ["--top-ports", "200", "--version-light"]
    if root:
        args += ["-O", "--osscan-guess"]
    if scripts:
        bad = [s for s in scripts if s not in SAFE_SCRIPTS]
        if bad:
            raise ValueError(f"Scripts ikke tilladt: {bad}. Tilladte: {SAFE_SCRIPTS}")
        args += ["--script", ",".join(scripts)]
    return args


def apply_host(store: Store, h: NmapHost) -> None:
    dev = store.upsert_observation(
        h.ip, h.mac, vendor=h.vendor, hostname=h.hostname,
        os=f"{h.os_name} ({h.os_accuracy}%)" if h.os_name else None,
        os_cpe=h.os_cpe, device_type=h.device_type,
    )
    store.set_services(dev, h.services)


def scan_services(store: Store, ips: list[str], networks: list[str], profile: str = "quick",
                  nmap_path: str = "nmap", ports: str | None = None,
                  scripts: list[str] | None = None) -> list[NmapHost]:
    for ip in ips:
        ensure_in_scope(ip, networks)
    if not ips:
        return []
    args = build_args(profile, ports, scripts)
    log.info("  Versionsscanning af %d vært(er), profil=%s, %s%s", len(ips), profile,
             "administrator (OS-detektion til)" if is_root() else "uden administrator (ingen OS-detektion)",
             f", porte={ports}" if ports else "")
    log.info("  Det kan tage flere minutter – nmap rapporterer fremdrift undervejs")
    t0 = time.monotonic()
    hosts = parse_nmap_xml(run_nmap([*args, *ips], nmap_path))
    for h in hosts:
        if not h.up:
            continue
        apply_host(store, h)
        log.info("    %s%s – %d åbne porte", h.ip, f" ({h.os_name}, {h.os_accuracy}%)" if h.os_name else "",
                 len(h.services))
        for s in h.services:
            log.info("      %5d/%s %-14s %s %s", s.port, s.protocol, s.name or "", s.product or "", s.version or "")
    log.info("  Versionsscanning færdig på %.0fs", time.monotonic() - t0)
    return hosts
