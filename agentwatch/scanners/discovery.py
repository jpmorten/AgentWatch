"""Discovery-agent: find alle enheder (IP, MAC, producent, hostname)."""

from __future__ import annotations

import logging
import re
import subprocess
import sys

from ..store import Store, normalize_mac
from .nmap import is_root, parse_nmap_xml, run_nmap

log = logging.getLogger("agentwatch")

# macOS: "? (192.168.1.1) at a4:2b:b0:1:2:3 on en0 ifscope [ethernet]"
# Linux: "? (192.168.1.1) at a4:2b:b0:01:02:03 [ether] on eth0"
ARP_RE = re.compile(r"\((?P<ip>[\d.]+)\) at (?P<mac>[0-9a-fA-F:]+)")
# Windows: "  192.168.1.1          a4-2b-b0-11-22-33     dynamic"
WIN_ARP_RE = re.compile(r"^\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<mac>(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2})\s+\S+")


def parse_arp(output: str) -> dict[str, str]:
    result = {}
    for line in output.splitlines():
        m = ARP_RE.search(line) or WIN_ARP_RE.search(line)
        if not m or "incomplete" in line:
            continue
        mac = normalize_mac(m.group("mac"))
        if mac in ("ff:ff:ff:ff:ff:ff",) or (mac and mac.startswith("01:00:5e")):
            continue  # broadcast/multicast
        result[m.group("ip")] = mac  # type: ignore[assignment]
    return result


def read_arp_table() -> dict[str, str]:
    try:
        cmd = ["arp", "-a"] if sys.platform == "win32" else ["arp", "-an"]
        out = subprocess.run(cmd, capture_output=True, text=True, errors="ignore", timeout=15).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {}
    return parse_arp(out)


def discover(store: Store, networks: list[str], nmap_path: str = "nmap") -> set[str]:
    """Ping-sweep + ARP-tabel. Returnerer id'er på de enheder der blev set."""
    seen: set[str] = set()
    args = ["-sn", "-T4"]
    if not is_root():
        # Uden root bruger nmap TCP-ping; ARP-tabellen bagefter giver os MAC-adresserne.
        args += ["-PS22,80,443,445,554,8008,8080,62078", "-PA80,443"]
    for net in networks:
        log.info("  Ping-sweep af %s (%s)", net, "ARP/raw – administrator" if is_root() else "TCP-ping – uden administrator")
        hosts = parse_nmap_xml(run_nmap([*args, net], nmap_path))
        arp = read_arp_table()
        up = [h for h in hosts if h.up]
        log.info("  %d værter svarede på ping, %d står i ARP-tabellen", len(up), len(arp))
        for h in up:
            mac = h.mac or arp.get(h.ip)
            known = store.find(ip=h.ip, mac=mac) is not None
            dev = store.upsert_observation(h.ip, mac, hostname=h.hostname, vendor=h.vendor)
            seen.add(dev.id)
            log.info("    %-15s %-17s %-22s %s%s", h.ip, mac or "-", (dev.vendor or "")[:22], dev.hostname or "",
                     "" if known else "  [NY]")
        # Enheder der kun står i ARP-tabellen (svarer ikke på ping, fx telefoner i dvale)
        known_ips = {h.ip for h in hosts}
        from ipaddress import ip_address, ip_network

        n = ip_network(net, strict=False)
        for ip, mac in arp.items():
            if ip not in known_ips and ip_address(ip) in n:
                dev = store.upsert_observation(ip, mac)
                seen.add(dev.id)
                log.info("    %-15s %-17s (kun i ARP-tabellen – svarer ikke på ping)", ip, mac)
    return seen
