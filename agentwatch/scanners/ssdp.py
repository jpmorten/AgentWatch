"""SSDP/UPnP-agent: routere, smart-tv'er, NAS, medieservere.

UPnP-device-beskrivelsen (XML) giver producent, model, modelnummer og ofte
firmwareversion. SERVER-headeren afslører typisk OS + UPnP-stak + version.
"""

from __future__ import annotations

import logging
import socket
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import httpx

from ..models import Firmware
from ..store import Store

log = logging.getLogger("agentwatch")

MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\nST: ssdp:all\r\n\r\n"
).encode()

MAX_XML = 512 * 1024
NS = "{urn:schemas-upnp-org:device-1-0}"


def msearch(seconds: float = 4.0) -> dict[str, dict]:
    """Returnér {ip: {"server": str, "locations": set, "st": set}}."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(0.5)
    out: dict[str, dict] = {}
    try:
        for _ in range(2):
            sock.sendto(MSEARCH, ("239.255.255.250", 1900))
        end = time.time() + seconds
        while time.time() < end:
            try:
                data, (ip, _) = sock.recvfrom(65507)
            except socket.timeout:
                continue
            headers = parse_headers(data.decode(errors="ignore"))
            e = out.setdefault(ip, {"server": None, "locations": set(), "st": set()})
            e["server"] = headers.get("server") or e["server"]
            if headers.get("location"):
                e["locations"].add(headers["location"])
            if headers.get("st"):
                e["st"].add(headers["st"])
    finally:
        sock.close()
    return out


def parse_headers(text: str) -> dict[str, str]:
    h = {}
    for line in text.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            h[k.strip().lower()] = v.strip()
    return h


def parse_description(xml_text: str) -> dict[str, str]:
    root = ET.fromstring(xml_text)
    dev = root.find(f"{NS}device")
    if dev is None:
        return {}
    fields = ["friendlyName", "manufacturer", "modelName", "modelNumber", "modelDescription",
              "deviceType", "softwareVersion", "firmwareVersion", "presentationURL"]
    out = {}
    for f in fields:
        el = dev.find(f"{NS}{f}")
        if el is None:  # nogle producenter bruger andre namespaces
            el = next((e for e in dev if e.tag.endswith(f)), None)
        if el is not None and el.text and el.text.strip():
            out[f] = el.text.strip()[:200]
    return out


def fetch_description(url: str, timeout: float = 4.0) -> dict[str, str]:
    try:
        with httpx.stream("GET", url, timeout=timeout) as r:
            body = b""
            for chunk in r.iter_bytes():
                body += chunk
                if len(body) > MAX_XML:
                    return {}
        return parse_description(body.decode(errors="ignore"))
    except (httpx.HTTPError, ET.ParseError):
        return {}


def guess_type(desc: dict[str, str]) -> str | None:
    t = (desc.get("deviceType", "") + " " + desc.get("modelDescription", "")).lower()
    for needle, dtype in [("internetgateway", "router"), ("wanconnection", "router"), ("mediarenderer", "media-player"),
                          ("mediaserver", "media-server"), ("tv", "tv"), ("printer", "printer"),
                          ("nas", "nas"), ("camera", "camera"), ("zoneplayer", "speaker")]:
        if needle in t:
            return dtype
    return None


def scan_ssdp(store: Store, networks: list[str], seconds: float = 4.0) -> set[str]:
    from ipaddress import ip_address, ip_network

    nets = [ip_network(n, strict=False) for n in networks]
    seen = set()
    log.info("  Sender SSDP M-SEARCH og lytter i %.0f sekunder ...", seconds)
    responses = msearch(seconds)
    log.info("  %d enheder svarede på SSDP/UPnP", len(responses))
    for ip, e in responses.items():
        if not any(ip_address(ip) in n for n in nets):
            log.debug("    %s ignoreret (uden for scope)", ip)
            continue
        desc: dict[str, str] = {}
        for loc in sorted(e["locations"]):
            host = urlparse(loc).hostname
            if host != ip:  # hent kun beskrivelser fra enheden selv
                continue
            desc = fetch_description(loc)
            if desc:
                break
        upnp = {k: v for k, v in desc.items()}
        if e["server"]:
            upnp["ssdp_server"] = e["server"][:200]
        model = " ".join(filter(None, [desc.get("modelName"), desc.get("modelNumber")])) or None
        existing = store.find(ip=ip)
        dev = store.upsert_observation(
            ip, None, upnp=upnp, model=model, device_type=guess_type(desc),
            hostname=None if existing and existing.hostname else desc.get("friendlyName"),
        )
        fw = desc.get("firmwareVersion") or desc.get("softwareVersion")
        log.info("    %-15s %s | %s %s%s", ip, desc.get("friendlyName") or "", desc.get("manufacturer") or "",
                 model or "", f" | firmware {fw}" if fw else "")
        if e["server"]:
            log.info("      SERVER: %s", e["server"][:150])
        if fw and "firmware" not in dev.manual_fields:
            dev.firmware = Firmware(version=fw, vendor=desc.get("manufacturer"), model=model, source="ssdp")
            store.save(dev)
        seen.add(dev.id)
    return seen
