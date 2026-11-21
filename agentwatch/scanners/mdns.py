"""mDNS/Bonjour-agent: Chromecast, AirPlay, HomeKit, printere, Sonos, NAS ...

TXT-records indeholder ofte model og firmwareversion (fx AirPlay `model`/`fv`,
Chromecast `md`/`fn`, printere `ty`/`product`).
"""

from __future__ import annotations

import logging
import socket
import time

from ..store import Store

log = logging.getLogger("agentwatch")

INTERESTING_TXT = {
    "md": "model", "model": "model", "am": "model", "ty": "model", "product": "model", "usb_mdl": "model",
    "fv": "firmware", "srcvers": "firmware", "osxvers": "os_version", "vers": "firmware", "version": "firmware",
    "fn": "name", "deviceid": "device_id", "manufacturer": "manufacturer", "mf": "manufacturer",
}

TYPE_HINTS = {
    "_googlecast._tcp.local.": "media-player",
    "_airplay._tcp.local.": "media-player",
    "_raop._tcp.local.": "speaker",
    "_spotify-connect._tcp.local.": "speaker",
    "_sonos._tcp.local.": "speaker",
    "_ipp._tcp.local.": "printer",
    "_ipps._tcp.local.": "printer",
    "_printer._tcp.local.": "printer",
    "_pdl-datastream._tcp.local.": "printer",
    "_hap._tcp.local.": "iot",
    "_homekit._tcp.local.": "iot",
    "_matter._tcp.local.": "iot",
    "_hue._tcp.local.": "iot",
    "_smb._tcp.local.": "nas/computer",
    "_afpovertcp._tcp.local.": "nas/computer",
    "_companion-link._tcp.local.": "apple-device",
    "_amzn-wplay._tcp.local.": "media-player",
    "_androidtvremote2._tcp.local.": "tv",
}


def browse(seconds: float = 6.0) -> dict[str, dict]:
    """Returnér {ip: {"services": [...], "txt": {...}, "hostname": str}}."""
    from zeroconf import ServiceBrowser, Zeroconf, ZeroconfServiceTypes

    zc = Zeroconf()
    found: dict[str, dict] = {}
    try:
        types = set(ZeroconfServiceTypes.find(zc=zc, timeout=min(seconds, 4.0))) | set(TYPE_HINTS)
        names: list[tuple[str, str]] = []

        class L:
            def add_service(self, zc_, type_, name):
                names.append((type_, name))

            def update_service(self, *a):
                pass

            def remove_service(self, *a):
                pass

        browsers = [ServiceBrowser(zc, t, L()) for t in types]
        time.sleep(seconds)
        for b in browsers:
            b.cancel()
        for type_, name in names:
            info = zc.get_service_info(type_, name, timeout=1500)
            if not info:
                continue
            for addr in info.addresses:
                if len(addr) != 4:
                    continue
                ip = socket.inet_ntoa(addr)
                entry = found.setdefault(ip, {"services": set(), "txt": {}, "hostname": None, "types": set()})
                entry["services"].add(f"{type_.removesuffix('.local.')}:{info.port}")
                entry["types"].add(type_)
                if info.server:
                    entry["hostname"] = info.server.rstrip(".")
                for k, v in (info.properties or {}).items():
                    key = (k or b"").decode(errors="ignore").lower()
                    if key in INTERESTING_TXT and v:
                        entry["txt"][INTERESTING_TXT[key]] = v.decode(errors="ignore")[:120]
    finally:
        zc.close()
    return found


def apply_mdns(store: Store, found: dict[str, dict]) -> set[str]:
    seen = set()
    log.info("  %d enheder annoncerer sig via mDNS/Bonjour", len(found))
    for ip, e in found.items():
        log.info("    %-15s %s  %s", ip, e["hostname"] or "", ", ".join(sorted(e["services"]))[:120])
        if e["txt"]:
            log.info("      TXT: %s", ", ".join(f"{k}={v}" for k, v in e["txt"].items())[:160])
        txt = e["txt"]
        dtype = next((TYPE_HINTS[t] for t in e["types"] if t in TYPE_HINTS), None)
        dev = store.upsert_observation(
            ip, None, hostname=e["hostname"], mdns_services=sorted(e["services"]),
            model=txt.get("model"), device_type=dtype,
            upnp={f"mdns_{k}": v for k, v in txt.items()},
        )
        if txt.get("firmware") and "firmware" not in dev.manual_fields:
            from ..models import Firmware

            dev.firmware = Firmware(version=txt["firmware"], model=txt.get("model"),
                                    vendor=txt.get("manufacturer"), source="mdns")
            store.save(dev)
        seen.add(dev.id)
    return seen


def scan_mdns(store: Store, seconds: float = 6.0) -> set[str]:
    log.info("  Lytter efter mDNS-annonceringer i %.0f sekunder ...", seconds)
    return apply_mdns(store, browse(seconds))
