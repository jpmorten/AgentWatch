"""Orchestrator: kører scanner-agenterne i rækkefølge og registrerer kørslen."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

from .config import Config
from .models import ScanRun, utcnow
from .scope import parse_networks
from .store import Store

log = logging.getLogger("agentwatch")

ALL_MODULES = ["discovery", "mdns", "ssdp", "services", "web", "dns"]


STEP_TITLES = {
    "discovery": "Discovery – finder enheder (ping-sweep + ARP)",
    "mdns": "mDNS/Bonjour – Chromecast, AirPlay, printere, HomeKit …",
    "ssdp": "SSDP/UPnP – routere, tv'er, NAS, medieservere",
    "services": "Services – åbne porte og softwareversioner (nmap -sV)",
    "web": "Web – webinterfaces, teknologi, login, TLS",
    "dns": "DNS – app- og streamingbrug pr. enhed",
}


def run_scan(cfg: Config, store: Store, modules: list[str] | None = None,
             progress: Callable[[str], None] | None = None) -> ScanRun:
    """progress er bevaret for bagudkompatibilitet; al output går nu gennem loggeren 'agentwatch'."""
    modules = modules or ALL_MODULES
    parse_networks(cfg.networks)  # fejler tidligt hvis scope er ugyldigt
    run = store.save_run(ScanRun(targets=cfg.networks, modules=modules))
    seen: set[str] = set()
    t_all = time.monotonic()
    before = {d.id for d in store.all()}
    log.info("=" * 70)
    log.info("Scanning #%s startet – netværk: %s – agenter: %s", run.id, ", ".join(cfg.networks), ", ".join(modules))
    active = [m for m in ALL_MODULES if m in modules]

    def step(name: str, fn):
        if name not in modules:
            return
        n = active.index(name) + 1
        log.info("")
        log.info("[%d/%d] %s", n, len(active), STEP_TITLES.get(name, name))
        t0 = time.monotonic()
        try:
            res = fn()
            if isinstance(res, set):
                seen.update(res)
            log.info("[%d/%d] %s færdig (%.0fs)", n, len(active), name, time.monotonic() - t0)
        except Exception as exc:  # én agent må ikke vælte hele kørslen
            msg = f"{name}: {type(exc).__name__}: {exc}"
            run.errors.append(msg)
            log.error("[%d/%d] %s FEJLEDE: %s", n, len(active), name, exc)
            log.debug("Detaljer", exc_info=True)

    from .scanners import discovery, dns_usage, mdns, services, ssdp, web

    step("discovery", lambda: discovery.discover(store, cfg.networks, cfg.nmap_path))
    step("mdns", lambda: mdns.scan_mdns(store))
    step("ssdp", lambda: ssdp.scan_ssdp(store, cfg.networks))
    step("services", lambda: services.scan_services(
        store, [d.ip for d in store.all() if d.ip and d.online and (not seen or d.id in seen)],
        cfg.networks, cfg.service_profile, cfg.nmap_path) and None)
    step("web", lambda: web.scan_web(store, cfg.extra_web_ports, cfg.http_timeout) and None)
    step("dns", lambda: dns_usage.scan_dns(store, cfg.dns) and None)

    if "discovery" in modules and not any(e.startswith("discovery") for e in run.errors):
        store.mark_offline(seen)
    run.finished = utcnow()
    run.devices_found = len(seen)
    store.save_run(run)
    allv = store.all()
    new = [d for d in allv if d.id not in before]
    log.info("")
    log.info("Scanning #%s færdig på %.0fs: %d enheder set, %d nye, %d i alt, %d åbne services, %d webinterfaces",
             run.id, time.monotonic() - t_all, len(seen), len(new), len(allv),
             sum(len(d.services) for d in allv), sum(len(d.webapps) for d in allv))
    for d in new:
        log.info("  NY ENHED: %s %s %s", d.ip, d.vendor or "", d.hostname or "")
    if run.errors:
        log.warning("%d agent(er) fejlede – se ovenfor eller i logfilen", len(run.errors))
    log.info("=" * 70)
    return run
