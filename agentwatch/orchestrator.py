"""Orchestrator: kører scanner-agenterne i rækkefølge og registrerer kørslen."""

from __future__ import annotations

import logging
from collections.abc import Callable

from .config import Config
from .models import ScanRun, utcnow
from .scope import parse_networks
from .store import Store

log = logging.getLogger("agentwatch")

ALL_MODULES = ["discovery", "mdns", "ssdp", "services", "web", "dns"]


def run_scan(cfg: Config, store: Store, modules: list[str] | None = None,
             progress: Callable[[str], None] = lambda m: log.info(m)) -> ScanRun:
    modules = modules or ALL_MODULES
    parse_networks(cfg.networks)  # fejler tidligt hvis scope er ugyldigt
    run = store.save_run(ScanRun(targets=cfg.networks, modules=modules))
    seen: set[str] = set()

    def step(name: str, fn):
        if name not in modules:
            return
        progress(f"[{name}] starter")
        try:
            res = fn()
            if isinstance(res, set):
                seen.update(res)
            progress(f"[{name}] færdig")
        except Exception as exc:  # én agent må ikke vælte hele kørslen
            msg = f"{name}: {type(exc).__name__}: {exc}"
            run.errors.append(msg)
            progress(f"[{name}] FEJL – {msg}")

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
    return run
