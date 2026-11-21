"""App-brug-agent: læser DNS-logs og udleder hvilke apps/tjenester hver enhed bruger.

Kilder (se docs/dns-logs.md):
- AdGuard Home (anbefalet på macOS – kan køre på din Mac eller en Raspberry Pi)
- Pi-hole v6
- dnsmasq-logfil (fx fra OpenWrt/Asuswrt-Merlin med log-queries)
- CSV (client_ip,domain,timestamp) – til routere der kan eksportere DNS-log
"""

from __future__ import annotations

import csv
import logging
import os
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx

from ..apps_catalog import build_index, load_catalog, match_domain
from ..config import DnsSource
from ..models import AppUsage
from ..store import Store


log = logging.getLogger("agentwatch")


@dataclass
class Query:
    client_ip: str
    domain: str
    ts: datetime


def _cutoff(hours: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=hours)


def _parse_ts(v) -> datetime:
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(float(v), tz=timezone.utc)
    s = str(v).replace("Z", "+00:00")
    # AdGuard bruger nanosekunder: 2026-11-21T10:00:00.123456789+01:00
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def fetch_adguard(src: DnsSource, max_pages: int = 50) -> list[Query]:
    auth = (src.username, os.environ.get(src.password_env, "")) if src.username else None
    cutoff = _cutoff(src.hours)
    out: list[Query] = []
    older_than = ""
    with httpx.Client(base_url=src.url.rstrip("/"), auth=auth, timeout=20) as c:
        for _ in range(max_pages):
            params = {"limit": 1000}
            if older_than:
                params["older_than"] = older_than
            r = c.get("/control/querylog", params=params)
            r.raise_for_status()
            data = r.json()
            rows = data.get("data") or []
            for row in rows:
                ts = _parse_ts(row["time"])
                if ts < cutoff:
                    return out
                name = (row.get("question") or {}).get("name") or (row.get("question") or {}).get("host")
                if name and row.get("client"):
                    out.append(Query(row["client"], name, ts))
            older_than = data.get("oldest") or ""
            if not rows or not older_than:
                break
    return out


def fetch_pihole(src: DnsSource) -> list[Query]:
    base = src.url.rstrip("/")
    with httpx.Client(base_url=base, timeout=30) as c:
        r = c.post("/api/auth", json={"password": os.environ.get(src.password_env, "")})
        r.raise_for_status()
        sid = r.json()["session"]["sid"]
        try:
            now = datetime.now(timezone.utc)
            r = c.get("/api/queries", headers={"sid": sid}, params={
                "from": int(_cutoff(src.hours).timestamp()), "until": int(now.timestamp()), "length": 100000})
            r.raise_for_status()
            return [Query((q.get("client") or {}).get("ip"), q["domain"], _parse_ts(q["time"]))
                    for q in r.json().get("queries", []) if (q.get("client") or {}).get("ip")]
        finally:
            c.delete("/api/auth", headers={"sid": sid})


DNSMASQ_RE = re.compile(r"^(?P<ts>\w{3}\s+\d+\s[\d:]+).*query\[\w+\]\s(?P<domain>\S+)\sfrom\s(?P<ip>[\d.a-f:]+)")


def parse_dnsmasq(lines, year: int | None = None) -> list[Query]:
    year = year or datetime.now().year
    out = []
    for line in lines:
        m = DNSMASQ_RE.search(line)
        if not m:
            continue
        try:
            ts = datetime.strptime(f"{year} {m.group('ts')}", "%Y %b %d %H:%M:%S").astimezone(timezone.utc)
        except ValueError:
            continue
        out.append(Query(m.group("ip"), m.group("domain"), ts))
    return out


def parse_csv(lines) -> list[Query]:
    out = []
    for row in csv.DictReader(lines):
        try:
            out.append(Query(row["client_ip"], row["domain"], _parse_ts(row["timestamp"])))
        except (KeyError, ValueError):
            continue
    return out


def fetch_queries(src: DnsSource) -> list[Query]:
    if src.type == "adguard":
        return fetch_adguard(src)
    if src.type == "pihole":
        return fetch_pihole(src)
    if src.type in ("dnsmasq_log", "csv"):
        with open(os.path.expanduser(src.path or ""), encoding="utf-8", errors="ignore") as f:
            qs = parse_dnsmasq(f) if src.type == "dnsmasq_log" else parse_csv(f)
        cutoff = _cutoff(src.hours)
        return [q for q in qs if q.ts >= cutoff]
    return []


def aggregate(queries: list[Query], extra_catalog: str | None = None) -> dict[str, list[AppUsage]]:
    index = build_index(load_catalog(extra_catalog))
    acc: dict[tuple[str, str], dict] = defaultdict(lambda: {"domains": set(), "n": 0, "first": None, "last": None})
    cats: dict[str, str] = {}
    for q in queries:
        hit = match_domain(q.domain, index)
        if not hit:
            continue
        app, cat = hit
        cats[app] = cat
        a = acc[(q.client_ip, app)]
        a["domains"].add(q.domain.lower().strip("."))
        a["n"] += 1
        a["first"] = min(filter(None, [a["first"], q.ts]))
        a["last"] = max(filter(None, [a["last"], q.ts]))
    result: dict[str, list[AppUsage]] = defaultdict(list)
    for (ip, app), a in acc.items():
        result[ip].append(AppUsage(app=app, category=cats[app], domains=sorted(a["domains"])[:25],
                                   query_count=a["n"], first_seen=a["first"], last_seen=a["last"]))
    return result


def unknown_domains(queries: list[Query], extra_catalog: str | None = None, top: int = 50) -> list[tuple[str, int]]:
    """Hyppigste domæner der ikke matcher kataloget – nyttigt for LLM-analysen."""
    index = build_index(load_catalog(extra_catalog))
    counts: dict[str, int] = defaultdict(int)
    for q in queries:
        if not match_domain(q.domain, index):
            parts = q.domain.lower().strip(".").split(".")
            counts[".".join(parts[-2:])] += 1
    return sorted(counts.items(), key=lambda x: -x[1])[:top]


def scan_dns(store: Store, src: DnsSource, extra_catalog: str | None = None) -> int:
    if src.type == "none":
        log.info("  Ingen DNS-kilde konfigureret (dns.type: none) – springer over. Se docs/dns-logs.md")
        return 0
    log.info("  Henter DNS-opslag fra %s (%s) for de sidste %d timer", src.type, src.url or src.path, src.hours)
    queries = fetch_queries(src)
    per_ip = aggregate(queries, extra_catalog)
    log.info("  %d opslag fra %d klienter, %d genkendte app-forbindelser",
             len(queries), len({q.client_ip for q in queries}), sum(len(a) for a in per_ip.values()))
    for ip, apps in per_ip.items():
        dev = store.find(ip=ip) or store.upsert_observation(ip, None)
        store.merge_apps(dev, apps)
        log.info("    %-15s %s", ip, ", ".join(f"{a.app} ({a.query_count})" for a in apps[:10]))
    return sum(len(a) for a in per_ip.values())
