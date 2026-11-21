"""SQLite-lager for inventar, scan-kørsler og ændringshistorik."""

from __future__ import annotations

import functools
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator

from . import SCHEMA_VERSION
from .models import AppUsage, Device, Inventory, ScanRun, Service, WebApp, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS changes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL, device_id TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL
);
"""

# Felter som brugeren kan låse fra GUI'en.
EDITABLE_FIELDS = [
    "hostname", "vendor", "device_type", "os", "model", "owner", "location", "trusted", "notes", "tags",
]


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    parts = mac.replace("-", ":").lower().split(":")
    if len(parts) != 6:
        return mac.lower()
    return ":".join(p.zfill(2) for p in parts)


def locked(fn):
    """Serialisér adgang: scanner-tråden og web-requests deler samme forbindelse."""

    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return fn(self, *args, **kwargs)

    return wrapper


def device_key(ip: str | None, mac: str | None) -> str:
    m = normalize_mac(mac)
    return f"mac:{m}" if m else f"ip:{ip}"


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")  # læsere blokerer ikke skrivere
        self._conn.executescript(SCHEMA)

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            yield from self._tx()

    def _tx(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # ---------- devices ----------
    @locked
    def get(self, device_id: str) -> Device | None:
        row = self._conn.execute("SELECT data FROM devices WHERE id=?", (device_id,)).fetchone()
        return Device.model_validate_json(row[0]) if row else None

    @locked
    def all(self) -> list[Device]:
        rows = self._conn.execute("SELECT data FROM devices").fetchall()
        devs = [Device.model_validate_json(r[0]) for r in rows]
        return sorted(devs, key=lambda d: _ip_sort(d.ip))

    @locked
    def find(self, ip: str | None = None, mac: str | None = None) -> Device | None:
        mac = normalize_mac(mac)
        if mac:
            d = self.get(f"mac:{mac}")
            if d:
                return d
        if ip:
            for d in self.all():
                if d.ip == ip:
                    return d
        return None

    @locked
    def save(self, dev: Device) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO devices(id, data) VALUES(?, ?) ON CONFLICT(id) DO UPDATE SET data=excluded.data",
                (dev.id, dev.model_dump_json()),
            )

    @locked
    def delete(self, device_id: str) -> None:
        with self.tx() as c:
            c.execute("DELETE FROM devices WHERE id=?", (device_id,))

    @locked
    def log_change(self, device_id: str, kind: str, detail: str) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO changes(ts, device_id, kind, detail) VALUES(?,?,?,?)",
                (utcnow().isoformat(), device_id, kind, detail),
            )

    @locked
    def changes(self, since: datetime | None = None, limit: int = 200) -> list[dict]:
        q = "SELECT ts, device_id, kind, detail FROM changes"
        args: tuple = ()
        if since:
            q += " WHERE ts >= ?"
            args = (since.isoformat(),)
        q += " ORDER BY id DESC LIMIT ?"
        rows = self._conn.execute(q, args + (limit,)).fetchall()
        return [dict(zip(["ts", "device_id", "kind", "detail"], r)) for r in rows]

    # ---------- observationer fra scannere ----------
    @locked
    def upsert_observation(self, ip: str | None, mac: str | None = None, **fields) -> Device:
        """Flet en observation ind i eksisterende enhed. Låste (manuelle) felter røres ikke."""
        mac = normalize_mac(mac)
        dev = self.find(ip=ip, mac=mac)
        now = utcnow()
        if dev is None:
            dev = Device(id=device_key(ip, mac), ip=ip, mac=mac)
            self.log_change(dev.id, "new_device", f"Ny enhed {ip} {mac or ''} {fields.get('vendor') or ''}".strip())
        else:
            if mac and not dev.mac:
                # Enheden var kun kendt på IP – flyt til MAC-nøgle.
                self.delete(dev.id)
                dev.id = device_key(ip, mac)
                dev.mac = mac
            if ip and dev.ip != ip:
                self.log_change(dev.id, "ip_changed", f"{dev.ip} -> {ip}")
                dev.ip = ip
        for k, v in fields.items():
            if v in (None, "", [], {}):
                continue
            if k in dev.manual_fields:
                continue
            if k == "mdns_services":
                dev.mdns_services = sorted(set(dev.mdns_services) | set(v))
            elif k == "upnp":
                dev.upnp.update(v)
            elif k == "os_cpe":
                dev.os_cpe = sorted(set(dev.os_cpe) | set(v))
            else:
                setattr(dev, k, v)
        dev.last_seen = now
        dev.online = True
        self.save(dev)
        return dev

    @locked
    def set_services(self, dev: Device, services: list[Service]) -> None:
        old = {(s.port, s.protocol): s for s in dev.services}
        new = {(s.port, s.protocol): s for s in services}
        for key, s in new.items():
            o = old.get(key)
            if o is None:
                self.log_change(dev.id, "port_opened", f"{s.port}/{s.protocol} {s.product or s.name or ''}".strip())
            elif (o.product, o.version) != (s.product, s.version):
                self.log_change(
                    dev.id, "version_changed",
                    f"{s.port}/{s.protocol}: {o.product} {o.version} -> {s.product} {s.version}",
                )
        for key in old.keys() - new.keys():
            self.log_change(dev.id, "port_closed", f"{key[0]}/{key[1]}")
        # Bevar manuelt tilføjede services
        manual = [s for s in dev.services if s.source == "manual" and (s.port, s.protocol) not in new]
        dev.services = sorted(list(new.values()) + manual, key=lambda s: (s.protocol, s.port))
        self.save(dev)

    @locked
    def set_webapps(self, dev: Device, webapps: list[WebApp]) -> None:
        manual = [w for w in dev.webapps if w.source == "manual"]
        urls = {w.url for w in webapps}
        dev.webapps = webapps + [w for w in manual if w.url not in urls]
        self.save(dev)

    @locked
    def merge_apps(self, dev: Device, apps: list[AppUsage]) -> None:
        by_name = {a.app: a for a in dev.apps}
        for a in apps:
            o = by_name.get(a.app)
            if o is None:
                self.log_change(dev.id, "new_app", f"{a.app} ({a.category})")
                by_name[a.app] = a
            else:
                o.domains = sorted(set(o.domains) | set(a.domains))
                o.query_count = a.query_count
                o.last_seen = a.last_seen or o.last_seen
                o.first_seen = min(filter(None, [o.first_seen, a.first_seen]), default=None)
        dev.apps = sorted(by_name.values(), key=lambda a: (-a.query_count, a.app))
        self.save(dev)

    @locked
    def mark_offline(self, seen_ids: set[str]) -> None:
        for d in self.all():
            if d.id not in seen_ids and d.online and "manual" not in d.tags:
                d.online = False
                self.save(d)

    # ---------- runs ----------
    @locked
    def save_run(self, run: ScanRun) -> ScanRun:
        with self.tx() as c:
            if run.id is None:
                cur = c.execute("INSERT INTO runs(data) VALUES(?)", (run.model_dump_json(),))
                run.id = cur.lastrowid
            c.execute("UPDATE runs SET data=? WHERE id=?", (run.model_dump_json(), run.id))
        return run

    @locked
    def last_run(self) -> ScanRun | None:
        row = self._conn.execute("SELECT data FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        return ScanRun.model_validate_json(row[0]) if row else None

    @locked
    def runs(self, limit: int = 20) -> list[ScanRun]:
        rows = self._conn.execute("SELECT data FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [ScanRun.model_validate_json(r[0]) for r in rows]

    @locked
    def inventory(self, networks: list[str]) -> Inventory:
        return Inventory(
            schema_version=SCHEMA_VERSION, networks=networks, devices=self.all(), last_run=self.last_run()
        )


def _ip_sort(ip: str | None):
    import ipaddress

    try:
        a = ipaddress.ip_address(ip or "")
        return (a.version, int(a))
    except ValueError:
        return (9, 0)


def dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, default=str)
