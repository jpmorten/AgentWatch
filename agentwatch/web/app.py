"""Lokal web-GUI: overblik, manuel indtastning/rettelse, start scanning, eksport.

Kører kun på 127.0.0.1 som standard. POST-requests afvises hvis de ikke kommer
fra GUI'en selv (beskytter mod at en ondsindet hjemmeside sender requests til
din lokale AgentWatch).
"""

from __future__ import annotations

import logging
import os
import platform
import sys
import threading
import traceback
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from ..config import Config
from ..export import FORMATS
from ..logsetup import BUFFER, LOG, LOG_FILE
from ..models import Device, Firmware, Service, WebApp
from ..store import EDITABLE_FIELDS, Store, device_key, dumps, normalize_mac

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
DEVICE_TYPES = ["router", "access-point", "switch", "computer", "phone", "tablet", "tv", "media-player",
                "speaker", "game-console", "nas", "printer", "camera", "iot", "smart-plug", "other"]


class ScanState:
    def __init__(self):
        self.running = False
        self.task = ""  # "scan" eller "analyse"
        self.lock = threading.Lock()

    @property
    def log(self) -> list[str]:
        return BUFFER.since(0, 15)[1]


def create_app(cfg: Config, store: Store) -> FastAPI:
    app = FastAPI(title="AgentWatch", docs_url=None, redoc_url=None)
    state = ScanState()
    if BUFFER not in LOG.handlers:  # fx i tests, hvor CLI'en ikke har sat logging op
        LOG.addHandler(BUFFER)
        LOG.setLevel(logging.DEBUG)

    @app.exception_handler(Exception)
    async def on_error(request: Request, exc: Exception):
        LOG.error("Fejl i GUI ved %s %s: %s", request.method, request.url.path, exc)
        LOG.debug("".join(traceback.format_exception(exc)))
        return TEMPLATES.TemplateResponse(request, "error.html", {
            "cfg": cfg, "scan": state, "env": {"admin": True, "nmap_ok": True},
            "title": "Noget gik galt", "message": f"{type(exc).__name__}: {exc}",
            "detail": "".join(traceback.format_exception(exc))[-3000:], "log_file": str(LOG_FILE),
        }, status_code=500)

    @app.middleware("http")
    async def same_origin_post(request: Request, call_next):
        if request.method == "POST":
            src = request.headers.get("origin") or request.headers.get("referer")
            host = request.headers.get("host", "")
            if not src or urlparse(src).netloc != host:
                LOG.warning("POST %s afvist: origin=%r host=%r", request.url.path, src, host)
                return HTMLResponse(
                    "<h3>Handlingen blev afvist (CSRF-beskyttelse)</h3><p>Browseren sendte ikke en Origin/Referer "
                    f"der matcher <code>{host}</code> (fik <code>{src}</code>). Åbn GUI'en via præcis samme adresse "
                    "som den kører på, fx <a href='http://127.0.0.1:8765/'>http://127.0.0.1:8765/</a>, og slå evt. "
                    "browser-udvidelser der fjerner Referer fra for denne side.</p>", status_code=403)
        return await call_next(request)

    def render(request: Request, name: str, **ctx):
        from ..scanners.nmap import find_nmap, install_hint, is_root

        env = {"admin": is_root(), "nmap_ok": bool(find_nmap(cfg.nmap_path)), "nmap_hint": install_hint()}
        return TEMPLATES.TemplateResponse(request, name, {"cfg": cfg, "scan": state, "env": env, **ctx})

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request, q: str = "", show: str = "online"):
        devs = store.all()
        if show == "online":
            devs = [d for d in devs if d.online]
        if q:
            ql = q.lower()
            devs = [d for d in devs if ql in d.model_dump_json().lower()]
        allv = store.all()
        stats = {
            "devices": len(allv), "online": sum(d.online for d in allv),
            "services": sum(len(d.services) for d in allv),
            "webapps": sum(len(d.webapps) for d in allv),
            "no_firmware": sum(1 for d in allv if not (d.firmware and d.firmware.version)),
            "unknown_type": sum(1 for d in allv if not d.device_type),
        }
        return render(request, "index.html", devices=devs, stats=stats, q=q, show=show,
                      last_run=store.last_run())

    @app.get("/device", response_class=HTMLResponse)
    def device(request: Request, id: str):
        d = store.get(id)
        if not d:
            raise HTTPException(404, "Ukendt enhed")
        return render(request, "device.html", d=d, device_types=DEVICE_TYPES, fields=EDITABLE_FIELDS,
                      changes=[c for c in store.changes(limit=500) if c["device_id"] == d.id][:30])

    @app.post("/device/edit")
    async def device_edit(request: Request, id: str = Form(...)):
        d = _get(store, id)
        form = await request.form()
        locked = set(d.manual_fields)
        for f in EDITABLE_FIELDS:
            if f not in form:
                continue
            raw = str(form[f]).strip()
            if f == "trusted":
                val = {"yes": True, "no": False}.get(raw)
            elif f == "tags":
                val = [t.strip() for t in raw.split(",") if t.strip()]
            else:
                val = raw or None
            if val != getattr(d, f):
                setattr(d, f, val)
                locked.add(f)
                store.log_change(d.id, "manual_edit", f"{f} = {val}")
        # Brugeren kan låse/oplåse felter eksplicit
        for f in EDITABLE_FIELDS:
            if form.get(f"unlock_{f}"):
                locked.discard(f)
        d.manual_fields = sorted(locked)
        store.save(d)
        return RedirectResponse(f"/device?id={id}", status_code=303)

    @app.post("/device/firmware")
    def device_firmware(id: str = Form(...), version: str = Form(""), vendor: str = Form(""),
                        model: str = Form(""), cpe: str = Form("")):
        d = _get(store, id)
        d.firmware = Firmware(version=version or None, vendor=vendor or None, model=model or None,
                              cpe=cpe or None, source="manual")
        if "firmware" not in d.manual_fields:
            d.manual_fields.append("firmware")
        store.save(d)
        store.log_change(d.id, "manual_edit", f"firmware = {version}")
        return RedirectResponse(f"/device?id={id}", status_code=303)

    @app.post("/device/service")
    def device_service(id: str = Form(...), port: int = Form(...), protocol: str = Form("tcp"),
                       name: str = Form(""), product: str = Form(""), version: str = Form(""), cpe: str = Form("")):
        d = _get(store, id)
        d.services = [s for s in d.services if (s.port, s.protocol) != (port, protocol)]
        d.services.append(Service(port=port, protocol=protocol if protocol in ("tcp", "udp") else "tcp",
                                  name=name or None, product=product or None, version=version or None,
                                  cpe=[c.strip() for c in cpe.split(",") if c.strip()], source="manual"))
        d.services.sort(key=lambda s: (s.protocol, s.port))
        store.save(d)
        return RedirectResponse(f"/device?id={id}", status_code=303)

    @app.post("/device/service/delete")
    def device_service_delete(id: str = Form(...), port: int = Form(...), protocol: str = Form("tcp")):
        d = _get(store, id)
        d.services = [s for s in d.services if (s.port, s.protocol) != (port, protocol)]
        store.save(d)
        return RedirectResponse(f"/device?id={id}", status_code=303)

    @app.post("/device/webapp")
    def device_webapp(id: str = Form(...), url: str = Form(...), title: str = Form(""),
                      technologies: str = Form("")):
        d = _get(store, id)
        d.webapps = [w for w in d.webapps if w.url != url]
        d.webapps.append(WebApp(url=url, title=title or None, source="manual",
                                technologies=[t.strip() for t in technologies.split(",") if t.strip()]))
        store.save(d)
        return RedirectResponse(f"/device?id={id}", status_code=303)

    @app.post("/device/delete")
    def device_delete(id: str = Form(...)):
        _get(store, id)
        store.delete(id)
        return RedirectResponse("/", status_code=303)

    @app.get("/new", response_class=HTMLResponse)
    def new_form(request: Request):
        return render(request, "new.html", device_types=DEVICE_TYPES)

    @app.post("/new")
    def new_device(ip: str = Form(""), mac: str = Form(""), hostname: str = Form(""), vendor: str = Form(""),
                   device_type: str = Form(""), model: str = Form(""), os: str = Form(""),
                   firmware: str = Form(""), notes: str = Form("")):
        if not ip and not mac and not hostname:
            raise HTTPException(400, "Angiv mindst IP, MAC eller navn")
        mac_n = normalize_mac(mac) if mac else None
        key = device_key(ip or None, mac_n) if (ip or mac_n) else f"manual:{hostname.lower().replace(' ', '-')}"
        fields = {k: v or None for k, v in dict(hostname=hostname, vendor=vendor, device_type=device_type,
                                                 model=model, os=os, notes=notes).items()}
        d = Device(id=key, ip=ip or None, mac=mac_n, tags=["manual"], online=bool(ip), **fields,
                   manual_fields=[k for k, v in fields.items() if v])
        if firmware:
            d.firmware = Firmware(version=firmware, model=model or None, vendor=vendor or None, source="manual")
            d.manual_fields.append("firmware")
        store.save(d)
        store.log_change(d.id, "manual_add", hostname or ip or mac)
        return RedirectResponse(f"/device?id={d.id}", status_code=303)

    @app.get("/changes", response_class=HTMLResponse)
    def changes(request: Request):
        return render(request, "changes.html", changes=store.changes(limit=300),
                      names={d.id: d.hostname or d.model or d.ip for d in store.all()})

    def start_background(task: str, fn) -> bool:
        with state.lock:
            if state.running:
                LOG.warning("%s er allerede i gang – vent til den er færdig", state.task)
                return False
            state.running, state.task = True, task

        def worker():
            try:
                fn()
            except Exception as exc:
                LOG.error("%s fejlede: %s", task, exc)
                LOG.debug("".join(traceback.format_exception(exc)))
            finally:
                state.running, state.task = False, ""

        threading.Thread(target=worker, daemon=True, name=f"agentwatch-{task}").start()
        return True

    @app.post("/scan")
    def scan(modules: str = Form(""), profile: str = Form("")):
        from ..orchestrator import run_scan

        if profile in ("quick", "full"):
            cfg.service_profile = profile  # type: ignore[assignment]
        start_background("scanning", lambda: run_scan(cfg, store, [m for m in modules.split(",") if m] or None))
        return RedirectResponse("/#log", status_code=303)

    @app.post("/analyze")
    def analyze(instruction: str = Form("")):
        def job():
            try:
                from ..analyst import run_analyst
            except ImportError:
                LOG.error("Claude-analytikeren kræver pakken 'anthropic' (pip install agentwatch[agent])")
                return
            if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
                LOG.warning("ANTHROPIC_API_KEY er ikke sat – forsøger med 'ant auth login'-profil, hvis den findes")
            LOG.info("=" * 70)
            LOG.info("Claude-analytiker startet")
            result = run_analyst(cfg, store, instruction or None, on_text=lambda t: LOG.info("  %s", t))
            LOG.info("Analyse færdig:")
            for line in result.splitlines():
                LOG.info("  %s", line)
            LOG.info("=" * 70)

        start_background("analyse", job)
        return RedirectResponse("/#log", status_code=303)

    @app.get("/scan/status")
    def scan_status(since: int = 0):
        last, lines = BUFFER.since(since)
        return JSONResponse({"running": state.running, "task": state.task, "seq": last, "lines": lines})

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon():
        svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><circle cx="16" cy="16" r="14" '
               'fill="#2f6fde"/><circle cx="16" cy="16" r="5" fill="#fff"/></svg>')
        return Response(svg, media_type="image/svg+xml", headers={"Cache-Control": "max-age=86400"})

    @app.get("/log", response_class=HTMLResponse)
    def log_page(request: Request):
        return render(request, "log.html", lines=BUFFER.since(0, 1000)[1], log_file=str(LOG_FILE))

    @app.get("/diag", response_class=HTMLResponse)
    def diag(request: Request):
        import subprocess

        from .. import __version__
        from ..scanners.nmap import find_nmap, is_root

        nmap = find_nmap(cfg.nmap_path)
        nmap_version = ""
        if nmap:
            try:
                nmap_version = subprocess.run([nmap, "--version"], capture_output=True, text=True, timeout=10,
                                              errors="replace").stdout.splitlines()[0]
            except Exception as exc:
                nmap_version = f"kunne ikke køres: {exc}"
        npcap = ""
        if sys.platform == "win32":
            npcap = "installeret" if os.path.exists(r"C:\Windows\System32\Npcap") else "IKKE fundet (installer via nmap-installeren)"
        rows = [
            ("AgentWatch", __version__), ("Python", sys.version.split()[0]),
            ("OS", f"{platform.system()} {platform.release()} ({platform.machine()})"),
            ("Administrator/root", "ja" if is_root() else "nej – OS-detektion/UDP slået fra"),
            ("nmap", nmap or "IKKE FUNDET"), ("nmap-version", nmap_version),
            *([("Npcap", npcap)] if npcap else []),
            ("Netværk (scope)", ", ".join(cfg.networks)), ("Scan-profil", cfg.service_profile),
            ("Database", str(cfg.db_file)), ("Logfil", str(LOG_FILE)),
            ("DNS-kilde", f"{cfg.dns.type} {cfg.dns.url or cfg.dns.path or ''}"),
            ("Anthropic API-nøgle", "sat" if os.environ.get("ANTHROPIC_API_KEY") else "ikke sat (kun nødvendig til analyse)"),
            ("Enheder i inventaret", str(len(store.all()))),
        ]
        return render(request, "diag.html", rows=rows, runs=store.runs(10))

    @app.get("/export/{fmt}")
    def export(fmt: str):
        if fmt not in FORMATS:
            raise HTTPException(404)
        body = dumps(FORMATS[fmt](store.inventory(cfg.networks)))
        return Response(body, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="agentwatch-{fmt}.json"'})

    return app


def _get(store: Store, id: str) -> Device:
    d = store.get(id)
    if not d:
        raise HTTPException(404, "Ukendt enhed")
    return d
