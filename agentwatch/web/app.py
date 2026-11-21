"""Lokal web-GUI: overblik, manuel indtastning/rettelse, start scanning, eksport.

Kører kun på 127.0.0.1 som standard. POST-requests afvises hvis de ikke kommer
fra GUI'en selv (beskytter mod at en ondsindet hjemmeside sender requests til
din lokale AgentWatch).
"""

from __future__ import annotations

import threading
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from ..config import Config
from ..export import FORMATS
from ..models import Device, Firmware, Service, WebApp
from ..store import EDITABLE_FIELDS, Store, device_key, dumps, normalize_mac

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
DEVICE_TYPES = ["router", "access-point", "switch", "computer", "phone", "tablet", "tv", "media-player",
                "speaker", "game-console", "nas", "printer", "camera", "iot", "smart-plug", "other"]


class ScanState:
    def __init__(self):
        self.running = False
        self.log: list[str] = []
        self.lock = threading.Lock()


def create_app(cfg: Config, store: Store) -> FastAPI:
    app = FastAPI(title="AgentWatch", docs_url=None, redoc_url=None)
    state = ScanState()

    @app.middleware("http")
    async def same_origin_post(request: Request, call_next):
        if request.method == "POST":
            src = request.headers.get("origin") or request.headers.get("referer")
            host = request.headers.get("host", "")
            if not src or urlparse(src).netloc != host:
                return Response("Cross-origin POST afvist", status_code=403)
        return await call_next(request)

    def render(request: Request, name: str, **ctx):
        return TEMPLATES.TemplateResponse(request, name, {"cfg": cfg, "scan": state, **ctx})

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

    @app.post("/scan")
    def scan(modules: str = Form("")):
        from ..orchestrator import run_scan

        with state.lock:
            if state.running:
                return RedirectResponse("/", status_code=303)
            state.running, state.log = True, []

        def worker():
            try:
                run_scan(cfg, store, [m for m in modules.split(",") if m] or None, progress=state.log.append)
            except Exception as exc:
                state.log.append(f"FEJL: {exc}")
            finally:
                state.running = False

        threading.Thread(target=worker, daemon=True).start()
        return RedirectResponse("/", status_code=303)

    @app.get("/scan/status")
    def scan_status():
        return JSONResponse({"running": state.running, "log": state.log[-50:]})

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
