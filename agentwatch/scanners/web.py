"""Webapp-agent: find webinterfaces, titler, teknologier, login-krav og TLS-certifikater."""

from __future__ import annotations

import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

import httpx

from ..models import Device, TlsInfo, WebApp
from ..store import Store

WEB_SERVICE_NAMES = ("http", "https", "ssl/http", "http-proxy", "http-alt", "https-alt", "upnp", "rtsp")
TLS_PORTS = {443, 8443, 5001, 9443, 4443, 10443}

# (navn, hvor, regex) – hvor: "header" (alle headers som tekst), "body", "title"
FINGERPRINTS: list[tuple[str, str, str]] = [
    ("nginx", "header", r"server: nginx"),
    ("Apache httpd", "header", r"server: apache"),
    ("lighttpd", "header", r"server: lighttpd"),
    ("Microsoft IIS", "header", r"server: microsoft-iis"),
    ("GoAhead (embedded)", "header", r"server: goahead"),
    ("Boa (embedded)", "header", r"server: boa"),
    ("mini_httpd (embedded)", "header", r"server: mini_httpd"),
    ("uhttpd (OpenWrt)", "header", r"server: uhttpd"),
    ("PHP", "header", r"x-powered-by: php"),
    ("Express (Node.js)", "header", r"x-powered-by: express"),
    ("ASP.NET", "header", r"x-powered-by: asp\.net"),
    ("OpenWrt LuCI", "body", r"luci|openwrt"),
    ("DD-WRT", "body", r"dd-wrt"),
    ("ASUS router", "body", r"asuswrt|asus router"),
    ("Netgear router", "body", r"netgear"),
    ("TP-Link", "body", r"tp-link|tplink"),
    ("Zyxel", "body", r"zyxel"),
    ("Technicolor", "body", r"technicolor"),
    ("Fritz!Box", "body", r"fritz!box|fritz\.box"),
    ("UniFi", "body", r"unifi"),
    ("MikroTik RouterOS", "body", r"routeros|mikrotik"),
    ("Synology DSM", "body", r"synology|diskstation"),
    ("QNAP QTS", "body", r"qnap|qts"),
    ("Home Assistant", "body", r"home assistant|home-assistant"),
    ("Node-RED", "body", r"node-red"),
    ("Pi-hole", "body", r"pi-hole"),
    ("AdGuard Home", "body", r"adguard home"),
    ("Plex Media Server", "body", r"plex"),
    ("Jellyfin", "body", r"jellyfin"),
    ("Emby", "body", r"emby"),
    ("Grafana", "body", r"grafana"),
    ("Portainer", "body", r"portainer"),
    ("Proxmox VE", "body", r"proxmox"),
    ("WordPress", "body", r"wp-content|wordpress"),
    ("Jenkins", "header", r"x-jenkins"),
    ("Hikvision", "body", r"hikvision"),
    ("Dahua", "body", r"dahua"),
    ("Philips Hue bridge", "body", r"philips hue|hue personal wireless"),
    ("Sonos", "body", r"sonos"),
    ("HP printer (EWS)", "body", r"hp embedded web server|hewlett-packard"),
    ("Brother printer", "body", r"brother industries"),
    ("Epson printer", "body", r"epson"),
    ("CUPS", "body", r"cups\.css|common unix printing"),
]

TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
GENERATOR_RE = re.compile(rb'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)


def candidate_urls(dev: Device, extra_ports: list[int]) -> list[str]:
    urls = []
    for s in dev.services:
        if s.protocol != "tcp":
            continue
        name = (s.name or "").lower()
        is_web = any(n in name for n in WEB_SERVICE_NAMES) or s.port in (80, 443) or s.port in extra_ports
        if not is_web or name == "rtsp":
            continue
        tls = "ssl" in name or "https" in name or s.port in TLS_PORTS
        urls.append(f"{'https' if tls else 'http'}://{dev.ip}:{s.port}/")
    return sorted(set(urls))


def fingerprint(headers_text: str, body: str, title: str | None) -> list[str]:
    hay = {"header": headers_text.lower(), "body": body.lower(), "title": (title or "").lower()}
    return sorted({name for name, where, rx in FINGERPRINTS if re.search(rx, hay[where])})


def get_tls_info(host: str, port: int, timeout: float = 4.0) -> TlsInfo | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # vi inventerer – gyldighed vurderes bagefter
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                der = s.getpeercert(binary_form=True)
                proto = s.version()
    except (OSError, ssl.SSLError):
        return None
    if not der:
        return TlsInfo(protocol=proto)
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der)
        subj, iss = cert.subject.rfc4514_string(), cert.issuer.rfc4514_string()
        return TlsInfo(subject=subj, issuer=iss, not_after=cert.not_valid_after_utc.isoformat(),
                       self_signed=subj == iss, protocol=proto)
    except Exception:
        return TlsInfo(protocol=proto)


def probe(url: str, timeout: float = 5.0) -> WebApp | None:
    try:
        with httpx.Client(verify=False, timeout=timeout, follow_redirects=False,
                          headers={"User-Agent": "AgentWatch/0.1 (inventory)"}) as c:
            r = c.get(url)
            # Følg kun redirects på samme vært – aldrig ud af netværket
            for _ in range(3):
                loc = r.headers.get("location")
                if not (r.is_redirect and loc):
                    break
                nxt = r.url.join(loc)
                if nxt.host != r.url.host:
                    break
                r = c.get(nxt)
    except httpx.HTTPError:
        return None
    body = r.content[:200_000]
    m = TITLE_RE.search(body)
    title = re.sub(r"\s+", " ", m.group(1).decode(errors="ignore")).strip()[:200] if m else None
    headers_text = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    techs = fingerprint(headers_text, body.decode(errors="ignore"), title)
    g = GENERATOR_RE.search(body)
    if g:
        techs.append(g.group(1).decode(errors="ignore")[:80])
    auth = r.status_code == 401 or "www-authenticate" in r.headers or bool(
        re.search(rb'type=["\']password["\']', body, re.I))
    app = WebApp(url=url, status=r.status_code, title=title, server=r.headers.get("server"),
                 powered_by=r.headers.get("x-powered-by"), technologies=sorted(set(techs)),
                 auth_required=auth)
    if url.startswith("https://"):
        u = httpx.URL(url)
        app.tls = get_tls_info(u.host, u.port or 443, timeout)
    return app


def scan_web(store: Store, extra_ports: list[int], timeout: float = 5.0, device_ids: list[str] | None = None) -> int:
    devices = [d for d in store.all() if d.ip and d.online and (device_ids is None or d.id in device_ids)]
    jobs = [(d, u) for d in devices for u in candidate_urls(d, extra_ports)]
    results: dict[str, list[WebApp]] = {}
    with ThreadPoolExecutor(max_workers=16) as ex:
        for (d, _), app in zip(jobs, ex.map(lambda j: probe(j[1], timeout), jobs)):
            if app:
                results.setdefault(d.id, []).append(app)
    for d in devices:
        if d.id in results:
            store.set_webapps(store.get(d.id) or d, results[d.id])
    return sum(len(v) for v in results.values())
