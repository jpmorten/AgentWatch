"""CVE-vagt: matcher inventarets software/firmware mod kendte sårbarheder.

Kilder (alle gratis, ingen konto nødvendig):
- NVD CVE API 2.0 (NIST) – CVE'er pr. CPE inkl. versionsintervaller og CVSS
- CISA KEV – sårbarheder der aktivt udnyttes i angreb (højeste prioritet)
- FIRST EPSS – sandsynlighed for udnyttelse inden for 30 dage

Prioritering: KEV først, derefter EPSS og CVSS. Nye fund logges, vises i GUI'en
og kan sendes som push-besked (ntfy) eller webhook (Discord/Slack/andet).

Begrænsninger der er værd at kende:
- Linux-distributioner (Ubuntu/Debian/…) backporter sikkerhedsrettelser uden at
  ændre versionsnummeret. Fund på distro-pakker markeres med lav sikkerhed.
- Kun software med kendt version matches. nmaps OS-gæt (fx "Linux 5.4") bruges
  ikke, da det giver tusindvis af irrelevante fund – indtast OS/firmware-CPE
  manuelt for at få dem med.
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx
from pydantic import BaseModel, Field

from .models import Device, utcnow

log = logging.getLogger("agentwatch")

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
UA = {"User-Agent": "AgentWatch/0.2 (home network inventory; CVE watch)"}

# nmap-CPE -> NVD-CPE hvor navngivningen afviger (vendor:product)
CPE_ALIASES = {
    "matt_johnston:dropbear_ssh_server": "dropbear_ssh_project:dropbear_ssh",
    "openbsd:openssh": "openbsd:openssh",
    "igor_sysoev:nginx": "f5:nginx",
    "nginx:nginx": "f5:nginx",
    "lighttpd:lighttpd": "lighttpd:lighttpd",
    "thekelleys:dnsmasq": "thekelleys:dnsmasq",
    "samba:samba": "samba:samba",
    "miniupnp_project:miniupnpd": "miniupnp_project:miniupnpd",
    "acme:mini_httpd": "acme:mini_httpd",
}
DISTRO_RE = re.compile(r"ubuntu|debian|deb\d|raspbian|el\d|fedora|alpine|suse|\+deb", re.I)


class CveFinding(BaseModel):
    cve_id: str
    device_id: str
    cpe: str
    product: str | None = None
    version: str | None = None
    where: str | None = None  # "22/tcp", "firmware", "os"
    cvss: float | None = None
    severity: str | None = None  # CRITICAL/HIGH/MEDIUM/LOW
    vector: str | None = None
    kev: bool = False
    kev_ransomware: bool = False
    kev_due: str | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    published: str | None = None
    description: str = ""
    references: list[str] = Field(default_factory=list)
    confidence: str = "høj"
    confidence_note: str | None = None
    status: str = "open"  # open | acknowledged | ignored | resolved
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    notified: bool = False

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.device_id, self.cve_id, self.cpe)

    @property
    def priority(self) -> float:
        """Højere = vigtigere. KEV dominerer, derefter EPSS og CVSS."""
        return (100 if self.kev else 0) + (self.epss or 0) * 50 + (self.cvss or 0)


# ---------------------------------------------------------------- CPE-håndtering
@dataclass
class Target:
    device_id: str
    cpe23: str
    product: str | None
    version: str | None
    where: str
    distro: bool = False


def cpe22_to_23(cpe: str, version_hint: str | None = None) -> str | None:
    """'cpe:/a:openbsd:openssh:9.6p1' -> 'cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*'.

    Returnerer None hvis der ikke kan findes en version (for bredt til at matche).
    """
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")
        if len(parts) < 6:
            return None
        if parts[5] in ("*", "-", ""):
            m = re.match(r"[\w.\-]+", (version_hint or "").strip())
            if not m:
                return None
            parts[5] = m.group(0)
        parts += ["*"] * (13 - len(parts))
        return ":".join(parts[:13])
    if not cpe.startswith("cpe:/"):
        return None
    parts = cpe[5:].split(":")
    part, vendor, product = (parts + ["", "", ""])[:3]
    version = parts[3] if len(parts) > 3 else ""
    update = parts[4] if len(parts) > 4 else "*"
    if not version and version_hint:
        m = re.match(r"[\w.\-]+", version_hint.strip())
        version = m.group(0) if m else ""
    if not (part and vendor and product and version):
        return None
    alias = CPE_ALIASES.get(f"{vendor}:{product}")
    if alias:
        vendor, product = alias.split(":")
    fields = [part, vendor, product, version, update or "*", "*", "*", "*", "*", "*", "*"]
    return "cpe:2.3:" + ":".join(f.replace(" ", "_").lower() if i < 3 else f for i, f in enumerate(fields))


def targets_for(dev: Device, include_os_guess: bool = False) -> list[Target]:
    out: list[Target] = []
    for s in dev.services:
        distro = bool(DISTRO_RE.search(" ".join(filter(None, [s.version, s.extra_info]))))
        for c in s.cpe[:2]:
            if c.startswith("cpe:/o:") or c.startswith("cpe:2.3:o:"):
                continue  # OS-CPE fra service-banner – for upræcist
            c23 = cpe22_to_23(c, s.version)
            if c23:
                out.append(Target(dev.id, c23, s.product, s.version, f"{s.port}/{s.protocol}", distro))
                break
    if dev.firmware and dev.firmware.cpe:
        c23 = cpe22_to_23(dev.firmware.cpe, dev.firmware.version)
        if c23:
            out.append(Target(dev.id, c23, dev.firmware.model or dev.model, dev.firmware.version, "firmware"))
    trusted_os = include_os_guess or "os" in dev.manual_fields
    if trusted_os:
        for c in dev.os_cpe[:1]:
            c23 = cpe22_to_23(c)
            if c23:
                out.append(Target(dev.id, c23, dev.os, None, "os"))
    # dedup
    seen, uniq = set(), []
    for t in out:
        if (t.cpe23, t.where) not in seen:
            seen.add((t.cpe23, t.where))
            uniq.append(t)
    return uniq


# ---------------------------------------------------------------- NVD / KEV / EPSS
class NvdClient:
    def __init__(self, api_key: str | None = None, timeout: float = 60.0):
        self.api_key = api_key
        self.delay = 0.8 if api_key else 6.5  # NVD: 50 req/30s med nøgle, 5 req/30s uden
        self._last = 0.0
        headers = dict(UA)
        if api_key:
            headers["apiKey"] = api_key
        self.http = httpx.Client(timeout=timeout, headers=headers)

    def _get(self, url: str, params: dict) -> dict:
        for attempt in range(4):
            wait = self.delay - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            try:
                r = self.http.get(url, params=params)
            except httpx.HTTPError as exc:
                log.warning("  NVD-forespørgsel fejlede (%s) – prøver igen", exc)
                time.sleep(5 * (attempt + 1))
                continue
            if r.status_code in (403, 429, 503):
                log.warning("  NVD svarede %s (rate limit) – venter %ds", r.status_code, 10 * (attempt + 1))
                time.sleep(10 * (attempt + 1))
                continue
            r.raise_for_status()
            return r.json()
        raise RuntimeError("NVD svarer ikke – prøv igen senere (eller sæt NVD_API_KEY for højere grænse)")

    def cves_for_cpe(self, cpe23: str, max_results: int = 2000) -> list[dict]:
        out, start = [], 0
        while True:
            data = self._get(NVD_CVE_URL, {"virtualMatchString": cpe23, "resultsPerPage": 2000,
                                           "startIndex": start, "noRejected": ""})
            out += data.get("vulnerabilities", [])
            start += data.get("resultsPerPage", 0)
            if start >= min(data.get("totalResults", 0), max_results) or not data.get("resultsPerPage"):
                return out

    def suggest_cpe(self, keyword: str, limit: int = 15) -> list[dict]:
        """Søg i NVD's CPE-ordbog. Samler versioner pr. produkt (version '*'), firmware/OS først."""
        data = self._get(NVD_CPE_URL, {"keywordSearch": keyword, "resultsPerPage": 500})
        products: dict[str, dict] = {}
        for p in data.get("products", []):
            c = p.get("cpe", {})
            if c.get("deprecated") or not c.get("cpeName"):
                continue
            parts = c["cpeName"].split(":")
            key = ":".join(parts[2:5])  # part:vendor:product
            title = next((t["title"] for t in c.get("titles", []) if t.get("lang") == "en"), "")
            e = products.setdefault(key, {"cpe": ":".join(parts[:5] + ["*"] * 8), "part": parts[2],
                                          "title": title, "versions": 0})
            e["versions"] += 1
        kind = {"o": "firmware/OS", "a": "software", "h": "hardware"}
        out = sorted(products.values(), key=lambda e: ({"o": 0, "a": 1, "h": 2}.get(e["part"], 3), -e["versions"]))
        for e in out:
            e["title"] = f"[{kind.get(e['part'], e['part'])}] {e['cpe'].split(':')[3]} {e['cpe'].split(':')[4]}" \
                         f" – {e['versions']} versioner i NVD"
        return out[:limit]


def fetch_kev(timeout: float = 60.0) -> dict[str, dict]:
    r = httpx.get(KEV_URL, timeout=timeout, headers=UA)
    r.raise_for_status()
    return {v["cveID"]: v for v in r.json().get("vulnerabilities", [])}


def fetch_epss(cve_ids: list[str], timeout: float = 30.0) -> dict[str, tuple[float, float]]:
    out: dict[str, tuple[float, float]] = {}
    ids = sorted(set(cve_ids))
    for i in range(0, len(ids), 100):
        try:
            r = httpx.get(EPSS_URL, params={"cve": ",".join(ids[i:i + 100])}, timeout=timeout, headers=UA)
            r.raise_for_status()
            for row in r.json().get("data", []):
                out[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            log.warning("  EPSS kunne ikke hentes (%s) – fortsætter uden", exc)
            break
    return out


def parse_nvd_item(item: dict) -> dict:
    cve = item.get("cve", {})
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score = sev = vector = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if not arr:
            continue
        primary = next((m for m in arr if m.get("type") == "Primary"), arr[0])
        d = primary.get("cvssData", {})
        score = d.get("baseScore")
        sev = d.get("baseSeverity") or primary.get("baseSeverity")
        vector = d.get("vectorString")
        break
    refs = [r["url"] for r in cve.get("references", [])][:4]
    return {"cve_id": cve.get("id"), "description": desc[:600], "cvss": score, "severity": sev,
            "vector": vector, "published": (cve.get("published") or "")[:10], "references": refs}


# ---------------------------------------------------------------- hovedløkken
def check_inventory(store, cfg, use_cache: bool = True, include_os_guess: bool = False) -> dict:
    """Matcher alle enheder mod NVD og opdaterer fund i databasen. Returnerer en opsummering."""
    ccfg = cfg.cve
    api_key = os.environ.get(ccfg.nvd_api_key_env) or None
    nvd = NvdClient(api_key)
    devices = store.all()
    targets = [t for d in devices for t in targets_for(d, include_os_guess)]
    uniq_cpes = sorted({t.cpe23 for t in targets})
    log.info("=" * 70)
    log.info("CVE-vagt: %d enheder, %d software/firmware-komponenter med version, %d unikke CPE'er",
             len(devices), len(targets), len(uniq_cpes))
    if not api_key:
        log.info("  Ingen NVD API-nøgle (%s) – NVD tillader 5 forespørgsler/30s, så det tager ca. %d sek. "
                 "Gratis nøgle: https://nvd.nist.gov/developers/request-an-api-key",
                 ccfg.nvd_api_key_env, int(len(uniq_cpes) * 6.5))
    skipped = [(d, s) for d in devices for s in d.services if not s.cpe and (s.product or s.name)]
    if skipped:
        log.info("  %d services uden CPE/version kan ikke matches (fx %s)", len(skipped),
                 ", ".join(f"{d.ip}:{s.port} {s.product or s.name}" for d, s in skipped[:4]))

    by_cpe: dict[str, list[dict]] = {}
    for i, cpe in enumerate(uniq_cpes, 1):
        cached = store.cve_cache_get(cpe, max_age=timedelta(hours=ccfg.cache_hours)) if use_cache else None
        if cached is not None:
            by_cpe[cpe] = cached
            log.info("  [%d/%d] %s – %d CVE'er (cache)", i, len(uniq_cpes), cpe, len(cached))
            continue
        try:
            items = [parse_nvd_item(x) for x in nvd.cves_for_cpe(cpe)]
        except Exception as exc:
            log.error("  [%d/%d] %s – fejl: %s", i, len(uniq_cpes), cpe, exc)
            continue
        store.cve_cache_put(cpe, items)
        by_cpe[cpe] = items
        log.info("  [%d/%d] %s – %d CVE'er", i, len(uniq_cpes), cpe, len(items))

    log.info("  Henter CISA KEV-kataloget (aktivt udnyttede sårbarheder) ...")
    try:
        kev = store.cve_cache_get("__kev__", max_age=timedelta(hours=12)) if use_cache else None
        if kev is None:
            kev = fetch_kev()
            store.cve_cache_put("__kev__", kev)
        log.info("  KEV: %d kendte udnyttede CVE'er", len(kev))
    except Exception as exc:
        log.warning("  KEV kunne ikke hentes: %s", exc)
        kev = {}

    all_ids = sorted({x["cve_id"] for items in by_cpe.values() for x in items})
    log.info("  Henter EPSS-scorer for %d CVE'er ...", len(all_ids))
    epss = fetch_epss(all_ids) if all_ids else {}

    existing = {f.key: f for f in store.cve_findings()}
    current: dict[tuple, CveFinding] = {}
    now = utcnow()
    for t in targets:
        if t.cpe23 not in by_cpe:
            continue  # fejlede – rør ikke ved eksisterende fund
        for x in by_cpe[t.cpe23]:
            k = kev.get(x["cve_id"])
            e = epss.get(x["cve_id"])
            f = CveFinding(
                device_id=t.device_id, cpe=t.cpe23, product=t.product, version=t.version, where=t.where,
                kev=bool(k), kev_ransomware=bool(k and k.get("knownRansomwareCampaignUse") == "Known"),
                kev_due=k.get("dueDate") if k else None,
                epss=e[0] if e else None, epss_percentile=e[1] if e else None, **x,
            )
            if t.distro:
                f.confidence = "lav"
                f.confidence_note = "Distro-pakke – rettelsen kan være backportet uden versionsskift. Tjek distroens sikkerhedsadvarsler."
            old = existing.get(f.key)
            if old:
                f.first_seen, f.notified = old.first_seen, old.notified
                f.status = old.status if old.status != "resolved" else "open"
            f.last_seen = now
            current[f.key] = f

    new = [f for k, f in current.items() if k not in existing or existing[k].status == "resolved"]
    resolved = []
    checked_cpes = set(by_cpe)
    for k, old in existing.items():
        if k not in current and old.status != "resolved":
            dev_targets = {t.cpe23 for t in targets if t.device_id == old.device_id}
            if old.cpe not in dev_targets or old.cpe in checked_cpes:
                old.status = "resolved"
                old.last_seen = now
                current[k] = old
                resolved.append(old)
    store.cve_findings_save(list(current.values()))
    for f in new:
        store.log_change(f.device_id, "new_cve", f"{f.cve_id} CVSS {f.cvss} {'KEV ' if f.kev else ''}{f.product or ''} {f.version or ''}".strip())
    for f in resolved:
        store.log_change(f.device_id, "cve_resolved", f"{f.cve_id} ({f.product} {f.version})")

    open_ = [f for f in current.values() if f.status == "open"]
    summary = {
        "devices": len(devices), "cpes": len(uniq_cpes), "findings_open": len(open_),
        "new": len(new), "resolved": len(resolved),
        "kev": sum(f.kev for f in open_), "critical": sum((f.cvss or 0) >= 9 for f in open_),
        "high": sum(7 <= (f.cvss or 0) < 9 for f in open_),
    }
    names = {d.id: d.hostname or d.model or d.ip for d in devices}
    log.info("")
    log.info("CVE-vagt færdig: %(findings_open)d åbne fund (%(kev)d KEV, %(critical)d kritiske, %(high)d høje), "
             "%(new)d nye, %(resolved)d løst", summary)
    for f in sorted(new, key=lambda f: -f.priority)[:25]:
        lvl = logging.WARNING if f.kev or (f.cvss or 0) >= ccfg.min_cvss else logging.INFO
        log.log(lvl, "  NY: %-16s CVSS %-4s %s%s%s – %s (%s %s)", f.cve_id, f.cvss or "?",
                "KEV! " if f.kev else "", f"EPSS {f.epss:.0%} " if f.epss else "",
                "[lav sikkerhed] " if f.confidence == "lav" else "", names.get(f.device_id), f.product or "", f.version or "")
    log.info("=" * 70)

    to_notify = [f for f in new if f.status == "open" and not f.notified and
                 ((ccfg.alert_on_kev and f.kev) or (f.cvss or 0) >= ccfg.min_cvss)]
    summary["notified"] = 0
    if to_notify and notify(ccfg, to_notify, names):
        for f in to_notify:
            f.notified = True
        store.cve_findings_save(to_notify)
        summary["notified"] = len(to_notify)
    return summary


# ---------------------------------------------------------------- notifikationer
def notify(ccfg, findings: list[CveFinding], names: dict[str, str]) -> bool:
    if not (ccfg.ntfy_topic or ccfg.webhook_url):
        log.info("  (Ingen notifikationskanal sat op – se 'cve:' i config for ntfy/webhook)")
        return False
    findings = sorted(findings, key=lambda f: -f.priority)
    lines = [f"{f.cve_id} CVSS {f.cvss or '?'}{' KEV' if f.kev else ''} – {names.get(f.device_id)}: "
             f"{f.product or ''} {f.version or ''}".strip() for f in findings[:10]]
    if len(findings) > 10:
        lines.append(f"… og {len(findings) - 10} mere")
    title = f"AgentWatch: {len(findings)} nye sårbarheder" + (" (aktivt udnyttet!)" if any(f.kev for f in findings) else "")
    body = "\n".join(lines)
    ok = False
    try:
        if ccfg.ntfy_topic:
            server = ccfg.ntfy_server.rstrip("/")
            r = httpx.post(f"{server}/{ccfg.ntfy_topic}", content=body.encode(), timeout=20,
                           headers={"Title": title.encode("utf-8").decode("latin-1", "ignore"),
                                    "Priority": "high" if any(f.kev for f in findings) else "default",
                                    "Tags": "warning,shield"})
            r.raise_for_status()
            ok = True
            log.info("  Push-besked sendt via ntfy (%s)", ccfg.ntfy_topic)
        if ccfg.webhook_url:
            # 'content' (Discord), 'text' (Slack/Teams/Mattermost) – plus struktureret data til andre
            payload = {"content": f"**{title}**\n{body}", "text": f"*{title}*\n{body}",
                       "title": title, "findings": [f.model_dump(mode="json") for f in findings[:50]]}
            r = httpx.post(ccfg.webhook_url, json=payload, timeout=20)
            r.raise_for_status()
            ok = True
            log.info("  Webhook sendt")
    except httpx.HTTPError as exc:
        log.error("  Notifikation fejlede: %s", exc)
    return ok


def scheduled_command(args: str = "cve check") -> str:
    import shutil
    import sys

    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" {args}'
    exe = shutil.which("agentwatch")
    return f'"{exe}" {args}' if exe else f'"{sys.executable}" -m agentwatch {args}'
