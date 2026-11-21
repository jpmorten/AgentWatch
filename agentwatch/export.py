"""Eksport til dit vurderings-setup.

- `inventory`: AgentWatch' eget JSON-format (fuld detalje, inkl. app-brug og noter)
- `cyclonedx`: CycloneDX 1.6 – standard-SBOM/HBOM-format med CPE'er, som kan
  læses af fx Dependency-Track og Grype til CVE-matchning
- `summary`: kompakt JSON optimeret til at give en LLM-agent overblik
"""

from __future__ import annotations

import uuid

from . import SCHEMA_VERSION, __version__
from .models import Device, Inventory, utcnow


def inventory_json(inv: Inventory) -> dict:
    return inv.model_dump(mode="json")


def summary_json(inv: Inventory) -> dict:
    devices = []
    for d in inv.devices:
        devices.append({
            "id": d.id, "ip": d.ip, "name": d.hostname, "vendor": d.vendor, "type": d.device_type,
            "model": d.model, "os": d.os, "firmware": d.firmware.version if d.firmware else None,
            "online": d.online, "trusted": d.trusted,
            "services": [
                f"{s.port}/{s.protocol} {s.name or ''} {s.product or ''} {s.version or ''}".strip()
                for s in d.services
            ],
            "cpe": sorted({c for s in d.services for c in s.cpe} | set(d.os_cpe)
                          | ({d.firmware.cpe} if d.firmware and d.firmware.cpe else set())),
            "web": [" ".join(filter(None, [w.url, f"[{w.status}]", w.title, w.server, ",".join(w.technologies),
                                           "(login)" if w.auth_required else None]))
                    for w in d.webapps],
            "apps": [f"{a.app} ({a.category}, {a.query_count} opslag)" for a in d.apps[:15]],
        })
    return {"schema_version": SCHEMA_VERSION, "generated": inv.generated.isoformat(),
            "networks": inv.networks, "device_count": len(devices), "devices": devices}


def _props(**kv) -> list[dict]:
    return [{"name": f"agentwatch:{k}", "value": str(v)} for k, v in kv.items() if v not in (None, "", [])]


def _device_component(d: Device) -> dict:
    children = []
    if d.os:
        children.append({
            "type": "operating-system", "bom-ref": f"{d.id}/os", "name": d.os,
            **({"cpe": d.os_cpe[0]} if d.os_cpe else {}),
        })
    if d.firmware and (d.firmware.version or d.firmware.cpe):
        children.append({
            "type": "firmware", "bom-ref": f"{d.id}/firmware",
            "name": d.firmware.model or d.model or "firmware",
            "version": d.firmware.version or "",
            **({"supplier": {"name": d.firmware.vendor}} if d.firmware.vendor else {}),
            **({"cpe": d.firmware.cpe} if d.firmware.cpe else {}),
            "properties": _props(source=d.firmware.source),
        })
    for s in d.services:
        children.append({
            "type": "application", "bom-ref": f"{d.id}/svc/{s.protocol}/{s.port}",
            "name": s.product or s.name or f"port-{s.port}", "version": s.version or "",
            **({"cpe": s.cpe[0]} if s.cpe else {}),
            "properties": _props(port=s.port, protocol=s.protocol, service=s.name, extra=s.extra_info,
                                 source=s.source, all_cpe=",".join(s.cpe[1:]) or None),
        })
    for w in d.webapps:
        children.append({
            "type": "application", "bom-ref": f"{d.id}/web/{w.url}", "name": w.title or w.url,
            "properties": _props(url=w.url, status=w.status, server=w.server, powered_by=w.powered_by,
                                 technologies=",".join(w.technologies), auth_required=w.auth_required,
                                 tls_issuer=w.tls.issuer if w.tls else None,
                                 tls_self_signed=w.tls.self_signed if w.tls else None,
                                 tls_not_after=w.tls.not_after if w.tls else None),
        })
    return {
        "type": "device", "bom-ref": d.id,
        "name": d.hostname or d.model or d.ip or d.id,
        **({"manufacturer": {"name": d.vendor}} if d.vendor else {}),
        **({"version": d.firmware.version} if d.firmware and d.firmware.version else {}),
        "properties": _props(ip=d.ip, mac=d.mac, device_type=d.device_type, model=d.model,
                             online=d.online, trusted=d.trusted, owner=d.owner, location=d.location,
                             apps=",".join(f"{a.app}:{a.category}" for a in d.apps),
                             mdns=",".join(d.mdns_services)),
        "components": children,
    }


def cyclonedx_json(inv: Inventory) -> dict:
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": utcnow().isoformat(),
            "tools": {"components": [{"type": "application", "name": "AgentWatch", "version": __version__}]},
            "properties": _props(networks=",".join(inv.networks)),
        },
        "components": [_device_component(d) for d in inv.devices],
    }


FORMATS = {"inventory": inventory_json, "cyclonedx": cyclonedx_json, "summary": summary_json}
