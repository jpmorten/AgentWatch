"""MCP-server: lader dit vurderings-agent-setup spørge direkte ind til inventaret.

Start: `agentwatch mcp` (stdio). Tilføj til fx Claude Code / Claude Desktop:
    {"mcpServers": {"agentwatch": {"command": "agentwatch", "args": ["mcp"]}}}

Serveren er læse-orienteret. Den eneste skrivning er `add_assessment_note`,
så vurderings-agenten kan gemme sine fund på enheden (vises i GUI'en).
"""

from __future__ import annotations

from datetime import timedelta

from .config import Config
from .export import cyclonedx_json, summary_json
from .models import utcnow
from .store import Store


def build_server(cfg: Config, store: Store):
    from mcp.server.mcpserver import MCPServer

    server = MCPServer(
        name="agentwatch",
        instructions=(
            "AgentWatch indeholder et inventar over enheder på brugerens eget netværk: IP/MAC, producent, "
            "OS, firmware, åbne services med versioner og CPE'er, webinterfaces og hvilke apps/tjenester "
            "enhederne bruger (fra DNS-logs). Brug get_summary først, derefter get_device for detaljer. "
            "Felter med source='manual' er indtastet af brugeren og er de mest pålidelige."
        ),
    )

    @server.tool()
    def get_summary() -> dict:
        """Kompakt overblik over alle enheder: services, CPE'er, webapps og app-brug."""
        return summary_json(store.inventory(cfg.networks))

    @server.tool()
    def list_devices(device_type: str | None = None, online_only: bool = False) -> list[dict]:
        """List enheder (id, ip, navn, type, producent, model, firmware). Filtrér evt. på type."""
        out = []
        for d in store.all():
            if online_only and not d.online:
                continue
            if device_type and (d.device_type or "").lower() != device_type.lower():
                continue
            out.append({"id": d.id, "ip": d.ip, "name": d.hostname, "type": d.device_type, "vendor": d.vendor,
                        "model": d.model, "firmware": d.firmware.version if d.firmware else None,
                        "online": d.online, "open_ports": len(d.services)})
        return out

    @server.tool()
    def get_device(device_id: str) -> dict:
        """Alle detaljer om én enhed (id fra list_devices, fx 'mac:aa:bb:..' eller 'ip:192.168.1.5')."""
        d = store.get(device_id) or store.find(ip=device_id)
        if not d:
            return {"error": f"Ukendt enhed: {device_id}"}
        return d.model_dump(mode="json")

    @server.tool()
    def search_software(query: str) -> list[dict]:
        """Find enheder der kører software/CPE/teknologi der matcher query (fx 'openssh', 'cpe:/a:apache')."""
        q = query.lower()
        hits = []
        for d in store.all():
            for s in d.services:
                hay = " ".join(filter(None, [s.name, s.product, s.version, *s.cpe])).lower()
                if q in hay:
                    hits.append({"device_id": d.id, "ip": d.ip, "port": s.port, "product": s.product,
                                 "version": s.version, "cpe": s.cpe})
            for w in d.webapps:
                if q in " ".join([w.url, w.title or "", w.server or "", *w.technologies]).lower():
                    hits.append({"device_id": d.id, "ip": d.ip, "url": w.url, "technologies": w.technologies})
            if d.firmware and q in " ".join(filter(None, [d.firmware.version, d.firmware.model, d.firmware.cpe])).lower():
                hits.append({"device_id": d.id, "ip": d.ip, "firmware": d.firmware.model_dump()})
        return hits

    @server.tool()
    def list_app_usage(category: str | None = None) -> list[dict]:
        """Hvilke apps/tjenester bruges af hvilke enheder (kategorier: streaming, remote-access, telemetry, smart-home, ...)."""
        out = []
        for d in store.all():
            for a in d.apps:
                if category and a.category != category:
                    continue
                out.append({"device_id": d.id, "ip": d.ip, "device": d.hostname or d.model, "app": a.app,
                            "category": a.category, "queries": a.query_count,
                            "last_seen": a.last_seen.isoformat() if a.last_seen else None})
        return out

    @server.tool()
    def get_changes(hours: int = 168) -> list[dict]:
        """Ændringer i inventaret (nye enheder, nye porte, versionsskift, nye apps) inden for X timer."""
        return store.changes(since=utcnow() - timedelta(hours=hours))

    @server.tool()
    def export_cyclonedx() -> dict:
        """Hele inventaret som CycloneDX 1.6 JSON (til CVE-matchning i fx Dependency-Track/Grype)."""
        return cyclonedx_json(store.inventory(cfg.networks))

    @server.tool()
    def add_assessment_note(device_id: str, note: str) -> str:
        """Gem et vurderingsfund/en note på en enhed. Vises i AgentWatch-GUI'en."""
        d = store.get(device_id)
        if not d:
            return f"Ukendt enhed: {device_id}"
        d.analyst_notes.append(f"[assessment {utcnow():%Y-%m-%d}] {note[:2000]}")
        store.save(d)
        return "ok"

    return server


def serve(cfg: Config, store: Store, transport: str = "stdio") -> None:
    build_server(cfg, store).run(transport)  # type: ignore[arg-type]
