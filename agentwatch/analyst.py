"""LLM-laget: en Claude-agent der beriger inventaret.

De faste scannere leverer rådata. Analytikeren:
1. finder huller (ukendt enhedstype, manglende versioner/firmware),
2. graver dybere på udvalgte enheder med informationsindsamlende værktøjer
   (begrænset til dine egne netværk og en whitelist af sikre nmap-scripts),
3. klassificerer enheder og retter felter (markeret source="analyst"),
4. skriver en liste over ting du selv skal indtaste i GUI'en (fx firmware
   fra routerens admin-side).

Den laver IKKE sårbarhedsvurdering – det overlades til dit andet agent-setup.
Kræver `pip install agentwatch[agent]` og en Anthropic API-nøgle/login.
"""

from __future__ import annotations

import json

from .config import Config
from .export import summary_json
from .models import Firmware
from .scope import ScopeError, ensure_in_scope
from .store import Store

SYSTEM_PROMPT = """Du er inventar-analytiker i AgentWatch og arbejder på brugerens eget hjemmenetværk, \
som brugeren ejer og har bedt om at få kortlagt. Dit mål er et så komplet og korrekt inventar som \
muligt: hvilke enheder der findes, hvad de er, hvilket OS/firmware og hvilke softwareversioner de \
kører, og hvilke webinterfaces de eksponerer. Et andet system laver selve sårbarhedsvurderingen \
bagefter – du skal ikke vurdere sårbarheder eller forsøge at udnytte noget.

Arbejdsgang:
- Start med list_inventory. Find enheder med huller: ukendt device_type, services uden version, \
manglende firmware/model, webinterfaces uden identificeret produkt.
- Brug deep_scan og http_probe målrettet på de enheder hvor det giver ny information. Undgå at \
gentage scanninger der allerede er gjort.
- Når du er rimelig sikker, så opdatér enheden med update_device. Angiv en kort begrundelse.
- Felter i manual_fields er indtastet af brugeren – de er korrekte og må ikke ændres.
- Slut af med et kort svar på dansk: hvad du har beriget, og en punktliste over oplysninger \
brugeren selv bør indtaste i AgentWatch-GUI'en (fx firmwareversion fra routerens admin-side, \
modelnumre der står på enheden), fordi de ikke kan ses udefra."""


def build_tools(cfg: Config, store: Store):
    from anthropic import beta_tool

    from .scanners import services, web

    @beta_tool
    def list_inventory() -> str:
        """Hent et kompakt overblik over alle kendte enheder i inventaret."""
        return json.dumps(summary_json(store.inventory(cfg.networks)), ensure_ascii=False, default=str)

    @beta_tool
    def get_device(device_id: str) -> str:
        """Hent alle detaljer om én enhed, inkl. UPnP/mDNS-data og manual_fields.

        Args:
            device_id: Enhedens id fra list_inventory, fx 'mac:aa:bb:cc:dd:ee:ff'.
        """
        d = store.get(device_id)
        return d.model_dump_json() if d else f"Ukendt enhed: {device_id}"

    @beta_tool
    def deep_scan(ip: str, ports: str = "", scripts: list[str] | None = None) -> str:
        """Kør en dybere nmap-versionsscanning af én enhed på brugerens netværk.

        Args:
            ip: IP-adresse inden for de konfigurerede netværk.
            ports: Portliste i nmap-format, fx '22,80,443' eller '1-65535'. Tom = top 1000.
            scripts: Valgfri liste af informationsindsamlende NSE-scripts fra whitelisten:
                banner, http-title, http-server-header, http-headers, ssl-cert, ssh-hostkey,
                ssh2-enum-algos, upnp-info, rtsp-methods, smb-os-discovery, smb-protocols,
                ssl-enum-ciphers, http-generator, mqtt-subscribe.
        """
        try:
            ensure_in_scope(ip, cfg.networks)
            hosts = services.scan_services(store, [ip], cfg.networks, "full", cfg.nmap_path,
                                           ports=ports or None, scripts=scripts or None)
        except (ScopeError, ValueError) as exc:
            return f"Afvist: {exc}"
        except Exception as exc:
            return f"Fejl: {type(exc).__name__}: {exc}"
        d = store.find(ip=ip)
        if d:
            web.scan_web(store, cfg.extra_web_ports, cfg.http_timeout, device_ids=[d.id])
        if not hosts:
            return "Ingen svar fra værten."
        h = hosts[0]
        return json.dumps({"os": h.os_name, "os_accuracy": h.os_accuracy, "device_type": h.device_type,
                           "services": [s.model_dump() for s in h.services]}, ensure_ascii=False)

    @beta_tool
    def http_probe(url: str) -> str:
        """Hent en webside på en enhed i netværket og returnér titel, headers-fingerprint og TLS-info.

        Args:
            url: Fuld URL, fx 'http://192.168.1.1:8080/'. Værten skal ligge i de konfigurerede netværk.
        """
        import httpx

        host = httpx.URL(url).host
        try:
            ensure_in_scope(host, cfg.networks)
        except ScopeError as exc:
            return f"Afvist: {exc}"
        app = web.probe(url, cfg.http_timeout)
        return app.model_dump_json() if app else "Intet svar."

    @beta_tool
    def update_device(device_id: str, reason: str, device_type: str = "", os: str = "", model: str = "",
                      vendor: str = "", firmware_version: str = "", firmware_cpe: str = "") -> str:
        """Opdatér felter på en enhed med analytikerens konklusion. Tomme felter ignoreres.

        Args:
            device_id: Enhedens id.
            reason: Kort begrundelse/evidens (gemmes som note).
            device_type: Fx router, access-point, tv, media-player, speaker, phone, computer, nas, printer, camera, iot.
            os: Operativsystem med version hvis kendt.
            model: Producent-model.
            vendor: Producent.
            firmware_version: Firmwareversion.
            firmware_cpe: CPE 2.3-streng for firmware/hardware hvis den kan udledes.
        """
        d = store.get(device_id)
        if not d:
            return f"Ukendt enhed: {device_id}"
        changed = []
        for field, val in [("device_type", device_type), ("os", os), ("model", model), ("vendor", vendor)]:
            if val and field not in d.manual_fields:
                setattr(d, field, val)
                changed.append(field)
        if (firmware_version or firmware_cpe) and "firmware" not in d.manual_fields:
            fw = d.firmware or Firmware(source="analyst")
            fw.version = firmware_version or fw.version
            fw.cpe = firmware_cpe or fw.cpe
            fw.model = fw.model or d.model
            fw.source = "analyst"
            d.firmware = fw
            changed.append("firmware")
        d.analyst_notes.append(f"[analyst] {', '.join(changed) or 'ingen ændringer'}: {reason[:500]}")
        store.save(d)
        store.log_change(d.id, "analyst_update", ", ".join(changed))
        return f"Opdateret: {changed or 'intet (låste felter?)'}"

    return [list_inventory, get_device, deep_scan, http_probe, update_device]


def run_analyst(cfg: Config, store: Store, instruction: str | None = None, max_iterations: int = 40,
                on_text=print) -> str:
    import anthropic

    client = anthropic.Anthropic()
    runner = client.beta.messages.tool_runner(
        model=cfg.analyst_model,
        max_tokens=16000,
        system=SYSTEM_PROMPT,
        thinking={"type": "adaptive"},
        output_config={"effort": "medium"},
        # Hvis en sikkerhedsklassifikator afviser (netværksscanning kan ligne offensive opgaver),
        # prøver API'et automatisk igen på en passende fallback-model.
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        tools=build_tools(cfg, store),
        max_iterations=max_iterations,
        messages=[{"role": "user", "content": instruction or
                   "Gennemgå inventaret, berig det hvor der er huller, og giv mig listen over hvad jeg selv skal indtaste."}],
    )
    final_text = ""
    last = None
    for message in runner:
        last = message
        for block in message.content:
            if block.type == "text" and block.text.strip():
                on_text(block.text)
                final_text = block.text
            elif block.type == "tool_use":
                on_text(f"  → {block.name}({json.dumps(block.input, ensure_ascii=False)[:160]})")
    if last is not None and last.stop_reason == "refusal":
        return "Analysen blev afvist af modellen. Prøv en mere specifik instruktion."
    if last is not None and last.stop_reason == "max_tokens":
        final_text += "\n(afbrudt: max_tokens)"
    return final_text
