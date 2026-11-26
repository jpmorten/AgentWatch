from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field


class DnsSource(BaseModel):
    """Hvor DNS-logs hentes fra. Se docs/dns-logs.md."""

    type: Literal["none", "adguard", "pihole", "dnsmasq_log", "csv"] = "none"
    url: str | None = None  # AdGuard Home / Pi-hole base-URL
    username: str | None = None
    # Hemmeligheder læses fra miljøvariabler, aldrig fra config-filen.
    password_env: str = "AGENTWATCH_DNS_PASSWORD"
    path: str | None = None  # til dnsmasq_log / csv
    hours: int = 24


class CveConfig(BaseModel):
    """CVE-vagt. Se docs/cve-vagt.md."""

    enabled: bool = True  # baggrundstjek mens GUI'en kører
    interval_hours: float = 12
    cache_hours: float = 24  # NVD-svar pr. CPE genbruges så længe
    min_cvss: float = 7.0  # notificér ved nye fund med mindst denne score ...
    alert_on_kev: bool = True  # ... eller som er på CISA's KEV-liste (aktivt udnyttet)
    nvd_api_key_env: str = "NVD_API_KEY"
    ntfy_server: str = "https://ntfy.sh"
    ntfy_topic: str | None = None  # push til telefon via ntfy-appen
    webhook_url: str | None = None  # Discord/Slack/Teams/egen


class Config(BaseModel):
    networks: list[str] = Field(default_factory=lambda: ["192.168.1.0/24"])
    db_path: str = "~/.agentwatch/agentwatch.db"
    nmap_path: str = "nmap"
    # "quick": top 200 porte; "full": top 1000 + OS-detektion (kræver sudo / administrator)
    service_profile: Literal["quick", "full"] = "quick"
    extra_web_ports: list[int] = Field(default_factory=lambda: [8008, 8009, 8443, 8888, 32400, 5000, 5001, 9000])
    http_timeout: float = 5.0
    dns: DnsSource = Field(default_factory=DnsSource)
    analyst_model: str = "claude-opus-5-5"
    cve: CveConfig = Field(default_factory=CveConfig)

    @property
    def db_file(self) -> Path:
        return Path(os.path.expanduser(self.db_path))


def load_config(path: str | os.PathLike | None = None) -> Config:
    candidates = [path] if path else ["agentwatch.yaml", "~/.agentwatch/config.yaml"]
    for c in candidates:
        if c is None:
            continue
        p = Path(os.path.expanduser(str(c)))
        if p.exists():
            return Config.model_validate(yaml.safe_load(p.read_text(encoding="utf-8")) or {})
    if path:
        raise FileNotFoundError(path)
    return Config()
