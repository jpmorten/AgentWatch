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
