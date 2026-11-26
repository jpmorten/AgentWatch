"""Datamodel for inventaret.

Det er denne model, dit vurderings-setup læser (via JSON-eksport, CycloneDX
eller MCP-serveren). Hvert felt har en `source`, så det er tydeligt om data
kommer fra en scanner, fra LLM-analysen eller fra manuel indtastning.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

Source = Literal["nmap", "arp", "mdns", "ssdp", "http", "dns", "analyst", "manual"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Service(BaseModel):
    port: int
    protocol: Literal["tcp", "udp"] = "tcp"
    state: str = "open"
    name: str | None = None  # fx "http", "ssh"
    product: str | None = None  # fx "OpenSSH"
    version: str | None = None  # fx "9.6p1"
    extra_info: str | None = None
    cpe: list[str] = Field(default_factory=list)
    source: Source = "nmap"


class TlsInfo(BaseModel):
    subject: str | None = None
    issuer: str | None = None
    not_after: str | None = None
    self_signed: bool | None = None
    protocol: str | None = None


class WebApp(BaseModel):
    url: str
    status: int | None = None
    title: str | None = None
    server: str | None = None
    powered_by: str | None = None
    technologies: list[str] = Field(default_factory=list)
    auth_required: bool | None = None
    tls: TlsInfo | None = None
    source: Source = "http"


class AppUsage(BaseModel):
    """En app/tjeneste en enhed bruger, udledt af DNS-opslag."""

    app: str  # fx "Netflix"
    category: str  # fx "streaming", "smart-home", "telemetry"
    domains: list[str] = Field(default_factory=list)
    query_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    source: Source = "dns"


class Firmware(BaseModel):
    version: str | None = None
    vendor: str | None = None
    model: str | None = None
    cpe: str | None = None
    source: Source = "manual"


class Device(BaseModel):
    id: str  # stabil nøgle: MAC hvis kendt, ellers IP
    ip: str | None = None
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None  # MAC/OUI-producent
    device_type: str | None = None  # router, tv, phone, nas, iot, printer, ...
    os: str | None = None
    os_cpe: list[str] = Field(default_factory=list)
    model: str | None = None
    firmware: Firmware | None = None
    services: list[Service] = Field(default_factory=list)
    webapps: list[WebApp] = Field(default_factory=list)
    apps: list[AppUsage] = Field(default_factory=list)
    mdns_services: list[str] = Field(default_factory=list)
    upnp: dict[str, str] = Field(default_factory=dict)
    owner: str | None = None
    location: str | None = None
    trusted: bool | None = None
    notes: str | None = None
    tags: list[str] = Field(default_factory=list)
    # Felter brugeren har låst via GUI'en – scannere overskriver dem ikke.
    manual_fields: list[str] = Field(default_factory=list)
    analyst_notes: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    online: bool = True


class ScanRun(BaseModel):
    id: int | None = None
    started: datetime = Field(default_factory=utcnow)
    finished: datetime | None = None
    targets: list[str] = Field(default_factory=list)
    modules: list[str] = Field(default_factory=list)
    devices_found: int = 0
    errors: list[str] = Field(default_factory=list)


class Inventory(BaseModel):
    schema_version: str
    generated: datetime = Field(default_factory=utcnow)
    networks: list[str] = Field(default_factory=list)
    devices: list[Device] = Field(default_factory=list)
    last_run: ScanRun | None = None
    # CVE-fund (åbne + kendte) fra CVE-vagten; se agentwatch/cve.py
    vulnerabilities: list[dict] = Field(default_factory=list)
