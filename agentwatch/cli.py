"""Kommandolinje: agentwatch init | scan | gui | analyze | mcp | export | devices | changes"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
from pathlib import Path

import typer

from .config import Config, load_config
from .store import Store, dumps

app = typer.Typer(help="AgentWatch – kortlæg dit netværk til sårbarhedsvurdering.", no_args_is_help=True)
ConfigOpt = typer.Option(None, "--config", "-c", help="Sti til agentwatch.yaml")


def _ctx(config: str | None) -> tuple[Config, Store]:
    cfg = load_config(config)
    return cfg, Store(cfg.db_file)


def guess_local_network() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # sender intet – finder blot den lokale IP
        ip = s.getsockname()[0]
    except OSError:
        ip = "192.168.1.10"
    finally:
        s.close()
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


@app.command()
def init(path: Path = typer.Option(Path("~/.agentwatch/config.yaml"), help="Hvor config skal skrives")):
    """Opret en config-fil med dit lokale netværk."""
    p = path.expanduser()
    if p.exists():
        typer.echo(f"{p} findes allerede")
        raise typer.Exit(1)
    p.parent.mkdir(parents=True, exist_ok=True)
    example = Path(__file__).parent / "config_example.yaml"
    text = example.read_text() if example.exists() else "networks:\n  - 192.168.1.0/24\n"
    text = text.replace("192.168.1.0/24", guess_local_network(), 1)
    p.write_text(text)
    typer.echo(f"Skrev {p} – tjek 'networks' og DNS-sektionen.")


@app.command()
def scan(config: str = ConfigOpt,
         modules: str = typer.Option("", help="Komma-liste: discovery,mdns,ssdp,services,web,dns (tom = alle)"),
         profile: str = typer.Option("", help="quick | full (overstyrer config)")):
    """Kør scanner-agenterne."""
    from .orchestrator import run_scan

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    cfg, store = _ctx(config)
    if profile:
        cfg.service_profile = profile  # type: ignore[assignment]
    run = run_scan(cfg, store, [m for m in modules.split(",") if m] or None, progress=typer.echo)
    typer.echo(f"\nFærdig: {run.devices_found} enheder set, {len(store.all())} i inventaret.")
    for e in run.errors:
        typer.secho(f"  fejl: {e}", fg="red")


@app.command()
def gui(config: str = ConfigOpt, host: str = "127.0.0.1", port: int = 8765):
    """Start web-GUI'en (http://127.0.0.1:8765)."""
    import uvicorn

    from .web.app import create_app

    cfg, store = _ctx(config)
    if host not in ("127.0.0.1", "localhost", "::1"):
        typer.secho("Advarsel: GUI'en har ingen login – eksponér den ikke på netværket.", fg="yellow")
    uvicorn.run(create_app(cfg, store), host=host, port=port, log_level="warning")


@app.command()
def analyze(config: str = ConfigOpt, instruction: str = typer.Argument(None, help="Valgfri opgave til analytikeren")):
    """Lad Claude-analytikeren berige inventaret og pege på huller."""
    from .analyst import run_analyst

    cfg, store = _ctx(config)
    result = run_analyst(cfg, store, instruction, on_text=typer.echo)
    typer.echo("\n" + "=" * 60 + "\n" + result)


@app.command()
def mcp(config: str = ConfigOpt, transport: str = typer.Option("stdio", help="stdio | streamable-http")):
    """Start MCP-serveren, så dit vurderings-setup kan læse inventaret."""
    from .mcp_server import serve

    cfg, store = _ctx(config)
    serve(cfg, store, transport)


@app.command()
def export(config: str = ConfigOpt, fmt: str = typer.Option("summary", "--format", "-f",
                                                            help="summary | inventory | cyclonedx"),
           out: Path = typer.Option(None, "--out", "-o", help="Fil (standard: stdout)")):
    """Eksportér inventaret som JSON."""
    from .export import FORMATS

    cfg, store = _ctx(config)
    if fmt not in FORMATS:
        raise typer.BadParameter(f"Ukendt format {fmt}")
    body = dumps(FORMATS[fmt](store.inventory(cfg.networks)))
    if out:
        out.write_text(body)
        typer.echo(f"Skrev {out}")
    else:
        typer.echo(body)


@app.command()
def devices(config: str = ConfigOpt, all: bool = typer.Option(False, "--all", help="Vis også offline")):
    """Vis inventaret som tabel."""
    _, store = _ctx(config)
    for d in store.all():
        if not all and not d.online:
            continue
        ports = ",".join(str(s.port) for s in d.services[:8])
        fw = d.firmware.version if d.firmware and d.firmware.version else "-"
        typer.echo(f"{d.ip or '-':15} {d.mac or '-':17} {(d.device_type or '?'):12} "
                   f"{(d.hostname or d.model or '')[:28]:28} {(d.vendor or '')[:20]:20} fw={fw:10} {ports}")


@app.command()
def changes(config: str = ConfigOpt, limit: int = 50):
    """Vis seneste ændringer (nye enheder, porte, versioner, apps)."""
    _, store = _ctx(config)
    for c in store.changes(limit=limit):
        typer.echo(f"{c['ts'][:19]}  {c['kind']:15} {c['device_id']:26} {c['detail']}")


@app.command("dns-unknown")
def dns_unknown(config: str = ConfigOpt, top: int = 40):
    """Vis de hyppigste DNS-domæner der ikke genkendes – til at udvide app-kataloget."""
    from .scanners.dns_usage import fetch_queries, unknown_domains

    cfg, _ = _ctx(config)
    for dom, n in unknown_domains(fetch_queries(cfg.dns), top=top):
        typer.echo(f"{n:7}  {dom}")


if __name__ == "__main__":
    app()
