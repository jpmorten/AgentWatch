"""Kommandolinje: agentwatch init | scan | gui | analyze | mcp | export | devices | changes"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import sys
from pathlib import Path

import typer

from .config import Config, load_config
from .store import Store, dumps

if sys.platform == "win32":
    # Windows-konsollen bruger ellers en gammel tegntabel (æøå, pile m.m.)
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:
            pass

app = typer.Typer(help="AgentWatch – kortlæg dit netværk til sårbarhedsvurdering.", no_args_is_help=True)
@app.callback()
def _global(verbose: bool = typer.Option(False, "--verbose", "-v",
                                          help="Vis alt, inkl. nmap-kommandoer og rå nmap-output")):
    from .logsetup import LOG_FILE, setup_logging

    setup_logging(verbose=verbose)
    logging.getLogger("agentwatch").debug("Logfil: %s", LOG_FILE)


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
    text = example.read_text(encoding="utf-8") if example.exists() else "networks:\n  - 192.168.1.0/24\n"
    text = text.replace("192.168.1.0/24", guess_local_network(), 1)
    p.write_text(text, encoding="utf-8")
    typer.echo(f"Skrev {p} – tjek 'networks' og DNS-sektionen.")


@app.command()
def scan(config: str = ConfigOpt,
         modules: str = typer.Option("", help="Komma-liste: discovery,mdns,ssdp,services,web,dns (tom = alle)"),
         profile: str = typer.Option("", help="quick | full (overstyrer config)")):
    """Kør scanner-agenterne."""
    from .orchestrator import run_scan

    from .logsetup import LOG_FILE

    cfg, store = _ctx(config)
    if profile:
        cfg.service_profile = profile  # type: ignore[assignment]
    run = run_scan(cfg, store, [m for m in modules.split(",") if m] or None)
    for e in run.errors:
        typer.secho(f"  fejl: {e}", fg="red")
    typer.echo(f"Fuld log: {LOG_FILE}   ·   kør med -v for endnu mere detaljer")


@app.command()
def gui(config: str = ConfigOpt, host: str = "127.0.0.1", port: int = 8765,
        open_browser: bool = typer.Option(False, "--open", help="Åbn browseren automatisk")):
    """Start web-GUI'en (http://127.0.0.1:8765)."""
    import uvicorn

    from .web.app import create_app

    from .logsetup import LOG_FILE

    cfg, store = _ctx(config)
    log = logging.getLogger("agentwatch")
    log.info("AgentWatch GUI kører på http://%s:%s/  (luk vinduet eller tryk Ctrl+C for at stoppe)", host, port)
    log.info("Config: netværk %s · database %s · log %s", ", ".join(cfg.networks), cfg.db_file, LOG_FILE)
    if host not in ("127.0.0.1", "localhost", "::1"):
        typer.secho("Advarsel: GUI'en har ingen login – eksponér den ikke på netværket.", fg="yellow")
    if open_browser:
        import threading
        import webbrowser

        threading.Timer(1.5, lambda: webbrowser.open(f"http://{host}:{port}/")).start()
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
        out.write_text(body, encoding="utf-8")
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


cve_app = typer.Typer(help="CVE-vagt: match inventaret mod NVD, CISA KEV og EPSS.", no_args_is_help=True)
app.add_typer(cve_app, name="cve")


@cve_app.command("check")
def cve_check(config: str = ConfigOpt,
              scan_first: bool = typer.Option(False, "--scan", help="Kør en scanning først"),
              no_cache: bool = typer.Option(False, "--no-cache", help="Hent alt fra NVD igen"),
              os_guess: bool = typer.Option(False, "--include-os-guess",
                                            help="Medtag nmaps OS-gæt (giver mange falske positiver)")):
    """Tjek alle enheder for kendte sårbarheder og notificér om nye."""
    from .cve import check_inventory

    cfg, store = _ctx(config)
    if scan_first:
        from .orchestrator import run_scan

        run_scan(cfg, store)
    res = check_inventory(store, cfg, use_cache=not no_cache, include_os_guess=os_guess)
    if res["kev"]:
        raise typer.Exit(2)  # nyttigt i scripts: 2 = aktivt udnyttede sårbarheder fundet


@cve_app.command("list")
def cve_list(config: str = ConfigOpt, min_cvss: float = 0.0, kev: bool = typer.Option(False, "--kev"),
             all_status: bool = typer.Option(False, "--all", help="Medtag løste/ignorerede")):
    """Vis fund, vigtigste først."""
    _, store = _ctx(config)
    names = {d.id: d.hostname or d.model or d.ip for d in store.all()}
    for f in store.cve_findings():
        if (not all_status and f.status != "open") or (f.cvss or 0) < min_cvss or (kev and not f.kev):
            continue
        typer.echo(f"{f.cve_id:17} CVSS {str(f.cvss or '?'):4} {'KEV ' if f.kev else '    '}"
                   f"EPSS {f'{f.epss:.0%}' if f.epss is not None else '?':>4}  {f.status:12} "
                   f"{(names.get(f.device_id) or '')[:20]:20} {f.product or ''} {f.version or ''} "
                   f"{'(lav sikkerhed)' if f.confidence == 'lav' else ''}")


@cve_app.command("set")
def cve_set(device_id: str, cve_id: str, status: str = typer.Argument(..., help="open | acknowledged | ignored"),
            config: str = ConfigOpt):
    """Markér et fund som kendt/ignoreret/åbent."""
    _, store = _ctx(config)
    if status not in ("open", "acknowledged", "ignored"):
        raise typer.BadParameter("status skal være open, acknowledged eller ignored")
    typer.echo(f"{store.cve_set_status(device_id, cve_id, status)} fund opdateret")


@cve_app.command("schedule")
def cve_schedule(time_of_day: str = typer.Option("07:40", "--time", help="Klokkeslæt (HH:MM)"),
                 scan: bool = typer.Option(True, help="Scan netværket før CVE-tjekket"),
                 apply: bool = typer.Option(False, "--apply", help="Opret opgaven (ellers vises kun kommandoen)")):
    """Kør CVE-vagten dagligt via Windows Opgavestyring / launchd / cron."""
    import subprocess

    from .cve import scheduled_command

    cmd = scheduled_command("cve check" + (" --scan" if scan else ""))
    if sys.platform == "win32":
        args = ["schtasks", "/Create", "/F", "/SC", "DAILY", "/ST", time_of_day, "/TN", "AgentWatch CVE-vagt",
                "/TR", cmd]
        typer.echo("Windows Opgavestyring:\n  " + subprocess.list2cmdline(args))
        typer.echo("Tip: kør i en administrator-PowerShell og tilføj /RL HIGHEST for fuld scanning med OS-detektion.")
        if apply:
            r = subprocess.run(args, capture_output=True, text=True, errors="replace")
            typer.echo(r.stdout or r.stderr)
    else:
        hh, mm = time_of_day.split(":")
        line = f"{int(mm)} {int(hh)} * * * {cmd} >> ~/.agentwatch/cve-cron.log 2>&1"
        typer.echo("Tilføj denne linje med `crontab -e` (macOS/Linux):\n  " + line)
        if apply:
            cur = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
            if line not in cur:
                subprocess.run(["crontab", "-"], input=cur + line + "\n", text=True, check=True)
                typer.echo("Tilføjet til crontab.")


@cve_app.command("cpe")
def cve_cpe(query: str = typer.Argument(..., help="Fx 'asus rt-ax88u' eller 'synology dsm 7.2'")):
    """Find den rigtige CPE til manuel firmware-indtastning (søger i NVD's CPE-ordbog)."""
    import os

    from .config import CveConfig
    from .cve import NvdClient

    for r in NvdClient(os.environ.get(CveConfig().nvd_api_key_env)).suggest_cpe(query):
        typer.echo(f"{r['cpe']}\n    {r['title']}")


def main() -> None:
    """Indgang for `python -m agentwatch` og AgentWatch.exe.

    Uden argumenter (fx dobbeltklik på AgentWatch.exe) oprettes config ved første
    start, og GUI'en åbnes i browseren.
    """
    if len(sys.argv) == 1:
        cfg_path = Path("~/.agentwatch/config.yaml").expanduser()
        if not cfg_path.exists():
            try:
                init(cfg_path)
            except typer.Exit:
                pass
        sys.argv += ["gui", "--open"]
    app()


if __name__ == "__main__":
    main()
