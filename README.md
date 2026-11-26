# AgentWatch

Kortlægger dit eget netværk, så et andet agent-setup kan vurdere angrebsvektorer
og sårbarheder. AgentWatch finder **enheder, software (med versioner og CPE),
firmware, webinterfaces og hvilke apps/streamingtjenester der bruges**, og
samler det i ét inventar. Det gør det på tre måder:

| Interface | Til hvem | Hvad |
|---|---|---|
| **Web-GUI** (`agentwatch gui`) | dig | Overblik, start scanninger, **ret og supplér manuelt** (firmware, model, ejer, "kendt enhed"), se ændringer |
| **MCP-server** (`agentwatch mcp`) | dit vurderings-agent-setup | Agenten kan spørge live: `get_summary`, `get_device`, `search_software("openssh")`, `list_app_usage("remote-access")`, `get_changes`, og gemme fund med `add_assessment_note` |
| **Eksport** (`agentwatch export`) | ethvert værktøj | `summary` (kompakt JSON til LLM'er), `inventory` (fuld JSON), `cyclonedx` (CycloneDX 1.6 med CPE'er til Dependency-Track, Grype m.fl.) |

## Arkitektur

```
                ┌──────────────────── Scanner-agenter (deterministiske) ────────────────────┐
  dit netværk → │ discovery   mdns   ssdp/upnp   services(nmap -sV)   web   dns(app-brug)   │
                └───────────────────────────────────┬───────────────────────────────────────┘
                                                    ▼
          manuel indtastning (GUI) ──────►  SQLite-inventar + ændringslog  ◄──── Claude-analytiker
                                                    │                         (beriger, graver dybere,
                                    ┌───────────────┼───────────────┐          peger på huller)
                                    ▼               ▼               ▼
                                 Web-GUI        MCP-server       JSON / CycloneDX
                                                    │
                                                    ▼
                                      dit vurderings-agent-setup
```

| Agent | Finder | Kilde |
|---|---|---|
| `discovery` | IP, MAC, producent, hostname | nmap ping-sweep + macOS ARP-tabel |
| `mdns` | Chromecast, AirPlay, HomeKit, printere, Sonos … inkl. model/firmware fra TXT-records | Bonjour/zeroconf |
| `ssdp` | Routere, tv'er, NAS: producent, model, firmware | UPnP device description |
| `services` | Åbne porte, produkt + version + CPE, OS-gæt | `nmap -sV` (`-O` med sudo) |
| `web` | Webinterfaces: titel, server, teknologi (≈40 fingerprints), login-krav, TLS-certifikat | HTTP(S)-probe |
| `dns` | Apps pr. enhed: streaming, remote-access, telemetri, smart-home, gaming … | AdGuard Home / Pi-hole / dnsmasq / CSV |
| `analyze` (LLM) | Udfylder huller, klassificerer enheder, laver målrettede dybere scanninger, laver en liste over hvad *du* skal indtaste | Claude (`claude-opus-5-5`) via Anthropic API |

**Sikkerhedsrammer:** Kun private netværk fra din config må scannes (og
mindst /16). LLM-analytikeren er bundet af de samme rammer og kan kun bruge
en whitelist af informationsindsamlende nmap-scripts (ingen brute force,
ingen exploits). GUI'en lytter kun på 127.0.0.1 og afviser POST-requests fra
andre sider (CSRF).

## CVE-vagt

AgentWatch matcher løbende software og firmware mod **NVD**, **CISA KEV** (aktivt udnyttede
sårbarheder) og **EPSS** (sandsynlighed for udnyttelse). Nye fund vises i GUI'en (fanen *CVE-vagt*),
logges, og kan sendes som push-besked (ntfy) eller webhook. Kør `agentwatch cve check`, eller sæt en
daglig kørsel op med `agentwatch cve schedule --apply`. Se [docs/cve-vagt.md](docs/cve-vagt.md).

## Installation (macOS)

```bash
brew install nmap python@3.12
git clone https://github.com/jpmorten/AgentWatch.git && cd AgentWatch
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[all]"
agentwatch init            # skriver ~/.agentwatch/config.yaml med dit /24-netværk
```

## Installation (Windows)

**Mulighed 1: færdig AgentWatch.exe (nemmest)**
1. Installer nmap med Npcap: `winget install Insecure.Nmap` (eller hent installeren fra nmap.org).
2. Hent `AgentWatch-windows` under *Actions* → seneste grønne *CI*-kørsel → *Artifacts* og pak den ud.
3. Dobbeltklik `AgentWatch.exe`. Første gang laves config med dit netværk, og GUI'en åbner i browseren.
   Til den fulde scanning (OS-detektion, UDP): højreklik → *Kør som administrator*.

**Mulighed 2: installer fra kildekoden**
```powershell
git clone https://github.com/jpmorten/AgentWatch.git; cd AgentWatch
.\windows\install.bat        # eller: powershell -ExecutionPolicy Bypass -File windows\install.ps1
```
Scriptet installerer Python og nmap via winget, hvis de mangler, laver et virtuelt miljø i
`%LOCALAPPDATA%\AgentWatch` og lægger to genveje på skrivebordet: *AgentWatch* og
*AgentWatch (administrator)*.

Windows-noter:
- Tillad Python/AgentWatch på *Private netværk*, når Windows Firewall spørger. Ellers virker mDNS/SSDP-discovery ikke.
- Uden administrator kører nmap i `--unprivileged`-mode (TCP connect, ingen OS-detektion). GUI'en viser det.
- SmartScreen advarer, fordi exe-filen ikke er kodesigneret: *Flere oplysninger* → *Kør alligevel*.
- AdGuard Home til DNS-logs kører også direkte på Windows (se [docs/dns-logs.md](docs/dns-logs.md)).

## Konfiguration

Ret `~/.agentwatch/config.yaml` (Windows: `%USERPROFILE%\.agentwatch\config.yaml`), især `networks` og `dns` (se
[docs/dns-logs.md](docs/dns-logs.md)).

## Brug

```bash
agentwatch scan                        # alle agenter, quick-profil (uden sudo)
sudo -E .venv/bin/agentwatch scan --profile full   # + OS-detektion, TCP 1-10000, UDP – mere præcist, langsommere
agentwatch gui                         # http://127.0.0.1:8765
agentwatch devices                     # tabel i terminalen
agentwatch changes                     # nye enheder, porte, versioner, apps
agentwatch export -f cyclonedx -o inventory.cdx.json
agentwatch analyze                     # Claude beriger inventaret
agentwatch analyze "Find ud af hvad 192.168.1.37 er"
```

`sudo` giver ARP-baseret discovery, OS-detektion og UDP-scanning. Kør
`sudo -E` så din config og DB i `~/.agentwatch` bruges. Første gang spørger
macOS evt. om netværkstilladelse til Python (mDNS/SSDP).

### LLM-analytikeren

`agentwatch analyze` bruger Anthropic API'et (Messages API + SDK'ets tool
runner). Værktøjerne kører lokalt på din Mac, fordi scanningerne skal ske
inde i dit netværk. Kræver `ANTHROPIC_API_KEY` (eller `ant auth login`).
Inventardata (IP'er, hostnames, softwareversioner) sendes til API'et. Lad
være med at køre `analyze`, hvis det ikke er i orden for dig.

Analytikeren bruger `fallbacks: "default"`. Hvis en sikkerhedsklassifikator
afviser en anmodning (netværksscanning kan ligne en offensiv opgave), kører
API'et den automatisk igen på en passende fallback-model.

### Koble på dit vurderings-setup

**MCP** (Claude Code, Claude Desktop eller andre MCP-klienter):

```json
{"mcpServers": {"agentwatch": {"command": "/sti/til/AgentWatch/.venv/bin/agentwatch", "args": ["mcp"]}}}
```

**Fil-baseret:** `agentwatch export -f summary` til LLM-agenter,
`-f cyclonedx` til CVE-matchning:

```bash
agentwatch export -f cyclonedx -o inv.cdx.json && grype sbom:inv.cdx.json
```

### Manuel indtastning – hvornår?

Nogle ting kan ikke ses udefra. Indtast dem i GUI'en, så låses felterne
(🔒) og scannerne overskriver dem ikke:

- **Firmwareversion** på routeren, access points, kameraer og tv'er (står på admin-siden eller i indstillingsmenuen)
- **Model** når producenten kun står som MAC-producent (fx "Espressif" = ukendt IoT-chip)
- **Kendt/ukendt enhed** (`trusted`), ejer og placering
- Enheder der ikke er på netværket hele tiden (bil, gæsteenheder)

`agentwatch analyze` slutter altid med en liste over præcis hvad der mangler.

### Udvid app-kataloget

```bash
agentwatch dns-unknown     # top-domæner der ikke genkendes
```

Tilføj selv apps i `agentwatch/apps_catalog.py` (eller send en PR).

## Udvikling

```bash
pip install -e ".[all]"
pytest
```
