# DNS-logs: sådan ser AgentWatch hvilke apps og streamingtjenester der bruges

En aktiv scanning kan se *hvad* en enhed er, men ikke *hvad den bruger*. Det
kræver DNS-opslag: når Stue-TV'et slår `nflxvideo.net` op, ved vi at Netflix
bruges. Når en PC slår `teamviewer.com` op, er der fjernadgangssoftware på
netværket.

AgentWatch kan læse fra fire kilder. Vælg én af dem.

## Mulighed A – AdGuard Home (anbefalet)

AdGuard Home er en lokal DNS-server med indbygget query-log og et API, som
AgentWatch læser direkte. Den kan køre:

- **på en Raspberry Pi** eller en anden enhed der altid er tændt (bedst), eller
- **på din Mac**. Det virker, men hvis Mac'en sover eller er væk hjemmefra,
  mister hele netværket DNS (se faldgruber nedenfor).

### Installation på macOS

```bash
# Officielt installationsscript (understøtter macOS)
curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
# eller med Docker:
docker run -d --name adguard -p 53:53/udp -p 53:53/tcp -p 3000:3000 adguard/adguardhome
```

Åbn `http://127.0.0.1:3000`, lav en admin-bruger og sæt upstream-DNS (fx
`https://dns.quad9.net/dns-query`).

### Få netværket til at bruge AdGuard

1. Giv Mac'en/Pi'en en **fast IP** (DHCP-reservation i routeren).
2. Find routerens **DHCP-indstillinger** og sæt *DNS-server* til AdGuard-IP'en.
   - **Vigtigt:** DHCP skal udlevere AdGuards IP *direkte* til klienterne. Hvis
     routeren i stedet bruger sig selv som DNS og videresender til AdGuard,
     kommer alle opslag til at se ud som om de kommer fra routeren, og så kan
     AgentWatch ikke se hvilken enhed der bruger hvad.
3. Forny DHCP-lease på enhederne (eller vent et døgn / genstart dem).

### AgentWatch-config

```yaml
dns:
  type: adguard
  url: http://127.0.0.1:3000      # eller Pi'ens IP
  username: admin
  password_env: AGENTWATCH_DNS_PASSWORD
  hours: 24
```

```bash
export AGENTWATCH_DNS_PASSWORD='din-adguard-adgangskode'
agentwatch scan --modules dns
agentwatch dns-unknown          # hyppige domæner som kataloget ikke kender
```

## Mulighed B – Pi-hole v6

Samme princip som AdGuard. Kører ikke direkte på macOS (kun via Docker).

```yaml
dns:
  type: pihole
  url: http://192.168.1.2
  password_env: AGENTWATCH_DNS_PASSWORD
```

## Mulighed C – routerens egen log (dnsmasq)

Mange routere bruger dnsmasq internt. Kan routeren logge forespørgsler og
sende syslog til din Mac, kan AgentWatch læse filen direkte.

| Router | Hvordan |
|---|---|
| **OpenWrt** | `uci set dhcp.@dnsmasq[0].logqueries=1 && uci commit && /etc/init.d/dnsmasq restart`, send syslog til Mac'en (System → Logging → External system log server) |
| **Asus med Asuswrt-Merlin** | Tilføj `log-queries` i `/jffs/configs/dnsmasq.conf.add`, slå JFFS-scripts til |
| **UniFi** | Har ikke en per-opslag-log, men har *Traffic Identification* (DPI). Brug AdGuard i stedet, eller eksportér til CSV |
| **Fritz!Box** | Ingen DNS-log. Brug AdGuard Home og sæt den som "lokal DNS-server" under Netværk → IPv4 |
| **ISP-router (YouSee, Telia, Norlys, Hiper …)** | Har typisk ingen DNS-log og låste DHCP-indstillinger. Så er AdGuard Home + routerens "DNS-server"-felt vejen frem. Kan feltet ikke ændres, så slå DHCP fra i routeren og lad AdGuard Home være DHCP-server (den har en indbygget) |

```yaml
dns:
  type: dnsmasq_log
  path: ~/Library/Logs/router-dnsmasq.log
```

## Mulighed D – CSV

Har du en anden kilde, så lav en CSV med kolonnerne `client_ip,domain,timestamp`
(ISO-8601):

```yaml
dns:
  type: csv
  path: ~/dns-export.csv
```

## Faldgruber (vigtige for vurderingen)

- **Hardcodet DNS**: Chromecast, nogle smart-tv'er og IoT-enheder ignorerer
  DHCP og bruger fx `8.8.8.8` direkte. Deres opslag ses ikke, medmindre
  routeren kan omdirigere udgående port 53 (NAT-redirect) til AdGuard.
  At en enhed omgår din DNS er i sig selv et relevant fund.
- **DNS-over-HTTPS (DoH)**: Browsere og iOS/macOS (iCloud Private Relay) kan
  kryptere DNS uden om AdGuard. AdGuard Home blokerer som standard Firefox'
  "canary"-domæne, så Firefox falder tilbage til almindelig DNS. Andre
  DoH-klienter kan blokeres med AdGuards DoH-blokliste.
- **Mac'en som DNS-server**: Sover Mac'en, virker internettet ikke for de
  andre. Brug en Raspberry Pi (eller sæt en sekundær DNS i DHCP, men så går en
  del af opslagene uden om loggen).
- **Privatliv**: DNS-loggen viser hvad alle i husstanden bruger. Sæt en kort
  `hours`-periode og en kort log-opbevaring i AdGuard, og fortæl husstanden
  at loggen findes.
