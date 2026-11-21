"""Domæne -> app/tjeneste. Bruges til at udlede app-brug fra DNS-logs.

Kategorierne er valgt efter relevans for angrebsflade:
- remote-access: fjernadgang ind i netværket (høj relevans)
- telemetry/ads: enheder der ringer hjem (privatliv, supply-chain)
- smart-home/iot: cloud-afhængige IoT-enheder
- streaming, gaming, communication, cloud-storage, social
Udvid gerne listen i din egen `apps_extra.yaml` (se README).
"""

from __future__ import annotations

from pathlib import Path

import yaml

CATALOG: dict[str, tuple[str, list[str]]] = {
    # --- streaming ---
    "Netflix": ("streaming", ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"]),
    "YouTube": ("streaming", ["youtube.com", "googlevideo.com", "ytimg.com", "youtubei.googleapis.com"]),
    "Disney+": ("streaming", ["disneyplus.com", "bamgrid.com", "dssott.com", "disney-plus.net"]),
    "Max (HBO)": ("streaming", ["max.com", "hbomax.com", "hbo.com", "hbomaxcdn.com"]),
    "Viaplay": ("streaming", ["viaplay.com", "viaplay.dk", "viaplay.tv"]),
    "TV 2 Play": ("streaming", ["play.tv2.dk", "tv2a.dk"]),
    "DR TV": ("streaming", ["dr-massive.com", "drm.dr.dk"]),
    "SkyShowtime": ("streaming", ["skyshowtime.com"]),
    "Amazon Prime Video": ("streaming", ["primevideo.com", "aiv-cdn.net", "aiv-delivery.net"]),
    "Apple TV+ / Apple Music": ("streaming", ["tv.apple.com", "music.apple.com", "itunes.apple.com", "aaplimg.com"]),
    "Spotify": ("streaming", ["spotify.com", "scdn.co", "spotifycdn.com", "spotify.map.fastly.net"]),
    "Twitch": ("streaming", ["twitch.tv", "ttvnw.net", "jtvnw.net"]),
    "Plex": ("streaming", ["plex.tv", "plex.direct", "plexapp.com"]),
    "Podimo": ("streaming", ["podimo.com"]),
    # --- social ---
    "TikTok": ("social", ["tiktok.com", "tiktokv.com", "tiktokcdn.com", "byteoversea.com", "ttwstatic.com"]),
    "Instagram": ("social", ["instagram.com", "cdninstagram.com"]),
    "Facebook": ("social", ["facebook.com", "fbcdn.net", "facebook.net"]),
    "Snapchat": ("social", ["snapchat.com", "sc-cdn.net", "snapkit.com"]),
    # --- communication ---
    "WhatsApp": ("communication", ["whatsapp.net", "whatsapp.com"]),
    "Zoom": ("communication", ["zoom.us", "zoom.com"]),
    "Microsoft Teams": ("communication", ["teams.microsoft.com", "teams.live.com", "skype.com"]),
    "Discord": ("communication", ["discord.com", "discord.gg", "discordapp.com", "discordapp.net"]),
    # --- remote access (høj relevans for angrebsflade) ---
    "TeamViewer": ("remote-access", ["teamviewer.com"]),
    "AnyDesk": ("remote-access", ["anydesk.com", "net.anydesk.com"]),
    "Tailscale": ("remote-access", ["tailscale.com", "tailscale.io"]),
    "ZeroTier": ("remote-access", ["zerotier.com"]),
    "Chrome Remote Desktop": ("remote-access", ["remotedesktop.google.com"]),
    "ngrok": ("remote-access", ["ngrok.io", "ngrok.com", "ngrok-free.app"]),
    "Cloudflare Tunnel": ("remote-access", ["argotunnel.com", "cftunnel.com"]),
    "Synology QuickConnect": ("remote-access", ["quickconnect.to", "synology.me"]),
    "Dynamic DNS (No-IP/DuckDNS)": ("remote-access", ["no-ip.com", "ddns.net", "duckdns.org", "dyndns.org"]),
    # --- smart home / iot ---
    "Google Home / Nest": ("smart-home", ["nest.com", "home.nest.com", "googlehomefoyer-pa.googleapis.com"]),
    "Amazon Alexa": ("smart-home", ["avs-alexa-eu.amazon.com", "alexa.amazon.com", "device-metrics-us.amazon.com"]),
    "Philips Hue": ("smart-home", ["meethue.com"]),
    "Sonos": ("smart-home", ["sonos.com", "ws.sonos.com"]),
    "Ring": ("smart-home", ["ring.com", "ring.devices.a2z.com"]),
    "Tuya / Smart Life": ("smart-home", ["tuyaeu.com", "tuyaus.com", "tuyacn.com", "iot.tuya.com"]),
    "Xiaomi / Mi Home": ("smart-home", ["xiaomi.com", "mi.com", "miot-spec.org", "io.mi.com"]),
    "Samsung SmartThings": ("smart-home", ["smartthings.com"]),
    "IKEA Dirigera": ("smart-home", ["dirigera.ikea.com", "ikea.net"]),
    "Shelly": ("smart-home", ["shelly.cloud"]),
    "Home Assistant Cloud": ("smart-home", ["nabucasa.com", "ui.nabu.casa"]),
    "Ezviz / Hikvision": ("smart-home", ["ezvizlife.com", "hik-connect.com", "ezviz.com"]),
    "Reolink": ("smart-home", ["reolink.com"]),
    # --- telemetry / ads ---
    "Samsung TV telemetri (ACR)": ("telemetry", ["samsungacr.com", "samsungcloudsolution.com", "samsungads.com"]),
    "LG TV telemetri": ("telemetry", ["lgtvsdp.com", "lgsmartad.com", "lgappstv.com"]),
    "Roku": ("telemetry", ["roku.com", "ravm.tv"]),
    "Microsoft telemetri": ("telemetry", ["events.data.microsoft.com", "vortex.data.microsoft.com", "telemetry.microsoft.com"]),
    "Google Ads": ("ads", ["doubleclick.net", "googlesyndication.com", "googleadservices.com"]),
    # --- gaming ---
    "Steam": ("gaming", ["steampowered.com", "steamcontent.com", "steamserver.net", "steamcommunity.com"]),
    "PlayStation Network": ("gaming", ["playstation.net", "playstation.com", "sonyentertainmentnetwork.com"]),
    "Xbox Live": ("gaming", ["xboxlive.com", "xbox.com"]),
    "Nintendo": ("gaming", ["nintendo.net", "nintendo.com"]),
    "Epic Games / Fortnite": ("gaming", ["epicgames.com", "fortnite.com", "epicgames.dev"]),
    "Roblox": ("gaming", ["roblox.com", "rbxcdn.com"]),
    # --- cloud storage ---
    "iCloud": ("cloud-storage", ["icloud.com", "icloud-content.com"]),
    "Google Drive / Photos": ("cloud-storage", ["drive.google.com", "photos.google.com", "googleusercontent.com"]),
    "OneDrive": ("cloud-storage", ["onedrive.live.com", "onedrive.com", "sharepoint.com"]),
    "Dropbox": ("cloud-storage", ["dropbox.com", "dropboxapi.com"]),
}


def load_catalog(extra_path: str | Path | None = None) -> dict[str, tuple[str, list[str]]]:
    cat = dict(CATALOG)
    if extra_path and Path(extra_path).exists():
        for app, spec in (yaml.safe_load(Path(extra_path).read_text(encoding="utf-8")) or {}).items():
            cat[app] = (spec["category"], list(spec["domains"]))
    return cat


def build_index(catalog: dict[str, tuple[str, list[str]]]) -> dict[str, tuple[str, str]]:
    idx = {}
    for app, (cat, domains) in catalog.items():
        for d in domains:
            idx[d.lower().strip(".")] = (app, cat)
    return idx


def match_domain(domain: str, index: dict[str, tuple[str, str]]) -> tuple[str, str] | None:
    """Find mest specifikke match: a.b.netflix.com -> netflix.com."""
    labels = domain.lower().strip(".").split(".")
    for i in range(len(labels) - 1):
        hit = index.get(".".join(labels[i:]))
        if hit:
            return hit
    return None
