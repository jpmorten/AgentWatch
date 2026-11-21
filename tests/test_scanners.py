from datetime import datetime, timezone
from pathlib import Path

from agentwatch.apps_catalog import CATALOG, build_index, match_domain
from agentwatch.scanners.discovery import parse_arp
from agentwatch.scanners.dns_usage import aggregate, parse_csv, parse_dnsmasq
from agentwatch.scanners.nmap import parse_nmap_xml
from agentwatch.scanners.services import apply_host, build_args
from agentwatch.scanners.ssdp import guess_type, parse_description, parse_headers
from agentwatch.scanners.web import fingerprint

FX = Path(__file__).parent / "fixtures"


def test_parse_nmap_lan():
    hosts = parse_nmap_xml((FX / "nmap_lan.xml").read_text())
    up = [h for h in hosts if h.up]
    assert len(up) == 1
    h = up[0]
    assert (h.ip, h.mac, h.vendor, h.hostname) == ("192.168.1.1", "A4:2B:B0:11:22:33", "TP-Link", "router.lan")
    assert [(s.port, s.protocol) for s in h.services] == [(22, "tcp"), (80, "tcp"), (53, "udp")]
    assert h.services[0].cpe == ["cpe:/a:matt_johnston:dropbear_ssh_server:2022.83"]
    assert h.os_name.startswith("OpenWrt") and h.os_accuracy == 96
    assert h.device_type == "router"  # fra service devicetype
    assert h.os_cpe == ["cpe:/o:linux:linux_kernel:5.4"]


def test_parse_real_nmap_output():
    hosts = parse_nmap_xml((FX / "nmap_sv.xml").read_text())
    assert hosts and hosts[0].services[0].port == 8080


def test_apply_host_and_version_change(store):
    h = parse_nmap_xml((FX / "nmap_lan.xml").read_text())[0]
    apply_host(store, h)
    d = store.find(ip="192.168.1.1")
    assert d.id == "mac:a4:2b:b0:11:22:33" and len(d.services) == 3
    h.services[0].version = "2024.85"
    apply_host(store, h)
    kinds = [c["kind"] for c in store.changes()]
    assert "version_changed" in kinds and kinds.count("new_device") == 1


def test_build_args_rejects_unsafe_scripts():
    import pytest
    with pytest.raises(ValueError):
        build_args("quick", scripts=["http-brute"])
    assert "--script" in build_args("quick", scripts=["ssl-cert"])


def test_parse_arp_macos_and_linux():
    out = """? (192.168.1.1) at a4:2b:b0:1:2:3 on en0 ifscope [ethernet]
? (192.168.1.7) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (192.168.1.9) at 3c:22:fb:aa:bb:cc [ether] on eth0"""
    assert parse_arp(out) == {"192.168.1.1": "a4:2b:b0:01:02:03", "192.168.1.9": "3c:22:fb:aa:bb:cc"}


def test_upnp_description():
    desc = parse_description((FX / "upnp_desc.xml").read_text())
    assert desc["manufacturer"] == "Samsung Electronics"
    assert desc["softwareVersion"] == "T-PTMFDEUC-1402.5"
    assert guess_type(desc) == "media-player"
    h = parse_headers("HTTP/1.1 200 OK\r\nSERVER: Linux/4.1 UPnP/1.0 Samsung/1.0\r\nLOCATION: http://x/\r\n\r\n")
    assert h["server"].startswith("Linux") and h["location"] == "http://x/"


def test_fingerprint():
    t = fingerprint("server: nginx/1.18\nx-powered-by: PHP/7.4", "<div>Synology DiskStation</div>", "DSM")
    assert {"nginx", "PHP", "Synology DSM"} <= set(t)


def test_domain_matching():
    idx = build_index(CATALOG)
    assert match_domain("ipv4-c001.1.nflxvideo.net.", idx) == ("Netflix", "streaming")
    assert match_domain("router15.teamviewer.com", idx) == ("TeamViewer", "remote-access")
    assert match_domain("example.org", idx) is None


def test_dns_aggregation():
    qs = parse_dnsmasq((FX / "dnsmasq.log").read_text().splitlines(), year=2026)
    assert len(qs) == 5  # "forwarded"-linjen ignoreres
    qs += parse_csv((FX / "dns.csv").read_text().splitlines())
    per_ip = aggregate(qs)
    tv = {a.app: a for a in per_ip["192.168.1.50"]}
    assert tv["Netflix"].query_count == 2 and tv["Netflix"].category == "streaming"
    assert "Samsung TV telemetri (ACR)" in tv
    assert [a.app for a in per_ip["192.168.1.20"]] == ["TeamViewer"]
    assert per_ip["192.168.1.30"][0].app == "Spotify"
    assert per_ip["192.168.1.30"][0].last_seen == datetime(2026, 11, 21, 9, 5, tzinfo=timezone.utc)
