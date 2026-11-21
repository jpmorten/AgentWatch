import pytest

from agentwatch.export import cyclonedx_json, summary_json
from agentwatch.models import AppUsage, Firmware, Service
from agentwatch.scope import ScopeError, ensure_in_scope, parse_networks


def test_scope():
    assert ensure_in_scope("192.168.1.5", ["192.168.1.0/24"])
    for bad in ["8.8.8.8", "192.168.2.5", "192.168.0.0/16"]:
        with pytest.raises(ScopeError):
            ensure_in_scope(bad, ["192.168.1.0/24"])
    with pytest.raises(ScopeError):
        parse_networks(["1.2.3.0/24"])
    with pytest.raises(ScopeError):
        parse_networks(["10.0.0.0/8"])


def test_manual_fields_not_overwritten(store):
    d = store.upsert_observation("192.168.1.10", None, vendor="Unknown")
    d.vendor, d.manual_fields = "Sonos", ["vendor"]
    store.save(d)
    d = store.upsert_observation("192.168.1.10", None, vendor="Scanner says X", hostname="sonos-kitchen")
    assert d.vendor == "Sonos" and d.hostname == "sonos-kitchen"


def test_ip_device_migrates_to_mac_key(store):
    store.upsert_observation("192.168.1.10", None)
    d = store.upsert_observation("192.168.1.10", "AA-BB-CC-DD-EE-FF")
    assert d.id == "mac:aa:bb:cc:dd:ee:ff" and len(store.all()) == 1
    d = store.upsert_observation("192.168.1.11", "aa:bb:cc:dd:ee:ff")
    assert d.ip == "192.168.1.11" and any(c["kind"] == "ip_changed" for c in store.changes())


def test_manual_services_kept(store):
    d = store.upsert_observation("192.168.1.10", None)
    d.services = [Service(port=9999, product="Custom", source="manual")]
    store.save(d)
    store.set_services(d, [Service(port=22, product="OpenSSH", version="9.6")])
    assert {s.port for s in store.get(d.id).services} == {22, 9999}


def test_mark_offline(store):
    a = store.upsert_observation("192.168.1.10", None)
    store.upsert_observation("192.168.1.11", None)
    store.mark_offline({a.id})
    assert [d.online for d in store.all()] == [True, False]


def test_exports(store):
    d = store.upsert_observation("192.168.1.1", "aa:bb:cc:dd:ee:ff", vendor="ASUS", model="RT-AX88U",
                                 os="Linux", os_cpe=["cpe:/o:linux:linux_kernel:4.1"])
    d.firmware = Firmware(version="3.0.0.4.388", cpe="cpe:2.3:o:asus:rt-ax88u_firmware:3.0.0.4.388:*:*:*:*:*:*:*")
    store.save(d)
    store.set_services(d, [Service(port=22, name="ssh", product="Dropbear", version="2022.83",
                                   cpe=["cpe:/a:matt_johnston:dropbear_ssh_server:2022.83"])])
    store.merge_apps(store.get(d.id), [AppUsage(app="TeamViewer", category="remote-access", query_count=3)])
    inv = store.inventory(["192.168.1.0/24"])
    bom = cyclonedx_json(inv)
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    dev = bom["components"][0]
    types = {c["type"] for c in dev["components"]}
    assert types == {"operating-system", "firmware", "application"}
    fw = next(c for c in dev["components"] if c["type"] == "firmware")
    assert fw["cpe"].startswith("cpe:2.3:o:asus") and fw["version"] == "3.0.0.4.388"
    s = summary_json(inv)["devices"][0]
    assert "cpe:/a:matt_johnston:dropbear_ssh_server:2022.83" in s["cpe"] and s["firmware"] == "3.0.0.4.388"
    assert s["apps"][0].startswith("TeamViewer")
