import pytest
from fastapi.testclient import TestClient

from agentwatch import cve
from agentwatch.cve import check_inventory, cpe22_to_23, parse_nvd_item, targets_for
from agentwatch.export import cyclonedx_json, summary_json
from agentwatch.models import Firmware, Service

NVD_ITEM = {"cve": {
    "id": "CVE-2024-6387", "published": "2024-07-01T13:15:01.030",
    "descriptions": [{"lang": "en", "value": "A signal handler race condition was found in sshd."}],
    "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
        "baseScore": 8.1, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
    "references": [{"url": "https://www.openssh.com/txt/release-9.8"}]}}


def test_cpe_conversion():
    assert cpe22_to_23("cpe:/a:openbsd:openssh:9.6p1") == "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"
    assert cpe22_to_23("cpe:/a:openbsd:openssh", "9.6p1 Ubuntu 3ubuntu13") == "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"
    assert cpe22_to_23("cpe:/a:openbsd:openssh") is None  # ingen version -> for bredt
    assert cpe22_to_23("cpe:/a:matt_johnston:dropbear_ssh_server:2022.83").startswith(
        "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2022.83")
    assert cpe22_to_23("cpe:2.3:o:asus:rt-ax88u_firmware:*:*:*:*:*:*:*:*", "3.0.0.4.388") == \
        "cpe:2.3:o:asus:rt-ax88u_firmware:3.0.0.4.388:*:*:*:*:*:*:*"


def test_parse_nvd_item():
    x = parse_nvd_item(NVD_ITEM)
    assert x["cve_id"] == "CVE-2024-6387" and x["cvss"] == 8.1 and x["severity"] == "HIGH"
    assert x["published"] == "2024-07-01" and x["references"]


def test_targets(store):
    d = store.upsert_observation("192.168.1.5", None, os="Linux 5.4", os_cpe=["cpe:/o:linux:linux_kernel:5.4"])
    store.set_services(d, [Service(port=22, product="OpenSSH", version="9.6p1 Ubuntu 3ubuntu13",
                                   cpe=["cpe:/a:openbsd:openssh:9.6p1"]),
                           Service(port=80, product="nginx", cpe=["cpe:/a:igor_sysoev:nginx"])])  # uden version
    d = store.get(d.id)
    d.firmware = Firmware(version="1.0", cpe="cpe:2.3:o:acme:router_firmware:*:*:*:*:*:*:*:*")
    t = targets_for(d)
    assert [(x.where, x.distro) for x in t] == [("22/tcp", True), ("firmware", False)]  # OS-gæt udeladt
    d.manual_fields.append("os")
    assert any(x.where == "os" for x in targets_for(d))


@pytest.fixture
def fake_sources(monkeypatch):
    calls = {"nvd": 0, "posts": []}

    def cves_for_cpe(self, cpe23, max_results=2000):
        calls["nvd"] += 1
        return [NVD_ITEM] if "openssh:9.6p1" in cpe23 else []

    monkeypatch.setattr(cve.NvdClient, "cves_for_cpe", cves_for_cpe)
    monkeypatch.setattr(cve, "fetch_kev", lambda: {"CVE-2024-6387": {"dueDate": "2024-08-01",
                                                                      "knownRansomwareCampaignUse": "Unknown"}})
    monkeypatch.setattr(cve, "fetch_epss", lambda ids: {i: (0.6, 0.99) for i in ids})

    class R:
        def raise_for_status(self):
            pass

    monkeypatch.setattr(cve.httpx, "post", lambda url, **kw: calls["posts"].append((url, kw)) or R())
    return calls


def test_check_inventory_lifecycle(cfg, store, fake_sources):
    cfg.cve.webhook_url = "https://example.invalid/hook"
    d = store.upsert_observation("192.168.1.5", "aa:bb:cc:dd:ee:05", hostname="nas")
    store.set_services(d, [Service(port=22, product="OpenSSH", version="9.6p1", cpe=["cpe:/a:openbsd:openssh:9.6p1"])])

    s1 = check_inventory(store, cfg)
    assert s1["new"] == 1 and s1["kev"] == 1 and s1["notified"] == 1
    f = store.cve_findings()[0]
    assert f.kev and f.epss == 0.6 and f.cvss == 8.1 and f.confidence == "høj" and f.notified
    assert fake_sources["posts"][0][1]["json"]["findings"][0]["cve_id"] == "CVE-2024-6387"
    assert any(c["kind"] == "new_cve" for c in store.changes())

    # Anden kørsel: cache bruges, intet nyt, ingen ny notifikation, status bevares
    store.cve_set_status(d.id, "CVE-2024-6387", "acknowledged")
    s2 = check_inventory(store, cfg)
    assert s2["new"] == 0 and fake_sources["nvd"] == 1 and len(fake_sources["posts"]) == 1
    assert store.cve_findings()[0].status == "acknowledged"

    # Opgradering: ny version -> fundet markeres løst
    store.set_services(store.get(d.id), [Service(port=22, product="OpenSSH", version="9.8p1",
                                                 cpe=["cpe:/a:openbsd:openssh:9.8p1"])])
    s3 = check_inventory(store, cfg)
    assert s3["resolved"] == 1 and store.cve_findings()[0].status == "resolved"
    assert any(c["kind"] == "cve_resolved" for c in store.changes())


def test_exports_and_gui(cfg, store, fake_sources):
    from agentwatch.web.app import create_app

    d = store.upsert_observation("192.168.1.5", "aa:bb:cc:dd:ee:05", hostname="nas")
    store.set_services(d, [Service(port=22, name="ssh", product="OpenSSH", version="9.6p1",
                                   cpe=["cpe:/a:openbsd:openssh:9.6p1"])])
    check_inventory(store, cfg)
    inv = store.inventory(cfg.networks)
    assert summary_json(inv)["devices"][0]["vulnerabilities"][0]["kev"] is True
    bom = cyclonedx_json(inv)
    refs = {c["bom-ref"] for dev in bom["components"] for c in dev["components"]}
    v = bom["vulnerabilities"][0]
    assert v["id"] == "CVE-2024-6387" and v["affects"][0]["ref"] in refs and v["ratings"][0]["score"] == 8.1

    c = TestClient(create_app(cfg, store))
    r = c.get("/cves")
    assert r.status_code == 200 and "CVE-2024-6387" in r.text and "KEV" in r.text
    assert "CVE-2024-6387" in c.get(f"/device?id={d.id}").text
    assert "KEV" in c.get("/").text
    r = c.post("/cve/status", data={"device_id": d.id, "cve_id": "CVE-2024-6387", "status": "ignored"},
               headers={"origin": "http://testserver"}, follow_redirects=False)
    assert r.status_code == 303 and store.cve_findings()[0].status == "ignored"
    assert "CVE-2024-6387" not in c.get("/cves").text  # kun åbne vises som standard
