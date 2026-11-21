import asyncio

from fastapi.testclient import TestClient

from agentwatch.web.app import create_app

ORIGIN = {"origin": "http://testserver"}


def test_gui_flow(cfg, store):
    c = TestClient(create_app(cfg, store))
    assert c.get("/").status_code == 200
    # Cross-origin POST afvises
    assert c.post("/new", data={"hostname": "x"}, headers={"origin": "http://evil.example"}).status_code == 403
    assert c.post("/new", data={"hostname": "x"}).status_code == 403  # ingen origin
    r = c.post("/new", data={"hostname": "Stue-TV", "ip": "192.168.1.50", "vendor": "Samsung",
                             "device_type": "tv", "firmware": "1402.5"}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303
    d = store.find(ip="192.168.1.50")
    assert d.firmware.version == "1402.5" and "vendor" in d.manual_fields
    assert c.get(f"/device?id={d.id}").status_code == 200
    r = c.post("/device/edit", data={"id": d.id, "owner": "Alex", "hostname": "Stue-TV", "vendor": "Samsung",
                                     "device_type": "tv", "trusted": "yes"}, headers=ORIGIN)
    d = store.get(d.id)
    assert d.owner == "Alex" and d.trusted is True and "owner" in d.manual_fields
    c.post("/device/service", data={"id": d.id, "port": "8001", "product": "Samsung TV API"}, headers=ORIGIN)
    assert store.get(d.id).services[0].source == "manual"
    for fmt in ["summary", "inventory", "cyclonedx"]:
        assert c.get(f"/export/{fmt}").status_code == 200
    assert c.get("/changes").status_code == 200


def test_mcp_tools(cfg, store):
    from agentwatch.mcp_server import build_server

    store.upsert_observation("192.168.1.1", "aa:bb:cc:dd:ee:ff", hostname="router")
    server = build_server(cfg, store)
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    assert {"get_summary", "get_device", "search_software", "list_app_usage", "add_assessment_note"} <= names


def test_concurrent_scan_writes_and_gui_reads(tmp_path, cfg):
    """Regression: scanner-tråd og web-requests delte SQLite-forbindelse uden lås -> 500-fejl."""
    import threading

    from agentwatch.models import Service
    from agentwatch.store import Store

    store = Store(tmp_path / "c.db")
    c = TestClient(create_app(cfg, store))
    errors = []

    def writer():
        try:
            for i in range(400):
                d = store.upsert_observation(f"192.168.1.{i % 250}", None, hostname=f"h{i}")
                store.set_services(d, [Service(port=22, version=str(i))])
        except Exception as e:  # pragma: no cover
            errors.append(repr(e))

    def reader():
        for _ in range(40):
            r = c.get("/")
            if r.status_code != 200:
                errors.append(r.status_code)

    ts = [threading.Thread(target=writer)] + [threading.Thread(target=reader) for _ in range(3)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert errors == []


def test_log_diag_status_pages(cfg, store):
    import logging

    c = TestClient(create_app(cfg, store))
    logging.getLogger("agentwatch").info("hej fra testen")
    j = c.get("/scan/status").json()
    assert j["running"] is False and any("hej fra testen" in l for l in j["lines"])
    assert c.get(f"/scan/status?since={j['seq']}").json()["lines"] == []
    assert "hej fra testen" in c.get("/log").text
    r = c.get("/diag")
    assert r.status_code == 200 and "nmap" in r.text


def test_error_page_instead_of_raw_500(cfg, store, monkeypatch):
    c = TestClient(create_app(cfg, store), raise_server_exceptions=False)
    monkeypatch.setattr(store, "all", lambda: (_ for _ in ()).throw(RuntimeError("db er væk")))
    r = c.get("/")
    assert r.status_code == 500 and "db er væk" in r.text and "Noget gik galt" in r.text
