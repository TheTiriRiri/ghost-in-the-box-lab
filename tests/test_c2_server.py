"""Unit tests for the c2-server Flask app (no Docker required)."""
import json
import pathlib
import sys

import pytest

C2_DIR = pathlib.Path(__file__).parent.parent / "module-techlab" / "c2-server"
sys.path.insert(0, str(C2_DIR))


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("C2_DATA_DIR", str(tmp_path))
    import importlib
    import app as c2_app
    importlib.reload(c2_app)
    c2_app.app.config["TESTING"] = True
    with c2_app.app.test_client() as c:
        yield c, tmp_path


def test_collect_persists_payload(client):
    c, data_dir = client
    resp = c.post("/collect", json={"host": "h", "user": "u", "keys": ["a"]})
    assert resp.status_code == 200
    lines = (data_dir / "received.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["host"] == "h"
    assert record["user"] == "u"
    assert record["keys"] == ["a"]
    assert "received_at" in record


def test_collect_rejects_non_json(client):
    c, _ = client
    resp = c.post("/collect", data="not json", content_type="text/plain")
    assert resp.status_code == 400


def test_healthcheck(client):
    c, _ = client
    resp = c.get("/healthz")
    assert resp.status_code == 200
