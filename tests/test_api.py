"""Unit and contract tests. They need neither Neo4j data nor Ollama: the RAG layer is stubbed.

    python -m pytest tests
"""
import importlib
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "pipeline")]

from api import routing  # noqa: E402

rag = importlib.import_module("09_graphrag")


# ------------------------------------------------------------------ router
@pytest.mark.parametrize("question,template", [
    ("Which products are affected by more than one CVE?", "products_multi"),
    ("Which vendor has the most CVEs in the corpus?", "vendor_most"),
    ("How many different vendors are affected by CVEs in the corpus?", "vendors_affected"),
    ("How many CVEs in the corpus are part of an exploit chain?", "chain_count"),
    ("How many CVEs affect Adobe products?", "vendor_cves"),
    ("how many cves affect Plex?", "vendor_cves"),
])
def test_aggregation_questions_are_routed_to_cypher(question, template):
    r = routing.classify(question)
    assert (r.kind, r.template) == ("aggregate", template)


def test_named_cve_is_an_exact_lookup():
    assert routing.classify("How many products does CVE-2026-21589 affect?").kind == "lookup"


@pytest.mark.parametrize("question", [
    "Which vulnerabilities let someone get past the login?",
    "Which products does the Fortinet advisory mention?",
])
def test_everything_else_is_semantic(question):
    assert routing.classify(question).kind == "semantic"


def test_vendor_name_is_cleaned():
    r = routing.classify("How many CVEs affect Adobe products?")
    assert r.params["vendor_query"] == "adobe"  # lower-cased: the Cypher lookup compares lower-case names


class FakeSession:
    def __init__(self, rows):
        self.rows = rows

    def run(self, cypher, *args, **kw):
        rows = self.rows.pop(0)

        class R:
            def data(_):
                return rows

            def single(_):
                return rows[0] if rows else None
        return R()


def test_execute_formats_a_tie():
    s = FakeSession([[{"name": "Citrix", "n": 2}, {"name": "Plex", "n": 2}]])
    out = routing.execute(s, routing.classify("Which vendor has the most CVEs?"))
    assert out["answer"] == "Citrix and Plex (2 CVEs each)."


def test_unknown_vendor_falls_back():
    s = FakeSession([[]])
    assert routing.execute(s, routing.classify("How many CVEs affect Nobody products?")) is None


# ----------------------------------------------------------- answer streaming
def test_answer_stream_extracts_the_answer_field_across_chunks():
    text = json.dumps({"answer": 'He said "hi"\nOK é', "sources": ["CVE-2026-1111"]})
    for size in (1, 3, 7, 50):
        p, out = rag.AnswerStream(), ""
        for i in range(0, len(text), size):
            out += p.feed(text[i:i + size])
        assert out == 'He said "hi"\nOK é', size


# -------------------------------------------------------------- API contract
@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("ASK_CACHE_TTL", "0")
    appmod = importlib.import_module("api.app")
    monkeypatch.setattr(appmod, "CACHE_TTL", 0)
    monkeypatch.setattr(appmod, "RATE_LIMIT", 0)

    def fake_stream(question, mode="graph", k=5, driver=None, num_ctx=8192):
        yield "retrieval", {"context": "ctx", "context_ids": ["CVE-2026-1111"], "retrieval_s": 0.1}
        yield "token", "Hello "
        yield "token", "world"
        yield "final", {"answer": "Hello world", "sources": ["CVE-2026-1111"], "context_cves": ["CVE-2026-1111"],
                        "retrieval_s": 0.1, "generation_s": 0.2, "cited_outside_context": ["CVE-2026-9999"], "context": "ctx"}

    monkeypatch.setattr(appmod.rag, "answer_stream", fake_stream)
    with TestClient(appmod.app) as c:
        yield c, appmod


def test_ask_auto_lookup(client):
    c, _ = client
    r = c.post("/ask", json={"question": "Which products does CVE-2026-1111 affect?"})
    body = r.json()
    assert r.status_code == 200
    assert body["mode"] == "graph" and body["route"]["kind"] == "lookup"
    assert body["ungrounded"] == ["CVE-2026-9999"]
    assert body["context"] == "ctx"


def test_ask_rejects_bad_mode_and_empty_question(client):
    c, _ = client
    assert c.post("/ask", json={"question": "x", "mode": "nope"}).status_code == 422
    assert c.post("/ask", json={"question": "   "}).status_code == 422


def test_stream_event_order(client):
    c, _ = client
    with c.stream("POST", "/ask/stream", json={"question": "Which products does CVE-2026-1111 affect?"}) as r:
        events = [line.split(": ", 1)[1] for line in r.iter_lines() if line.startswith("event: ")]
    assert events == ["route", "retrieval", "token", "token", "result"]


def test_api_key_is_required_when_configured(client, monkeypatch):
    c, _ = client
    monkeypatch.setenv("API_KEY", "secret")
    assert c.post("/ask", json={"question": "hello there"}).status_code == 401
    assert c.post("/ask", json={"question": "hello there"}, headers={"X-API-Key": "secret"}).status_code == 200


def test_rate_limit(client, monkeypatch):
    c, appmod = client
    monkeypatch.setattr(appmod, "RATE_LIMIT", 2)
    appmod._hits.clear()
    codes = [c.post("/ask", json={"question": "hello there"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_cache_hit_is_flagged(client, monkeypatch):
    c, appmod = client
    monkeypatch.setattr(appmod, "CACHE_TTL", 60)
    appmod._cache.clear()
    first = c.post("/ask", json={"question": "Tell me about login bypass"}).json()
    second = c.post("/ask", json={"question": "tell me  about login bypass"}).json()
    assert first["cached"] is False and second["cached"] is True
