"""Tests for the framework adapters. Each is skipped if its library is not installed;
`pip install -e ".[dev]"` installs all of them and CI runs them on every push."""

import base64

import pytest
from conftest import GroundedFakeGenerator, HashEmbeddings, make_services


# --------------------------------------------------------------------------- LangChain
def test_langchain_retriever_respects_clearance(services):
    pytest.importorskip("langchain_core")
    from ntk.retrieval.langchain_retriever import ClearanceRetriever

    r = ClearanceRetriever(secure=services.retriever, user=services.users.users["klaus"], k=8)
    docs = r.invoke("drone flights substation S-17 VARTA phishing Apa Nord")
    assert docs and {d.metadata["doc_id"] for d in docs} <= {"PUB-2026-001", "ASM-2026-031", "GUIDE-2026-002"}
    assert all("text" not in d.metadata for d in docs)


def test_langchain_generator_with_fake_chat_model(tmp_path, corpus_dir):
    pytest.importorskip("langchain_core")
    from langchain_core.language_models.fake_chat_models import FakeListChatModel

    from ntk.pipeline.llm import LangChainGenerator

    gen = LangChainGenerator(FakeListChatModel(responses=["Sector 4 has a fence gap [S1]."]))
    svc = make_services(tmp_path, corpus_dir, generator=gen)
    r = svc.ask("What weaknesses were found in the Calvara port perimeter?", svc.users.users["mihai"])
    assert r["status"] == "ok" and r["citations"][0]["doc_id"] == "ASM-2026-031"


# --------------------------------------------------------------------------- LangGraph
def test_langgraph_and_plain_runner_agree(tmp_path, corpus_dir, cases):
    pytest.importorskip("langgraph")
    graph_svc = make_services(tmp_path / "g", corpus_dir, generator=GroundedFakeGenerator(), use_langgraph=True)
    plain_svc = make_services(tmp_path / "p", corpus_dir, generator=GroundedFakeGenerator(), use_langgraph=False)
    for case in cases:
        for uid in ("ana", "elena", "klaus"):
            a = graph_svc.ask(case["question"], graph_svc.users.users[uid])
            b = plain_svc.ask(case["question"], plain_svc.users.users[uid])
            assert {k: v for k, v in a.items() if k != "trace_id"} == {k: v for k, v in b.items() if k != "trace_id"}


# --------------------------------------------------------------------------- Qdrant
def test_qdrant_store_zero_leakage(tmp_path, corpus_dir, cases, oracle):
    qdrant_client = pytest.importorskip("qdrant_client")
    from ntk.evals.runner import retrieval_metrics
    from ntk.retrieval.stores import QdrantStore

    store = QdrantStore(qdrant_client.QdrantClient(":memory:"), "test_chunks")
    svc = make_services(tmp_path, corpus_dir, store=store)
    m = retrieval_metrics(svc, cases, oracle, k=6)
    assert m["leaked_chunks"] == 0 and m["recall@6"] >= 0.8


def test_qdrant_filter_shape():
    pytest.importorskip("qdrant_client")
    from ntk.retrieval.stores import QdrantStore
    from ntk.security.policy import AccessFilter

    f = QdrantStore(client=None, collection="x").to_filter(AccessFilter(1, ("HALCYON", "ORION"), ("ROU",)))
    assert f.must[0].key == "level" and f.must[0].range.lte == 1
    assert f.must_not[0].key == "compartments" and set(f.must_not[0].match.any) == {"HALCYON", "ORION"}


# --------------------------------------------------------------------------- FastAPI
@pytest.fixture
def client(tmp_path, corpus_dir):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from ntk.api.app import create_app

    return TestClient(create_app(make_services(tmp_path, corpus_dir, generator=GroundedFakeGenerator())))


def test_api_auth_roles_and_query(client):
    assert client.get("/health").json()["status"] == "ok"
    assert client.post("/v1/query", json={"question": "anything at all"}).status_code == 401
    assert client.post("/v1/query", headers={"X-API-Key": "demo-auditor"}, json={"question": "test q"}).status_code == 403

    r = client.post("/v1/query", headers={"X-API-Key": "demo-mihai"},
                    json={"question": "What weaknesses were found in the Calvara port perimeter?"})
    body = r.json()
    assert r.status_code == 200 and body["status"] == "ok" and body["classification"] == "CONFIDENTIAL"
    assert client.get("/v1/me", headers={"X-API-Key": "demo-elena"}).json()["compartments"] == ["ORION"]


def test_api_ingest_and_audit(client):
    admin = {"X-API-Key": "demo-admin"}
    assert client.get("/v1/audit", headers={"X-API-Key": "stolen-guess"}).status_code == 401
    bad =base64.b64encode(b"RESTRICTED\n\n(S) portion above banner").decode()
    assert client.post("/v1/documents", headers=admin, json={"filename": "bad.txt", "content_base64": bad}).status_code == 422
    good = base64.b64encode(b"UNCLASSIFIED//REL TO ROU, NATO\nDOC-ID: NEW-1\nTITLE: New\n\nHello world text.").decode()
    r = client.post("/v1/documents", headers=admin, json={"filename": "../../etc/new.txt", "content_base64": good})
    assert r.status_code == 201 and r.json()["doc_id"] == "NEW-1"
    assert client.post("/v1/documents", headers={"X-API-Key": "demo-elena"},
                       json={"filename": "x.txt", "content_base64": good}).status_code == 403
    audit = client.get("/v1/audit/verify", headers={"X-API-Key": "demo-auditor"}).json()
    assert audit == {"intact": True, "first_bad_line": None}
    events = {e["event"] for e in client.get("/v1/audit", headers={"X-API-Key": "demo-auditor"}).json()}
    assert {"ingest", "ingest_rejected", "auth_failed", "forbidden"} <= events


def test_hash_embeddings_match_langchain_interface():
    lc = pytest.importorskip("langchain_core.embeddings")
    assert all(hasattr(HashEmbeddings, m) for m in ("embed_documents", "embed_query"))
    assert hasattr(lc.Embeddings, "embed_documents")
