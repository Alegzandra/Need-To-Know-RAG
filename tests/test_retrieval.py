import shutil

import pytest

from ntk.evals.runner import retrieval_metrics
from ntk.ingest.loaders import load_file
from ntk.retrieval.stores import Hit
from ntk.security.markings import Level
from ntk.text import detect_language


def test_chunks_never_mix_portion_levels(corpus_dir):
    _, chunks = load_file(corpus_dir / "ASM-2026-031.txt", {"ORION", "HALCYON"})
    assert [c.payload["level_name"] for c in chunks] == ["UNCLASSIFIED", "CONFIDENTIAL", "RESTRICTED"]
    assert "KESTREL" in chunks[1].text and all("KESTREL" not in c.text for c in (chunks[0], chunks[2]))


def test_language_detection_handles_romanian_without_diacritics():
    assert detect_language("Ce s-a intamplat la statia S-17 in noaptea de 3 noiembrie?") == "ro"
    assert detect_language("Ce s-a întâmplat la stația S-17?") == "ro"
    assert detect_language("What happened at substation S-17 that night?") == "en"


@pytest.mark.skipif(not shutil.which("tesseract"), reason="tesseract not installed")
def test_scanned_memo_is_ocred_and_marked(corpus_dir):
    doc, chunks = load_file(corpus_dir / "MEM-2026-007.png", set())
    assert doc.doc_id == "MEM-2026-007" and chunks[0].payload["level"] == Level.RESTRICTED
    assert "patrul" in chunks[0].text.lower()


def test_zero_leakage_against_independent_oracle(services, cases, oracle):
    m = retrieval_metrics(services, cases, oracle, k=6)
    assert m["leaked_chunks"] == 0
    assert m["pairs_evaluated"] == len(cases) * len(oracle["users"])
    assert m["recall@6"] >= 0.8 and m["mrr"] >= 0.7  # lexical-only fake embeddings; real ones do better


def test_partial_document_visibility(services):
    ana = services.users.users["ana"]
    hits = services.retriever.search("Calvara port perimeter sector 4 fence", ana, k=10)
    asm = [h for h in hits if h.payload["doc_id"] == "ASM-2026-031"]
    assert {h.payload["level_name"] for h in asm} <= {"UNCLASSIFIED", "RESTRICTED"} and asm
    assert all("KESTREL" not in h.text for h in hits)


def test_forbidden_chunks_do_not_consume_top_k(services):
    sorin = services.users.users["sorin"]  # SECRET but not read into ORION
    hits = services.retriever.search("VARTA operator group TALON quadcopters firmware", sorin, k=1)
    assert len(hits) == 1 and hits[0].payload["doc_id"] != "ORN-2026-002"


def test_defence_in_depth_when_store_filter_is_broken(services):
    class BrokenStore:
        """Simulates a misconfigured vector DB that ignores the access filter."""

        def __init__(self, inner):
            self.inner = inner

        def search(self, dense, sparse, access, k, candidates=50):
            return [Hit(cid, p["text"], p, 1.0) for cid, p in list(self.inner.payloads.items())[:k]]

    services.retriever.store = BrokenStore(services.retriever.store)
    ana = services.users.users["ana"]
    hits = services.retriever.search("anything", ana, k=50)
    assert all(h.payload["level"] <= Level.RESTRICTED and not h.payload["compartments"] for h in hits)
    events = [r for r in services.audit.tail(200) if r["event"] == "security_violation_blocked"]
    assert events and all(e["user"] == "ana" for e in events)
