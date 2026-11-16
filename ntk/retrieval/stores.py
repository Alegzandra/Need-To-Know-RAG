"""Vector stores with access control pushed down into the search.

Both stores implement the same interface, so tests run on the in-memory store while production
uses Qdrant. In both, forbidden chunks are filtered BEFORE ranking: they never take a slot in
the top-k, and nothing about them (score, count, existence) can leak through the results.
"""

from __future__ import annotations

import hashlib
import math
import uuid
from collections import Counter
from dataclasses import dataclass
from typing import Any, Protocol

import numpy as np

from ntk.security.policy import AccessFilter
from ntk.text import tokenize


# --------------------------------------------------------------------------- sparse (BM25-style) vectors
def _term_index(token: str) -> int:
    return int(hashlib.md5(token.encode()).hexdigest()[:8], 16)  # stable uint32 id


def sparse_document(text: str, k1: float = 1.2) -> dict[int, float]:
    """Saturated term frequencies; IDF is applied by the store (Qdrant's IDF modifier)."""
    tf = Counter(tokenize(text))
    return {_term_index(t): f * (k1 + 1) / (f + k1) for t, f in tf.items()}


def sparse_query(text: str) -> dict[int, float]:
    return {_term_index(t): 1.0 for t in set(tokenize(text))}


@dataclass
class Hit:
    chunk_id: str
    text: str
    payload: dict[str, Any]
    score: float


class VectorStore(Protocol):
    def upsert(self, ids: list[str], payloads: list[dict[str, Any]], dense: list[list[float]],
               sparse: list[dict[int, float]]) -> None: ...

    def search(self, dense: list[float], sparse: dict[int, float], access: AccessFilter, k: int,
               candidates: int = 50) -> list[Hit]: ...

    def delete_doc(self, doc_id: str) -> None: ...

    def count(self) -> int: ...


def _rrf(rankings: list[list[str]], k: int = 60) -> dict[str, float]:
    fused: dict[str, float] = {}
    for ranking in rankings:
        for r, cid in enumerate(ranking):
            fused[cid] = fused.get(cid, 0.0) + 1.0 / (k + r + 1)
    return fused


# --------------------------------------------------------------------------- in-memory
class InMemoryStore:
    """Reference implementation (tests, demos). Same semantics as the Qdrant store."""

    def __init__(self) -> None:
        self.payloads: dict[str, dict[str, Any]] = {}
        self.dense: dict[str, np.ndarray] = {}
        self.sparse: dict[str, dict[int, float]] = {}

    def upsert(self, ids, payloads, dense, sparse) -> None:
        for cid, p, d, s in zip(ids, payloads, dense, sparse):
            v = np.asarray(d, dtype=np.float32)
            self.payloads[cid], self.dense[cid], self.sparse[cid] = p, v / (np.linalg.norm(v) or 1.0), s

    def delete_doc(self, doc_id: str) -> None:
        for cid in [c for c, p in self.payloads.items() if p.get("doc_id") == doc_id]:
            del self.payloads[cid], self.dense[cid], self.sparse[cid]

    def count(self) -> int:
        return len(self.payloads)

    def search(self, dense, sparse, access, k, candidates=50) -> list[Hit]:
        allowed = [cid for cid, p in self.payloads.items() if access.matches(p)]  # filter first
        if not allowed:
            return []
        n = len(self.payloads)
        df: Counter = Counter()
        for s in self.sparse.values():
            df.update(s.keys())
        q = np.asarray(dense, dtype=np.float32)
        q = q / (np.linalg.norm(q) or 1.0)
        dense_scores = {cid: float(self.dense[cid] @ q) for cid in allowed}
        sparse_scores = {
            cid: sum(w * self.sparse[cid].get(t, 0.0) * math.log(1 + (n - df[t] + 0.5) / (df[t] + 0.5))
                     for t, w in sparse.items())
            for cid in allowed
        }
        dense_rank = sorted(allowed, key=lambda c: -dense_scores[c])[:candidates]
        sparse_rank = [c for c in sorted(allowed, key=lambda c: -sparse_scores[c]) if sparse_scores[c] > 0][:candidates]
        fused = _rrf([dense_rank, sparse_rank])
        top = sorted(fused, key=lambda c: -fused[c])[:k]
        return [Hit(c, self.payloads[c]["text"], self.payloads[c], fused[c]) for c in top]


# --------------------------------------------------------------------------- Qdrant
class QdrantStore:
    """Qdrant with a named dense vector + a sparse vector using Qdrant's IDF modifier, fused with RRF.

    The access filter is attached to EVERY prefetch (dense and sparse) and to the outer query,
    so filtering happens inside the engine before candidates are selected.
    """

    def __init__(self, client: Any, collection: str) -> None:
        from qdrant_client import models  # optional dependency

        self.m = models
        self.client = client
        self.collection = collection

    def _ensure_collection(self, dim: int) -> None:
        m = self.m
        if self.client.collection_exists(self.collection):
            return
        self.client.create_collection(
            collection_name=self.collection,
            vectors_config={"dense": m.VectorParams(size=dim, distance=m.Distance.COSINE)},
            sparse_vectors_config={"sparse": m.SparseVectorParams(modifier=m.Modifier.IDF)},
        )
        for field, schema in [("level", m.PayloadSchemaType.INTEGER), ("compartments", m.PayloadSchemaType.KEYWORD),
                              ("rel_to", m.PayloadSchemaType.KEYWORD), ("doc_id", m.PayloadSchemaType.KEYWORD)]:
            self.client.create_payload_index(self.collection, field_name=field, field_schema=schema)

    def to_filter(self, access: AccessFilter):
        m = self.m
        must = [
            m.FieldCondition(key="level", range=m.Range(lte=access.max_level)),
            m.FieldCondition(key="rel_to", match=m.MatchAny(any=list(access.rel_tokens))),
        ]
        must_not = []
        if access.forbidden_compartments:
            must_not.append(m.FieldCondition(key="compartments", match=m.MatchAny(any=list(access.forbidden_compartments))))
        return m.Filter(must=must, must_not=must_not)

    def upsert(self, ids, payloads, dense, sparse) -> None:
        m = self.m
        if not ids:
            return
        self._ensure_collection(len(dense[0]))
        points = [
            m.PointStruct(
                id=str(uuid.uuid5(uuid.NAMESPACE_URL, cid)),
                vector={"dense": d, "sparse": m.SparseVector(indices=list(s.keys()), values=list(s.values()))},
                payload=p,
            )
            for cid, p, d, s in zip(ids, payloads, dense, sparse)
        ]
        self.client.upsert(collection_name=self.collection, points=points)

    def delete_doc(self, doc_id: str) -> None:
        m = self.m
        if self.client.collection_exists(self.collection):
            self.client.delete(self.collection, points_selector=m.FilterSelector(filter=m.Filter(
                must=[m.FieldCondition(key="doc_id", match=m.MatchValue(value=doc_id))])))

    def count(self) -> int:
        if not self.client.collection_exists(self.collection):
            return 0
        return self.client.count(self.collection).count

    def search(self, dense, sparse, access, k, candidates=50) -> list[Hit]:
        m = self.m
        if not self.client.collection_exists(self.collection):
            return []
        flt = self.to_filter(access)
        res = self.client.query_points(
            collection_name=self.collection,
            prefetch=[
                m.Prefetch(query=dense, using="dense", filter=flt, limit=candidates),
                m.Prefetch(query=m.SparseVector(indices=list(sparse.keys()), values=list(sparse.values())),
                           using="sparse", filter=flt, limit=candidates),
            ],
            query=m.FusionQuery(fusion=m.Fusion.RRF),
            query_filter=flt,
            limit=k,
            with_payload=True,
        )
        return [Hit(p.payload["chunk_id"], p.payload["text"], p.payload, p.score) for p in res.points]
