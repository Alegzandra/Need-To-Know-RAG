"""SecureRetriever: the only path from a user's question to document text.

query -> embed (dense) + sparse -> store.search(with the user's AccessFilter) -> re-check policy
on every hit -> return. If the re-check ever removes something, the store filter is broken: the
chunk is dropped and a security event is written to the audit log.
"""

from __future__ import annotations

from typing import Protocol

from ntk.ingest.loaders import Chunk
from ntk.retrieval.stores import Hit, VectorStore, sparse_document, sparse_query
from ntk.security.audit import AuditLog
from ntk.security.policy import AccessFilter, User, can_access


class Embeddings(Protocol):
    """Same interface as langchain_core.embeddings.Embeddings, so LangChain embedders plug in directly."""

    def embed_documents(self, texts: list[str]) -> list[list[float]]: ...

    def embed_query(self, text: str) -> list[float]: ...


class SecureRetriever:
    def __init__(self, store: VectorStore, embeddings: Embeddings, compartments: set[str], audit: AuditLog,
                 candidates: int = 50) -> None:
        self.store = store
        self.embeddings = embeddings
        self.compartments = compartments
        self.audit = audit
        self.candidates = candidates

    # ---------------------------------------------------------------- write path
    def index(self, doc_id: str, chunks: list[Chunk], batch_size: int = 32) -> int:
        self.store.delete_doc(doc_id)  # re-ingest replaces the previous version
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i : i + batch_size]
            self.store.upsert(
                [c.chunk_id for c in batch],
                [c.payload for c in batch],
                self.embeddings.embed_documents([c.text for c in batch]),
                [sparse_document(c.text) for c in batch],
            )
        return len(chunks)

    # ---------------------------------------------------------------- read path
    def search(self, query: str, user: User, k: int = 6) -> list[Hit]:
        access = AccessFilter.for_user(user, self.compartments)
        hits = self.store.search(self.embeddings.embed_query(query), sparse_query(query), access, k, self.candidates)
        safe: list[Hit] = []
        for h in hits:
            ok, reason = can_access(user, h.payload)
            if ok:
                safe.append(h)
            else:
                self.audit.log("security_violation_blocked", user=user.id, chunk_id=h.chunk_id, reason=reason)
        return safe
