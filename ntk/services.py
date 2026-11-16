"""Composition root: builds every component from Settings. Tests inject fakes through the keyword args."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ntk.config import Settings
from ntk.ingest.loaders import load_file
from ntk.pipeline.steps import Deps, Generator, run_plain
from ntk.retrieval.secure import Embeddings, SecureRetriever
from ntk.retrieval.stores import VectorStore
from ntk.security.audit import AuditLog
from ntk.security.policy import User, UserDirectory, load_compartments

log = logging.getLogger(__name__)


@dataclass
class Services:
    settings: Settings
    users: UserDirectory
    compartments: set[str]
    audit: AuditLog
    retriever: SecureRetriever
    deps: Deps
    _runner: Callable[[str, User], dict[str, Any]] = field(repr=False, default=None)  # type: ignore[assignment]

    def ask(self, question: str, user: User) -> dict[str, Any]:
        return self._runner(question, user)

    def ingest(self, path: Path, actor: str = "cli") -> dict[str, Any]:
        doc, chunks = load_file(path, self.compartments, self.settings.owner_nationality)
        n = self.retriever.index(doc.doc_id, chunks)
        levels = sorted({c.payload["level_name"] for c in chunks})
        self.audit.log("ingest", user=actor, doc_id=doc.doc_id, banner=doc.banner.render(), chunks=n,
                       portion_levels=levels, source=path.name)
        return {"doc_id": doc.doc_id, "title": doc.title, "banner": doc.banner.render(), "chunks": n,
                "portion_levels": levels}


def _default_store(s: Settings) -> VectorStore:
    from qdrant_client import QdrantClient

    from ntk.retrieval.stores import QdrantStore

    if s.qdrant_url:
        client = QdrantClient(url=s.qdrant_url, api_key=s.qdrant_api_key or None)
    else:
        s.qdrant_path.mkdir(parents=True, exist_ok=True)
        client = QdrantClient(path=str(s.qdrant_path))  # embedded mode, no server needed
    return QdrantStore(client, s.collection)


def build_services(
    settings: Settings | None = None,
    *,
    store: VectorStore | None = None,
    embeddings: Embeddings | None = None,
    generator: Generator | None = None,
    use_langgraph: bool | None = None,
) -> Services:
    s = settings or Settings()
    users = UserDirectory.from_yaml(s.users_file)
    compartments = load_compartments(s.compartments_file)
    audit = AuditLog(s.audit_path)

    if embeddings is None or generator is None:
        from ntk.pipeline.llm import LangChainGenerator, make_chat_model, make_embeddings

        embeddings = embeddings or make_embeddings(s)
        generator = generator or LangChainGenerator(make_chat_model(s))

    retriever = SecureRetriever(store or _default_store(s), embeddings, compartments, audit)
    deps = Deps(retriever=retriever, generator=generator, audit=audit, top_k=s.top_k)
    services = Services(s, users, compartments, audit, retriever, deps)

    if s.use_langgraph if use_langgraph is None else use_langgraph:
        from ntk.pipeline.graph import build_graph, run_graph

        graph = build_graph(deps)
        services._runner = lambda q, u: run_graph(graph, q, u)
    else:
        services._runner = lambda q, u: run_plain(q, u, deps)
    return services
