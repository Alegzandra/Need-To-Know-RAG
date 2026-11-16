"""LangChain adapter: exposes the clearance-aware retriever as a standard LangChain retriever,
so it can be composed into any LCEL chain or agent without bypassing access control.

    retriever = ClearanceRetriever(secure=services.retriever, user=user, k=6)
    docs = retriever.invoke("drone sightings near substation S-17")
"""

from __future__ import annotations

from typing import Any

from langchain_core.callbacks import CallbackManagerForRetrieverRun
from langchain_core.documents import Document
from langchain_core.retrievers import BaseRetriever
from pydantic import ConfigDict


class ClearanceRetriever(BaseRetriever):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    secure: Any  # ntk.retrieval.secure.SecureRetriever
    user: Any  # ntk.security.policy.User (bound per request; never shared across users)
    k: int = 6

    def _get_relevant_documents(self, query: str, *, run_manager: CallbackManagerForRetrieverRun) -> list[Document]:
        return [
            Document(page_content=h.text, metadata={k: v for k, v in h.payload.items() if k != "text"})
            for h in self.secure.search(query, self.user, self.k)
        ]
