"""The question-answering pipeline as small, framework-free steps over a shared state dict.

The same functions are the nodes of the LangGraph graph (graph.py) and of a plain-Python runner
(`run_plain`), so the security logic is identical with or without LangGraph and is unit-tested
without any framework installed.

    prepare -> retrieve --(no context)--> refuse
                        \\-> redact -> generate -> verify --(bad citations, 1 retry)--> generate
                                                         \\-> finalize | refuse
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Protocol

from ntk.retrieval.secure import SecureRetriever
from ntk.security import pii
from ntk.security.audit import AuditLog
from ntk.security.markings import Level
from ntk.security.policy import User
from ntk.text import detect_language

NO_ANSWER = "NO_ANSWER"
REFUSAL = {
    "en": "I can't answer that from the documents available to you.",
    "ro": "Nu pot răspunde la această întrebare pe baza documentelor la care aveți acces.",
}
_CITATION = re.compile(r"\[S(\d+)\]")


@dataclass
class ContextItem:
    label: str  # "S1"
    chunk_id: str
    doc_id: str
    title: str
    section: int
    level: Level
    text: str  # possibly redacted


class Generator(Protocol):
    def generate(self, question: str, context: list[ContextItem], lang: str, strict: bool = False) -> str: ...


@dataclass
class Deps:
    retriever: SecureRetriever
    generator: Generator
    audit: AuditLog
    top_k: int = 6
    max_attempts: int = 2


State = dict[str, Any]


# --------------------------------------------------------------------------- nodes
def prepare(state: State, deps: Deps) -> State:
    user: User = state["user"]
    if "analyst" not in user.roles:
        raise PermissionError(f"User '{user.id}' does not have the analyst role")
    question = " ".join(state["question"].split())[:2000]
    return {"question": question, "lang": detect_language(question), "attempts": 0,
            "trace_id": state.get("trace_id") or uuid.uuid4().hex[:12], "t0": time.perf_counter()}


def retrieve(state: State, deps: Deps) -> State:
    hits = deps.retriever.search(state["question"], state["user"], deps.top_k)
    return {"hits": hits}


def redact(state: State, deps: Deps) -> State:
    user: User = state["user"]
    items, total = [], 0
    for i, h in enumerate(state["hits"], start=1):
        text = h.text
        if not user.pii_access:
            r = pii.redact(text)
            text, total = r.text, total + r.total
        p = h.payload
        items.append(ContextItem(f"S{i}", h.chunk_id, p["doc_id"], p["title"], p["section"], Level(p["level"]), text))
    return {"context": items, "redactions": total}


def generate(state: State, deps: Deps) -> State:
    draft = deps.generator.generate(state["question"], state["context"], state["lang"], strict=state["attempts"] > 0)
    return {"draft": draft.strip(), "attempts": state["attempts"] + 1}


def verify(state: State, deps: Deps) -> State:
    draft: str = state["draft"]
    if draft.upper().startswith(NO_ANSWER):
        return {"verdict": "no_answer"}
    labels = {c.label for c in state["context"]}
    cited = [f"S{n}" for n in _CITATION.findall(draft)]
    if not cited or not set(cited) <= labels:
        return {"verdict": "bad_citations", "cited": [c for c in cited if c in labels]}
    return {"verdict": "ok", "cited": list(dict.fromkeys(cited))}


def finalize(state: State, deps: Deps) -> State:
    user: User = state["user"]
    answer, extra = state["draft"], 0
    if not user.pii_access:  # second layer: the model must not reintroduce PII
        r = pii.redact(answer)
        answer, extra = r.text, r.total
    by_label = {c.label: c for c in state["context"]}
    cited_items = [by_label[c] for c in state.get("cited", []) if c in by_label] or state["context"]
    # Derivative classification: an answer is classified at the highest level of what it cites.
    level = max(c.level for c in cited_items)
    warning = None if state.get("verdict") == "ok" else "Citations could not be verified; treat with caution."
    result = {
        "status": "ok", "answer": answer, "classification": level.name,
        "citations": [{"label": c.label, "doc_id": c.doc_id, "title": c.title, "section": c.section,
                       "level": c.level.name} for c in cited_items],
        "redactions": state.get("redactions", 0) + extra, "warning": warning,
    }
    _audit(state, deps, result)
    return {"result": result}


def refuse(state: State, deps: Deps) -> State:
    # Identical response whether nothing exists or everything relevant is above the user's access:
    # the user cannot learn that a restricted document exists.
    result = {"status": "no_answer", "answer": REFUSAL[state.get("lang", "en")], "classification": Level.UNCLASSIFIED.name,
              "citations": [], "redactions": 0, "warning": None}
    _audit(state, deps, result)
    return {"result": result}


def _audit(state: State, deps: Deps, result: dict[str, Any]) -> None:
    deps.audit.log(
        "query", user=state["user"].id, trace_id=state["trace_id"], question=state["question"],
        retrieved=[h.chunk_id for h in state.get("hits", [])], cited=[c["doc_id"] for c in result["citations"]],
        status=result["status"], classification=result["classification"], redactions=result["redactions"],
        attempts=state.get("attempts", 0), latency_ms=round((time.perf_counter() - state["t0"]) * 1000),
    )


# --------------------------------------------------------------------------- routing
def route_after_retrieve(state: State) -> str:
    return "redact" if state.get("hits") else "refuse"


def route_after_verify(state: State, max_attempts: int = 2) -> str:
    verdict = state["verdict"]
    if verdict == "ok":
        return "finalize"
    if verdict == "no_answer":
        return "refuse"
    return "generate" if state["attempts"] < max_attempts else ("finalize" if state.get("cited") else "refuse")


# --------------------------------------------------------------------------- plain runner
def run_plain(question: str, user: User, deps: Deps) -> dict[str, Any]:
    state: State = {"question": question, "user": user}
    state |= prepare(state, deps)
    state |= retrieve(state, deps)
    if route_after_retrieve(state) == "refuse":
        state |= refuse(state, deps)
        return state["result"] | {"trace_id": state["trace_id"]}
    state |= redact(state, deps)
    while True:
        state |= generate(state, deps)
        state |= verify(state, deps)
        nxt = route_after_verify(state, deps.max_attempts)
        if nxt != "generate":
            break
    state |= (finalize if nxt == "finalize" else refuse)(state, deps)
    return state["result"] | {"trace_id": state["trace_id"]}
