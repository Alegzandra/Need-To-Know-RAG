"""LangGraph wiring of the pipeline steps (see steps.py for the logic and the diagram)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from ntk.pipeline import steps
from ntk.pipeline.steps import Deps
from ntk.security.policy import User


class PipelineState(TypedDict, total=False):
    question: str
    user: Any
    lang: str
    attempts: int
    trace_id: str
    t0: float
    hits: list
    context: list
    redactions: int
    draft: str
    verdict: str
    cited: list
    result: dict


def _bind(fn: Callable[[dict, Deps], dict], deps: Deps) -> Callable[[PipelineState], dict]:
    def node(state: PipelineState) -> dict:
        return fn(dict(state), deps)

    node.__name__ = fn.__name__
    return node


def build_graph(deps: Deps):
    g = StateGraph(PipelineState)
    for name in ("prepare", "retrieve", "redact", "generate", "verify", "finalize", "refuse"):
        g.add_node(name, _bind(getattr(steps, name), deps))
    g.add_edge(START, "prepare")
    g.add_edge("prepare", "retrieve")
    g.add_conditional_edges("retrieve", steps.route_after_retrieve, ["redact", "refuse"])
    g.add_edge("redact", "generate")
    g.add_edge("generate", "verify")
    g.add_conditional_edges("verify", lambda s: steps.route_after_verify(s, deps.max_attempts),
                            ["generate", "finalize", "refuse"])
    g.add_edge("finalize", END)
    g.add_edge("refuse", END)
    return g.compile()


def run_graph(graph, question: str, user: User) -> dict[str, Any]:
    state = graph.invoke({"question": question, "user": user})
    return state["result"] | {"trace_id": state["trace_id"]}
