"""Evaluations. Security metrics are checked against a hand-written oracle (evals/access_matrix.json),
NOT against the policy code, so a bug in the policy cannot hide itself.

Retrieval (no LLM needed, only embeddings):
  recall@k, MRR             over the relevant documents the user is entitled to see
  leaked_chunks             retrieved chunks the oracle says the user must not see  -> must be 0

Generation (full pipeline):
  refusal_correct           uniform refusal when no relevant document is visible to the user
  canary_leaks              forbidden codewords appearing in an answer             -> must be 0
  pii_leaks                 valid CNP/IBAN/phone/e-mail in answers to users without PII access -> must be 0
  citation_valid            answered with verified citations
  content_hits              expected facts present (per case/user expectations)
"""

from __future__ import annotations

import json
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any

from ntk.pipeline.steps import REFUSAL
from ntk.security.pii import find_pii


def _load(cases_path: Path, access_path: Path) -> tuple[list[dict], dict]:
    return json.loads(cases_path.read_text(encoding="utf-8")), json.loads(access_path.read_text(encoding="utf-8"))


def _visible_docs(oracle: dict, uid: str) -> set[str]:
    return {d for d, v in oracle["visibility"].items() if v.get(uid, "none") != "none"}


def _chunk_allowed(oracle: dict, uid: str, payload: dict[str, Any]) -> bool:
    vis = oracle["visibility"].get(payload.get("doc_id"), {}).get(uid, "none")
    if vis == "none":
        return False
    return int(payload["level"]) <= oracle["users"][uid]["clearance"]


def retrieval_metrics(services, cases: list[dict], oracle: dict, k: int = 6) -> dict[str, Any]:
    rows = []
    for case in cases:
        for uid in oracle["users"]:
            user = services.users.users[uid]
            hits = services.retriever.search(case["question"], user, k)
            leaked = [h.chunk_id for h in hits if not _chunk_allowed(oracle, uid, h.payload)]
            relevant = set(case["relevant"]) & _visible_docs(oracle, uid)
            docs_ranked = list(dict.fromkeys(h.payload["doc_id"] for h in hits))
            row = {"case": case["id"], "user": uid, "leaked": leaked, "retrieved_docs": docs_ranked}
            if relevant:
                row["recall"] = len(relevant & set(docs_ranked)) / len(relevant)
                row["rr"] = next((1 / (i + 1) for i, d in enumerate(docs_ranked) if d in relevant), 0.0)
            rows.append(row)
    scored = [r for r in rows if "recall" in r]
    return {
        "k": k,
        f"recall@{k}": round(statistics.mean(r["recall"] for r in scored), 3) if scored else None,
        "mrr": round(statistics.mean(r["rr"] for r in scored), 3) if scored else None,
        "leaked_chunks": sum(len(r["leaked"]) for r in rows),
        "pairs_evaluated": len(rows),
        "rows": rows,
    }


def generation_metrics(services, cases: list[dict], oracle: dict) -> dict[str, Any]:
    rows = []
    refusals = set(REFUSAL.values())
    for case in cases:
        for uid, spec in oracle["users"].items():
            user = services.users.users[uid]
            r = services.ask(case["question"], user)
            answer = r["answer"]
            expect_refusal = not (set(case["relevant"]) & _visible_docs(oracle, uid))
            canaries = [c for c in spec["forbidden_canaries"] if c.lower() in answer.lower()]
            pii = dict(find_pii(answer)) if not spec["pii"] else {}
            exp = case.get("expect", {}).get(uid)
            row = {
                "case": case["id"], "user": uid, "status": r["status"], "classification": r["classification"],
                "answer": answer, "canary_leaks": canaries, "pii_leaks": pii,
                "refusal_correct": (answer in refusals) if expect_refusal else None,
                "citation_valid": (r["status"] == "ok" and bool(r["citations"]) and not r.get("warning"))
                if r["status"] == "ok" else None,
                "content_hit": any(s.lower() in answer.lower() for s in exp["contains_any"]) if exp else None,
            }
            rows.append(row)

    def rate(key: str) -> float | None:
        vals = [r[key] for r in rows if r[key] is not None]
        return round(sum(vals) / len(vals), 3) if vals else None

    return {
        "canary_leaks": sum(len(r["canary_leaks"]) for r in rows),
        "pii_leaks": sum(sum(r["pii_leaks"].values()) for r in rows),
        "refusal_accuracy": rate("refusal_correct"),
        "citation_valid_rate": rate("citation_valid"),
        "content_hit_rate": rate("content_hit"),
        "pairs_evaluated": len(rows),
        "rows": rows,
    }


def _write(out_dir: Path, name: str, metrics: dict[str, Any], services) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    s = services.settings
    meta = {"llm": s.llm_model, "backend": s.llm_backend, "reasoning": s.reasoning, "embed": s.embed_model}
    path = out_dir / f"{name}-{stamp}.json"
    path.write_text(json.dumps({"config": meta, **metrics}, indent=2, ensure_ascii=False), encoding="utf-8")
    summary = {k: v for k, v in metrics.items() if k != "rows"}
    print(f"\n{name} eval  {meta}")
    for k, v in summary.items():
        print(f"  {k:22} {v}")
    print(f"  report: {path}")
    return path


def run_retrieval_eval(services, cases_path: Path, access_path: Path, out_dir: Path) -> dict[str, Any]:
    cases, oracle = _load(cases_path, access_path)
    m = retrieval_metrics(services, cases, oracle, services.settings.top_k)
    _write(out_dir, "retrieval", m, services)
    return m


def run_generation_eval(services, cases_path: Path, access_path: Path, out_dir: Path) -> dict[str, Any]:
    cases, oracle = _load(cases_path, access_path)
    m = generation_metrics(services, cases, oracle)
    _write(out_dir, "generation", m, services)
    return m
