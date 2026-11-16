"""Offline fixtures: in-memory vector store, deterministic embeddings and fake LLMs.

The most important fake is LeakyEchoGenerator: a worst-case "LLM" that dumps EVERYTHING it is given.
If no secret leaks even with it, leakage is prevented by retrieval + redaction alone, regardless of
how the real model behaves.
"""

from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from ntk.config import Settings
from ntk.pipeline.steps import NO_ANSWER
from ntk.retrieval.stores import InMemoryStore
from ntk.services import build_services
from ntk.text import tokenize

_STOP = {"what", "which", "were", "does", "this", "that", "with", "from", "care", "este", "pentru", "fost",
         "cum", "who", "the", "and", "ce", "la", "de", "in", "s-a", "say", "note"}


class HashEmbeddings:
    """Deterministic bag-of-tokens embeddings (LangChain Embeddings interface)."""

    def _vec(self, text: str) -> list[float]:
        v = np.zeros(512, dtype=np.float32)
        for t in tokenize(text):
            v[int(hashlib.md5(t.encode()).hexdigest(), 16) % 512] += 1.0
        return v.tolist()

    def embed_documents(self, texts):
        return [self._vec(t) for t in texts]

    def embed_query(self, text):
        return self._vec(text)


class LeakyEchoGenerator:
    """Worst case: repeats all context verbatim, with valid citations."""

    def generate(self, question, context, lang, strict=False):
        return "\n".join(f"{c.text} [{c.label}]" for c in context)


class GroundedFakeGenerator:
    """Answers only from context that shares >=2 content words with the question, else NO_ANSWER."""

    def generate(self, question, context, lang, strict=False):
        q = {t for t in tokenize(question) if len(t) > 3 and t not in _STOP}
        used = [c for c in context if len(q & set(tokenize(c.text + " " + c.title))) >= 2]
        if not used:
            return NO_ANSWER
        return " ".join(f"{c.text[:200]} [{c.label}]" for c in used)


class ScriptedGenerator:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def generate(self, question, context, lang, strict=False):
        self.calls.append({"strict": strict, "labels": [c.label for c in context]})
        return self.replies.pop(0)


@pytest.fixture(scope="session")
def corpus_dir(tmp_path_factory) -> Path:
    import make_corpus as mc

    out = tmp_path_factory.mktemp("corpus")
    for name, text in mc.DOCS.items():
        (out / name).write_text(text, encoding="utf-8")
    mc.make_pdf(out / mc.PDF_DOC["file"])
    if shutil.which("tesseract"):
        mc.make_scan(out / mc.SCAN_DOC["file"])
    return out


def make_services(tmp_path: Path, corpus_dir: Path, generator=None, use_langgraph=False, store=None):
    settings = Settings(
        users_file=ROOT / "config" / "users.yaml",
        compartments_file=ROOT / "config" / "compartments.yaml",
        data_dir=tmp_path / "data",
        top_k=6,
    )
    svc = build_services(settings, store=store or InMemoryStore(), embeddings=HashEmbeddings(),
                         generator=generator or LeakyEchoGenerator(), use_langgraph=use_langgraph)
    for f in sorted(corpus_dir.iterdir()):
        svc.ingest(f)
    return svc


@pytest.fixture
def services(tmp_path, corpus_dir):
    return make_services(tmp_path, corpus_dir)


@pytest.fixture
def oracle():
    import json

    return json.loads((ROOT / "evals" / "access_matrix.json").read_text(encoding="utf-8"))


@pytest.fixture
def cases():
    import json

    return json.loads((ROOT / "evals" / "cases.json").read_text(encoding="utf-8"))
