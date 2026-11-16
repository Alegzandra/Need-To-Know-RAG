"""Load documents (text, PDF, scanned images via OCR), parse markings, and chunk them safely.

Chunking rule that matters for security: a chunk NEVER mixes paragraphs of different portion
levels. Mixing would force the whole chunk up to the highest level (over-classification hides
releasable information) or, worse, let a lower-level chunk carry higher-level text.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pypdf import PdfReader

from ntk.security.markings import Level, MarkedDocument, parse_document
from ntk.text import detect_language

TEXT_EXT = {".txt", ".md"}
PDF_EXT = {".pdf"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".tif", ".tiff"}
SUPPORTED = TEXT_EXT | PDF_EXT | IMAGE_EXT


@dataclass
class Chunk:
    chunk_id: str
    text: str
    payload: dict[str, Any]


def extract_text(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in TEXT_EXT:
        return path.read_text(encoding="utf-8")
    if ext in PDF_EXT:
        return "\n\n".join((p.extract_text() or "") for p in PdfReader(str(path)).pages)
    if ext in IMAGE_EXT:
        if not shutil.which("tesseract"):
            raise RuntimeError("Scanned documents need Tesseract OCR (apt/brew install tesseract tesseract-ocr-ron)")
        langs = "ron+eng" if "ron" in subprocess.run(["tesseract", "--list-langs"], capture_output=True,
                                                     text=True, check=False).stdout else "eng"
        return subprocess.run(["tesseract", str(path), "stdout", "-l", langs], capture_output=True,
                              text=True, check=True, timeout=120).stdout
    raise ValueError(f"Unsupported file type: {path.name}")


def chunk_document(doc: MarkedDocument, source: str, max_words: int = 160) -> list[Chunk]:
    chunks: list[Chunk] = []
    group: list[str] = []
    group_level: Level | None = None

    def flush() -> None:
        nonlocal group, group_level
        if not group or group_level is None:
            return
        text = "\n\n".join(group)
        idx = len(chunks) + 1
        chunk_id = f"{doc.doc_id}#{idx}"
        chunks.append(Chunk(chunk_id, text, {
            "chunk_id": chunk_id,
            "doc_id": doc.doc_id,
            "title": doc.title,
            "section": idx,
            "level": int(group_level),
            "level_name": group_level.name,
            "compartments": list(doc.banner.compartments),
            "rel_to": list(doc.banner.rel_to),
            "doc_banner": doc.banner.render(),
            "lang": detect_language(text),
            "source": source,
            "content_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "text": text,
        }))
        group, group_level = [], None

    for p in doc.paragraphs:
        words_in_group = sum(len(g.split()) for g in group)
        if group and (p.level != group_level or words_in_group + len(p.text.split()) > max_words):
            flush()
        group.append(p.text)
        group_level = p.level
    flush()
    return chunks


def load_file(path: Path, known_compartments: set[str], owner_nationality: str = "ROU") -> tuple[MarkedDocument, list[Chunk]]:
    raw = extract_text(path)
    doc = parse_document(raw, path.stem, known_compartments, owner_nationality)
    return doc, chunk_document(doc, path.name)


def iter_files(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            out.extend(sorted(f for f in p.rglob("*") if f.suffix.lower() in SUPPORTED))
        elif p.suffix.lower() in SUPPORTED:
            out.append(p)
    return out
