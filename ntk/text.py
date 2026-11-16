"""Text utilities shared by ingestion and retrieval: diacritic folding, tokenization, RO/EN detection."""

from __future__ import annotations

import re
import unicodedata

_TOKEN = re.compile(r"[a-z0-9]+(?:[-.][a-z0-9]+)*")

_RO_STOP = {
    "si", "sau", "este", "sunt", "care", "pentru", "din", "intr", "intre", "cu", "la", "de", "pe", "nu", "ce",
    "fost", "acest", "aceasta", "unei", "unui", "dupa", "catre", "privind", "cand", "unde", "cine", "cum",
    "au", "ai", "fie", "mai", "vor", "fi", "doar", "le", "lor", "noi", "sa", "ca", "s-a", "a", "o", "un", "lui",
}
_EN_STOP = {
    "the", "and", "or", "is", "are", "which", "for", "from", "with", "at", "of", "on", "not", "what", "was",
    "this", "that", "after", "towards", "regarding", "when", "where", "who", "how", "were", "be", "been",
    "a", "an", "to", "in", "by", "it", "its", "has", "have", "did", "do", "does",
}
_RO_CHARS = set("ăâîșşțţĂÂÎȘŞȚŢ")


def fold(text: str) -> str:
    """Lowercase and strip diacritics: 'Vibrațiile' -> 'vibratiile'."""
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(c for c in nfkd if not unicodedata.combining(c)).lower()


def tokenize(text: str) -> list[str]:
    """Diacritic-folded tokens; hyphenated codes are kept whole and also split ('S-17' -> 's-17', 's', '17')."""
    out: list[str] = []
    for tok in _TOKEN.findall(fold(text)):
        out.append(tok)
        if "-" in tok or "." in tok:
            out.extend(p for p in re.split(r"[-.]", tok) if p)
    return out


def detect_language(text: str) -> str:
    """Tiny RO/EN identifier. Robust to Romanian typed WITHOUT diacritics, which is how
    most people type on phones: it relies on function words, with diacritics only as a bonus."""
    words = re.findall(r"[a-z]+(?:-[a-z]+)?", fold(text))
    ro = sum(w in _RO_STOP for w in words) + 2 * sum(c in _RO_CHARS for c in text)
    en = sum(w in _EN_STOP for w in words)
    return "ro" if ro > en else "en"
