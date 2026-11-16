"""Classification markings: banner lines and paragraph portion markings.

Banner (first line of a document), '//'-separated:
    CONFIDENTIAL//ORION//REL TO ROU, NATO
    level      compartment(s)   releasability

Portion markings at the start of paragraphs:  (U) (R) (C) (S)
A paragraph without a portion marking inherits the banner level (fail-safe). A portion
marked ABOVE the banner is a marking error and the document is rejected at ingest.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum

from ntk.text import fold


class Level(IntEnum):
    UNCLASSIFIED = 0
    RESTRICTED = 1
    CONFIDENTIAL = 2
    SECRET = 3

    @property
    def short(self) -> str:
        return "URCS"[self.value]


# English names, short forms and Romanian equivalents (matched after diacritic folding)
_ALIASES: dict[str, Level] = {
    "unclassified": Level.UNCLASSIFIED, "u": Level.UNCLASSIFIED, "neclasificat": Level.UNCLASSIFIED,
    "nesecret": Level.UNCLASSIFIED,
    "restricted": Level.RESTRICTED, "r": Level.RESTRICTED, "restrictionat": Level.RESTRICTED,
    "secret de serviciu": Level.RESTRICTED,
    "confidential": Level.CONFIDENTIAL, "c": Level.CONFIDENTIAL,
    "secret": Level.SECRET, "s": Level.SECRET, "strict secret": Level.SECRET,
}

_PORTION = re.compile(r"^\s*\((U|R|C|S)\)\s*", re.IGNORECASE)


class MarkingError(ValueError):
    pass


def parse_level(token: str) -> Level:
    key = " ".join(fold(token).split())
    if key not in _ALIASES:
        raise MarkingError(f"Unknown classification level '{token}'")
    return _ALIASES[key]


@dataclass(frozen=True)
class Banner:
    level: Level
    compartments: tuple[str, ...] = ()
    rel_to: tuple[str, ...] = ()

    def render(self) -> str:
        parts = [self.level.name, *self.compartments]
        if self.rel_to:
            parts.append("REL TO " + ", ".join(self.rel_to))
        return "//".join(parts)


def looks_like_banner(line: str) -> bool:
    head = line.split("//")[0].strip()
    try:
        parse_level(head)
        return True
    except MarkingError:
        return False


def parse_banner(line: str, known_compartments: set[str], owner_nationality: str = "ROU") -> Banner:
    tokens = [t.strip() for t in line.strip().split("//") if t.strip()]
    if not tokens:
        raise MarkingError("Empty banner")
    level = parse_level(tokens[0])
    compartments: list[str] = []
    rel_to: list[str] = []
    for tok in tokens[1:]:
        up = tok.upper()
        if up.startswith("REL TO"):
            rel_to = [x.strip().upper() for x in up[len("REL TO"):].split(",") if x.strip()]
        else:
            if up not in known_compartments:
                # fail closed: an unknown compartment cannot be enforced, so the document is rejected
                raise MarkingError(f"Compartment '{up}' is not declared in compartments.yaml")
            compartments.append(up)
    # Without an explicit REL TO, a document is national-only.
    return Banner(level, tuple(sorted(compartments)), tuple(rel_to or [owner_nationality]))


@dataclass
class Paragraph:
    text: str
    level: Level


@dataclass
class MarkedDocument:
    doc_id: str
    title: str
    banner: Banner
    paragraphs: list[Paragraph] = field(default_factory=list)


def parse_document(
    raw: str, default_doc_id: str, known_compartments: set[str], owner_nationality: str = "ROU"
) -> MarkedDocument:
    lines = raw.strip().splitlines()
    if not lines or not looks_like_banner(lines[0]):
        raise MarkingError(f"{default_doc_id}: first line must be a classification banner")
    banner = parse_banner(lines[0], known_compartments, owner_nationality)
    doc_id, title = default_doc_id, default_doc_id
    body_lines: list[str] = []
    for line in lines[1:]:
        low = fold(line.strip())
        if low.startswith("doc-id:"):
            doc_id = line.split(":", 1)[1].strip()
        elif low.startswith(("title:", "titlu:")):
            title = line.split(":", 1)[1].strip()
        elif ("//" in line and looks_like_banner(line)) or fold(line.strip()) == fold(lines[0].strip()):
            continue  # repeated banner (e.g. page footer)
        else:
            body_lines.append(line)

    paragraphs: list[Paragraph] = []
    for block in re.split(r"\n\s*\n", "\n".join(body_lines)):
        text = " ".join(block.split())
        if not text:
            continue
        m = _PORTION.match(text)
        level = parse_level(m.group(1)) if m else banner.level
        if level > banner.level:
            raise MarkingError(f"{doc_id}: portion ({level.short}) exceeds banner {banner.level.name}")
        paragraphs.append(Paragraph(_PORTION.sub("", text), level))
    return MarkedDocument(doc_id, title, banner, paragraphs)
