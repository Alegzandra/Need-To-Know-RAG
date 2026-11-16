"""Access-control policy: users, need-to-know rules and the store-agnostic access filter.

A user may see a chunk only if ALL of these hold (mandatory access control):
  1. clearance  >= chunk level
  2. compartments of the chunk ⊆ user's compartments (need-to-know)
  3. releasability: the user's nationality or one of their groups is in the chunk's REL TO list

The same rules are expressed twice, on purpose:
  - as an AccessFilter pushed INTO the vector database (so forbidden chunks are never ranked), and
  - as `can_access`, re-checked on every returned chunk (defence in depth; a mismatch is logged
    as a security event). Missing or malformed metadata always means "deny".
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ntk.security.markings import Level, parse_level


@dataclass(frozen=True)
class User:
    id: str
    name: str
    clearance: Level
    compartments: frozenset[str] = frozenset()
    nationality: str = "ROU"
    groups: frozenset[str] = frozenset()
    roles: frozenset[str] = frozenset({"analyst"})
    pii_access: bool = False

    @property
    def rel_tokens(self) -> list[str]:
        return sorted({self.nationality, *self.groups})


def can_access(user: User, payload: dict[str, Any]) -> tuple[bool, str]:
    try:
        level = int(payload["level"])
        compartments = set(payload["compartments"])
        rel_to = set(payload["rel_to"])
    except (KeyError, TypeError, ValueError):
        return False, "malformed_metadata"
    if level > user.clearance:
        return False, "clearance"
    if not compartments <= user.compartments:
        return False, "need_to_know"
    if not rel_to & set(user.rel_tokens):
        return False, "releasability"
    return True, "ok"


@dataclass(frozen=True)
class AccessFilter:
    """Store-agnostic description of what a user may retrieve."""

    max_level: int
    forbidden_compartments: tuple[str, ...]
    rel_tokens: tuple[str, ...]

    @classmethod
    def for_user(cls, user: User, all_compartments: set[str]) -> AccessFilter:
        return cls(int(user.clearance), tuple(sorted(all_compartments - user.compartments)), tuple(user.rel_tokens))

    def matches(self, payload: dict[str, Any]) -> bool:
        try:
            return (
                int(payload["level"]) <= self.max_level
                and not set(payload["compartments"]) & set(self.forbidden_compartments)
                and bool(set(payload["rel_to"]) & set(self.rel_tokens))
            )
        except (KeyError, TypeError, ValueError):
            return False


def hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


@dataclass
class UserDirectory:
    users: dict[str, User]
    key_hashes: dict[str, str] = field(default_factory=dict)  # sha256(api key) -> user id

    @classmethod
    def from_yaml(cls, path: Path) -> UserDirectory:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        users, keys = {}, {}
        for u in data["users"]:
            user = User(
                id=u["id"], name=u["name"], clearance=parse_level(u["clearance"]),
                compartments=frozenset(c.upper() for c in u.get("compartments", [])),
                nationality=u.get("nationality", "ROU").upper(),
                groups=frozenset(g.upper() for g in u.get("groups", [])),
                roles=frozenset(u.get("roles", ["analyst"])), pii_access=bool(u.get("pii_access", False)),
            )
            users[user.id] = user
            if u.get("api_key_sha256"):
                keys[u["api_key_sha256"]] = user.id
        return cls(users, keys)

    def authenticate(self, api_key: str | None) -> User | None:
        if not api_key:
            return None
        digest = hash_key(api_key)
        for stored, uid in self.key_hashes.items():
            if hmac.compare_digest(stored, digest):
                return self.users[uid]
        return None


def load_compartments(path: Path) -> set[str]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return {c.upper() for c in data.get("compartments", [])}
