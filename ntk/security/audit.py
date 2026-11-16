"""Tamper-evident audit log: append-only JSONL where every record carries the hash of the previous one.

Editing or deleting any past record breaks the chain, and `verify()` reports the first broken line.
In production, ship records to a WORM store / SIEM as well; the hash chain makes local tampering visible.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(prev_hash: str, record: dict[str, Any]) -> str:
    canonical = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        last = self.path.read_text(encoding="utf-8").strip().splitlines()[-1]
        return json.loads(last)["hash"]

    def log(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            record = {
                "id": uuid.uuid4().hex,
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "event": event,
                **fields,
                "prev_hash": self._last_hash,
            }
            record["hash"] = _digest(self._last_hash, record)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            self._last_hash = record["hash"]
            return record

    def tail(self, n: int = 50) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(x) for x in self.path.read_text(encoding="utf-8").strip().splitlines()[-n:] if x]

    def verify(self) -> tuple[bool, int | None]:
        """Returns (ok, first_bad_line_number)."""
        if not self.path.exists():
            return True, None
        prev = GENESIS
        for i, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
            rec = json.loads(line)
            stored = rec.pop("hash", None)
            if rec.get("prev_hash") != prev or _digest(prev, rec) != stored:
                return False, i
            prev = stored
        return True, None
