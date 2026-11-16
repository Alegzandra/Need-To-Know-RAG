"""Settings from environment variables (12-factor; the same image runs on a laptop and in Kubernetes)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


@dataclass
class Settings:
    # Model serving: "ollama" for laptops, "openai" for any OpenAI-compatible server such as vLLM
    llm_backend: str = field(default_factory=lambda: _env("NTK_LLM_BACKEND", "ollama"))
    llm_model: str = field(default_factory=lambda: _env("NTK_LLM_MODEL", "gpt-oss:20b"))
    reasoning: str = field(default_factory=lambda: _env("NTK_REASONING", "low"))  # gpt-oss: low|medium|high
    ollama_url: str = field(default_factory=lambda: _env("OLLAMA_BASE_URL", "http://localhost:11434"))
    openai_base_url: str = field(default_factory=lambda: _env("NTK_OPENAI_BASE_URL", "http://localhost:8000/v1"))
    openai_api_key: str = field(default_factory=lambda: _env("NTK_OPENAI_API_KEY", "not-needed"))
    # Multilingual embeddings (Romanian + English in one vector space)
    embed_model: str = field(default_factory=lambda: _env("NTK_EMBED_MODEL", "bge-m3"))

    # Vector store: Qdrant server if NTK_QDRANT_URL is set, otherwise embedded Qdrant on disk
    qdrant_url: str = field(default_factory=lambda: _env("NTK_QDRANT_URL", ""))
    qdrant_api_key: str = field(default_factory=lambda: _env("NTK_QDRANT_API_KEY", ""))
    collection: str = field(default_factory=lambda: _env("NTK_COLLECTION", "ntk_chunks"))

    # Security configuration (owned by the security officer, not by developers)
    users_file: Path = field(default_factory=lambda: Path(_env("NTK_USERS_FILE", "config/users.yaml")))
    compartments_file: Path = field(default_factory=lambda: Path(_env("NTK_COMPARTMENTS_FILE", "config/compartments.yaml")))
    owner_nationality: str = field(default_factory=lambda: _env("NTK_OWNER_NATIONALITY", "ROU"))

    data_dir: Path = field(default_factory=lambda: Path(_env("NTK_DATA_DIR", "data")))
    top_k: int = field(default_factory=lambda: int(_env("NTK_TOP_K", "6")))
    use_langgraph: bool = field(default_factory=lambda: _env("NTK_USE_LANGGRAPH", "1") == "1")

    @property
    def audit_path(self) -> Path:
        return self.data_dir / "audit" / "audit.jsonl"

    @property
    def qdrant_path(self) -> Path:
        return self.data_dir / "qdrant"
