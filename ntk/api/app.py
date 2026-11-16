"""FastAPI service.

Auth: `X-API-Key` header -> user (keys are stored only as SHA-256 hashes in users.yaml).
Roles: analyst -> /v1/query · admin -> /v1/documents · auditor -> /v1/audit*
Errors never expose internals; every query, ingest and denial is in the hash-chained audit log.

Run:  uvicorn ntk.api.app:create_app --factory --host 0.0.0.0 --port 8080
"""

import base64
import binascii
import logging
import tempfile
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

from ntk import __version__
from ntk.ingest.loaders import SUPPORTED
from ntk.security.markings import MarkingError
from ntk.security.policy import User
from ntk.services import Services, build_services

log = logging.getLogger("ntk.api")
MAX_UPLOAD_BYTES = 20 * 1024 * 1024


# --------------------------------------------------------------------------- schemas
class QueryRequest(BaseModel):
    question: str = Field(min_length=3, max_length=2000)


class Citation(BaseModel):
    label: str
    doc_id: str
    title: str
    section: int
    level: str


class QueryResponse(BaseModel):
    trace_id: str
    status: str
    answer: str
    classification: str = Field(description="Derivative classification of this answer")
    citations: list[Citation]
    redactions: int
    warning: str | None = None


class IngestRequest(BaseModel):
    filename: str = Field(max_length=200)
    content_base64: str


class IngestResponse(BaseModel):
    doc_id: str
    title: str
    banner: str
    chunks: int
    portion_levels: list[str]


class MeResponse(BaseModel):
    id: str
    name: str
    clearance: str
    compartments: list[str]
    releasability: list[str]
    roles: list[str]
    pii_access: bool


# --------------------------------------------------------------------------- app
def create_app(services: Services | None = None) -> FastAPI:
    svc = services or build_services()
    app = FastAPI(title="NTK-RAG", version=__version__,
                  description="Need-to-know retrieval-augmented generation for classified multilingual documents")
    api_key = APIKeyHeader(name="X-API-Key", auto_error=False)

    def current_user(key: str | None = Security(api_key)) -> User:
        user = svc.users.authenticate(key)
        if user is None:
            svc.audit.log("auth_failed")
            raise HTTPException(status_code=401, detail="Invalid or missing API key")
        return user

    def require(role: str):
        def checker(user: User = Depends(current_user)) -> User:
            if role not in user.roles:
                svc.audit.log("forbidden", user=user.id, required_role=role)
                raise HTTPException(status_code=403, detail="Forbidden")
            return user
        return checker

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):  # no stack traces to clients
        log.exception("Unhandled error on %s", request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal error"})

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__, "chunks_indexed": svc.retriever.store.count()}

    @app.get("/v1/me", response_model=MeResponse)
    def me(user: User = Depends(current_user)) -> MeResponse:
        return MeResponse(id=user.id, name=user.name, clearance=user.clearance.name,
                          compartments=sorted(user.compartments), releasability=user.rel_tokens,
                          roles=sorted(user.roles), pii_access=user.pii_access)

    @app.post("/v1/query", response_model=QueryResponse)
    def query(req: QueryRequest, user: User = Depends(require("analyst"))) -> QueryResponse:
        return QueryResponse(**svc.ask(req.question, user))

    @app.post("/v1/documents", response_model=IngestResponse, status_code=201)
    def ingest(req: IngestRequest, user: User = Depends(require("admin"))) -> IngestResponse:
        suffix = Path(req.filename).suffix.lower()
        if suffix not in SUPPORTED:
            raise HTTPException(status_code=415, detail=f"Unsupported file type {suffix}")
        try:
            content = base64.b64decode(req.content_base64, validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(status_code=400, detail="content_base64 is not valid base64") from None
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="File too large")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / Path(req.filename).name  # never trust client paths
            path.write_bytes(content)
            try:
                return IngestResponse(**svc.ingest(path, actor=user.id))
            except MarkingError as e:
                svc.audit.log("ingest_rejected", user=user.id, filename=path.name, reason=str(e))
                raise HTTPException(status_code=422, detail=f"Marking error: {e}") from None

    @app.get("/v1/audit")
    def audit_tail(limit: int = 50, user: User = Depends(require("auditor"))) -> list[dict]:
        return svc.audit.tail(max(1, min(limit, 500)))

    @app.get("/v1/audit/verify")
    def audit_verify(user: User = Depends(require("auditor"))) -> dict:
        ok, bad_line = svc.audit.verify()
        return {"intact": ok, "first_bad_line": bad_line}

    return app
