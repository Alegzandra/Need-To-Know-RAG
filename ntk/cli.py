"""CLI: `ntk ingest | ask | users | eval | audit | serve | hash-key`."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from ntk.config import Settings
from ntk.security.policy import hash_key


def _services(args):
    from ntk.services import build_services

    return build_services(Settings())


def cmd_ingest(args) -> int:
    from ntk.ingest.loaders import iter_files
    from ntk.security.markings import MarkingError

    svc = _services(args)
    files = iter_files([Path(p) for p in args.paths])
    rc = 0
    for f in files:
        try:
            r = svc.ingest(f, actor="cli")
            print(f"  ✓ {f.name}: {r['doc_id']} [{r['banner']}] {r['chunks']} chunks, portions {r['portion_levels']}")
        except MarkingError as e:
            rc = 1
            svc.audit.log("ingest_rejected", user="cli", filename=f.name, reason=str(e))
            print(f"  ✗ {f.name}: REJECTED — {e}")
    print(f"Indexed chunks: {svc.retriever.store.count()}")
    return rc


def cmd_ask(args) -> int:
    svc = _services(args)
    user = svc.users.users.get(args.user)
    if user is None:
        print(f"Unknown user '{args.user}'. Known: {', '.join(svc.users.users)}")
        return 2
    r = svc.ask(args.question, user)
    print(f"\n[{r['classification']}]  ({user.id}, clearance {user.clearance.name})\n")
    print(r["answer"])
    for c in r["citations"]:
        print(f"  {c['label']}: {c['doc_id']} §{c['section']} — {c['title']} ({c['level']})")
    if r["redactions"]:
        print(f"  {r['redactions']} PII item(s) redacted")
    if r.get("warning"):
        print(f"  ⚠ {r['warning']}")
    return 0


def cmd_users(args) -> int:
    from ntk.security.policy import UserDirectory

    for u in UserDirectory.from_yaml(Settings().users_file).users.values():
        print(f"{u.id:10} {u.clearance.name:13} comp={sorted(u.compartments) or '-'} rel={u.rel_tokens} "
              f"roles={sorted(u.roles)} pii={u.pii_access}")
    return 0


def cmd_eval(args) -> int:
    from ntk.evals.runner import run_generation_eval, run_retrieval_eval

    svc = _services(args)
    if args.kind in ("retrieval", "all"):
        run_retrieval_eval(svc, Path(args.cases), Path(args.access), Path(args.out))
    if args.kind in ("generation", "all"):
        run_generation_eval(svc, Path(args.cases), Path(args.access), Path(args.out))
    return 0


def cmd_audit(args) -> int:
    from ntk.security.audit import AuditLog

    log = AuditLog(Settings().audit_path)
    if args.action == "verify":
        ok, line = log.verify()
        print("Audit chain intact." if ok else f"TAMPERING DETECTED at line {line}.")
        return 0 if ok else 1
    for rec in log.tail(args.n):
        print(json.dumps({k: rec[k] for k in rec if k not in ("hash", "prev_hash")}, ensure_ascii=False))
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    uvicorn.run("ntk.api.app:create_app", factory=True, host=args.host, port=args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING)
    p = argparse.ArgumentParser(prog="ntk", description="Need-to-know RAG")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("ingest", help="parse markings, chunk, embed and index documents")
    sp.add_argument("paths", nargs="+")
    sp.set_defaults(fn=cmd_ingest)

    sp = sub.add_parser("ask", help="ask a question as a given user")
    sp.add_argument("--user", required=True)
    sp.add_argument("question")
    sp.set_defaults(fn=cmd_ask)

    sub.add_parser("users", help="list users and their access").set_defaults(fn=cmd_users)

    sp = sub.add_parser("eval", help="run evaluations")
    sp.add_argument("kind", choices=["retrieval", "generation", "all"])
    sp.add_argument("--cases", default="evals/cases.json")
    sp.add_argument("--access", default="evals/access_matrix.json")
    sp.add_argument("--out", default="evals/results")
    sp.set_defaults(fn=cmd_eval)

    sp = sub.add_parser("audit", help="show or verify the audit log")
    sp.add_argument("action", choices=["tail", "verify"])
    sp.add_argument("-n", type=int, default=20)
    sp.set_defaults(fn=cmd_audit)

    sp = sub.add_parser("serve", help="run the API")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8080)
    sp.set_defaults(fn=cmd_serve)

    sp = sub.add_parser("hash-key", help="hash an API key for users.yaml")
    sp.add_argument("key")
    sp.set_defaults(fn=lambda a: print(hash_key(a.key)) or 0)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
