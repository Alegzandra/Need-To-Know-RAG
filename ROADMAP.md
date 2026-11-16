# NTK-RAG roadmap

## Vision

Analysts in security-sensitive organisations get fast, cited answers from their own document
archives in Romanian and English, **without ever seeing information they aren't cleared for**, and
with every answer traceable for auditors.

## Who it's for

| Persona | Job to be done | What they need from NTK-RAG |
|---|---|---|
| **Analyst** | Answer operational questions quickly from large, mixed-language archives | Correct, cited answers in their language; no false refusals; speed |
| **Document control officer** | Get documents into the system with the right markings | Safe ingest that rejects badly marked files; clear errors; re-ingest and versioning |
| **Security auditor** | Prove that access rules held and investigate incidents | Complete, tamper-evident audit trail; evidence that nothing leaked |
| **Platform / ops engineer** | Run it on-premise on limited GPUs | Predictable sizing, monitoring, simple upgrades |

## How we measure success

**Hard guardrails** (release blockers, checked by CI on every change):

| Guardrail | Target |
|---|---|
| Leaked chunks, canary leaks, PII leaks in evals | **0** |
| Audit chain verification | Intact |
| Filter ↔ policy equivalence test | Passing |

**Product metrics** (targets to reach by v0.3; baseline to be measured in v0.2):

| Metric | Why it matters | Target |
|---|---|---|
| Answer correctness on the labelled set | Analysts trust it only if it's right | ≥ 85% |
| Citation validity | Every claim must be traceable | ≥ 95% |
| Correct refusals (nothing visible → refuse) | No hallucinated answers | ≥ 95% |
| False refusals (answer was visible but refused) | Over-cautious systems get abandoned | ≤ 10% |
| Retrieval recall@6 | The answer can't be better than what's retrieved | ≥ 0.90 |
| p50 / p95 latency, single GPU | Usable during real work | ≤ 5 s / ≤ 12 s |

## Now / Next / Later

### Done: v0.1, MVP

- Clearance, compartment and releasability rules enforced **inside Qdrant**, plus a runtime re-check
- Paragraph-level (portion) markings; chunks never mix classification levels
- PII redaction (CNP, IBAN, phone, e-mail) before and after the LLM
- Cited answers with verification and retry; derivative classification; uniform refusal
- Hash-chained audit log; FastAPI with roles; LangGraph pipeline; gpt-oss on Ollama or vLLM
- Leakage evals against an independent oracle with canary codewords; Docker, Compose, Helm, CI

### Now: v0.2, "Trustworthy with real models"

*Outcome: real numbers, real identity, and the two biggest security gaps closed.*

| Item | User value | Done when |
|---|---|---|
| **Baseline evals with real models** | We know where quality actually stands | README table filled for gpt-oss low/medium; results committed |
| **Green CI, including integration tests** | Every change is verified end to end | All 36 tests run and pass in CI; Helm lint and Docker build pass |
| **Single sign-on (OIDC, e.g. Keycloak)** | Clearance comes from the identity system, not a config file | Clearance, compartments and nationality read from signed token claims; invalid tokens → 401 + audit record; leak evals still 0 |
| **Prompt-injection red-team suite** | Documents can't hijack the assistant | ≥ 20 injection cases (RO and EN) in evals; 0 successful injections |
| **Name and location redaction (NER)** | Covers the most common PII the regexes miss | RO/EN person names redacted for users without PII access; precision and recall reported |

### Next: v0.3, "Production-ready at scale"

*Outcome: can run for a real team with more than one replica, and we can size the hardware.*

| Item | User value | Done when |
|---|---|---|
| **Central audit sink** (SIEM / write-once storage) | Auditors get one trustworthy trail; API can scale horizontally | Records shipped to the sink; chain verifiable end to end; Helm `replicaCount > 1` supported |
| **vLLM serving and GPU sizing benchmarks** | Ops can plan hardware with confidence | Throughput, p50/p95 latency and VRAM at 1/8/32 concurrent users, vLLM vs Ollama, published in `docs/` |
| **Observability** | Problems are visible before users report them | OpenTelemetry traces per pipeline step; dashboards for latency, refusal rate, citation failures |
| **Reranker after hybrid retrieval** | Better answers on hard questions | recall@6 and answer correctness improve by a measured margin with ≤ 20% latency cost |
| **Larger labelled eval set** | Decisions based on evidence, not anecdotes | ≥ 100 questions × 5 users, RO/EN, reviewed by a second person |

### Later: v0.4+, "Analyst experience and deeper analysis"

| Item | User value |
|---|---|
| **Web UI** with classification banners, source viewer and feedback buttons | Analysts can use it without the API; feedback feeds the eval set |
| **Multi-turn conversations with a classification "high-water mark"** | Follow-up questions, while the session is marked at the highest level seen so far |
| **GraphRAG module** with edge-level labels | Multi-hop questions ("what connects X and Y?") without leaking secret links |
| **Aggregation risk checks** | Flags answers that combine many low-level facts into something more sensitive |
| **Document versioning and withdrawal** | Superseded or withdrawn documents stop appearing in answers immediately |

## Why this order

1. **Measure before optimising.** v0.2 starts with real-model baselines; without them, every later
   improvement is a guess.
2. **Close security gaps before adding features.** Identity (OIDC) and prompt injection are the
   most likely ways a real deployment would fail, so they come before UI or GraphRAG.
3. **Unblock scale only when it's needed.** The central audit sink comes in v0.3, because it's the
   one thing preventing more than one replica.
4. **Features that need evidence come last.** GraphRAG and aggregation checks are valuable, but
   only worth building once the core is measured and trusted.

## Release gates (definition of done for every release)

- All guardrails at target (0 leaks, audit chain intact, equivalence test passing)
- Product metrics measured and reported, even when below target
- README and this roadmap updated
- No new dependency without a reason recorded in the pull request

## Risks and open questions

| Risk | Impact | Mitigation |
|---|---|---|
| Small models misread Romanian legal or military terminology | Wrong answers, false refusals | Romanian-focused eval cases; compare gpt-oss with a stronger model on vLLM |
| Aggregation: harmless facts combine into a sensitive picture | Leak not caught by per-chunk rules | Research spike in v0.4; human review for derived products until then |
| GPU availability on-premise | Latency targets missed | Benchmarks in v0.3; `reasoning=low` and smaller context as fallbacks |
| Over-refusal | Analysts stop using the tool | Track false-refusal rate as a first-class metric |

## Non-goals

- **Making classification decisions.** NTK-RAG enforces markings; it doesn't decide them.
- **Internet access or external APIs.** Everything runs on-premise.
- **Fine-tuning models on classified data.** Retrieval keeps sensitive data out of model weights.
- **Real national or NATO marking rules.** The scheme is simplified for demonstration.
