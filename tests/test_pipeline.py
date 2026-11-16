import pytest
from conftest import GroundedFakeGenerator, ScriptedGenerator, make_services

from ntk.evals.runner import generation_metrics
from ntk.pipeline.steps import REFUSAL


def test_worst_case_llm_cannot_leak_canaries_or_pii(services, cases, oracle):
    """LeakyEchoGenerator repeats all context verbatim. Zero leaks => security does not depend on the LLM."""
    m = generation_metrics(services, cases, oracle)
    assert m["canary_leaks"] == 0
    assert m["pii_leaks"] == 0
    assert m["pairs_evaluated"] == len(cases) * len(oracle["users"])


def test_refusals_and_content_with_grounded_generator(tmp_path, corpus_dir, cases, oracle):
    svc = make_services(tmp_path, corpus_dir, generator=GroundedFakeGenerator())
    m = generation_metrics(svc, cases, oracle)
    assert m["canary_leaks"] == 0 and m["pii_leaks"] == 0
    assert m["refusal_accuracy"] == 1.0
    assert m["citation_valid_rate"] == 1.0


def test_uniform_refusal_does_not_reveal_existence(tmp_path, corpus_dir):
    svc = make_services(tmp_path, corpus_dir, generator=GroundedFakeGenerator())
    mihai = svc.users.users["mihai"]
    exists = svc.ask("What does the HALCYON source protection note say?", mihai)  # exists, not cleared
    missing = svc.ask("What does the PELICAN logistics annex say?", mihai)  # does not exist
    strip = lambda r: {k: v for k, v in r.items() if k != "trace_id"}
    assert strip(exists) == strip(missing)
    assert exists["answer"] == REFUSAL["en"] and exists["classification"] == "UNCLASSIFIED"


def test_derivative_classification(services):
    elena, mihai = services.users.users["elena"], services.users.users["mihai"]
    q = "Who is behind the drone flights near substation S-17 and the Port of Calvara? VARTA"
    r_elena = services.ask(q, elena)
    assert "ORN-2026-002" in {c["doc_id"] for c in r_elena["citations"]}
    assert r_elena["classification"] == "SECRET"
    assert services.ask(q, mihai)["classification"] in {"UNCLASSIFIED", "RESTRICTED", "CONFIDENTIAL"}


def test_pii_redacted_for_unprivileged_but_visible_for_privileged(services):
    q = "În ce cont a fost transferată plata frauduloasă de la Apa Nord?"
    assert "ZZZZ" not in services.ask(q, services.users.users["mihai"])["answer"]
    assert "ZZZZ" in services.ask(q, services.users.users["elena"])["answer"]


def test_model_reintroduced_pii_is_scrubbed(tmp_path, corpus_dir):
    gen = ScriptedGenerator(["The account is RO49 AAAA 1B31 0075 9384 0000 [S1]."])
    svc = make_services(tmp_path, corpus_dir, generator=gen)
    r = svc.ask("Cum a fost compromis operatorul de apă Apa Nord?", svc.users.users["mihai"])
    assert "[IBAN REDACTED]" in r["answer"] and r["redactions"] >= 1


def test_citation_retry_then_success(tmp_path, corpus_dir):
    gen = ScriptedGenerator(["An answer with no citation.", "Now cited [S1]."])
    svc = make_services(tmp_path, corpus_dir, generator=gen)
    r = svc.ask("What weaknesses were found in the Calvara port perimeter?", svc.users.users["mihai"])
    assert r["status"] == "ok" and r["warning"] is None
    assert [c["strict"] for c in gen.calls] == [False, True]


def test_hallucinated_labels_lead_to_refusal(tmp_path, corpus_dir):
    gen = ScriptedGenerator(["Invented [S42].", "Still invented [S99]."])
    svc = make_services(tmp_path, corpus_dir, generator=gen)
    r = svc.ask("What weaknesses were found in the Calvara port perimeter?", svc.users.users["mihai"])
    assert r["status"] == "no_answer"


def test_non_analyst_cannot_query_and_queries_are_audited(services):
    with pytest.raises(PermissionError):
        services.ask("anything", services.users.users["auditor"])
    services.ask("What weaknesses were found in the Calvara port perimeter?", services.users.users["klaus"])
    rec = [r for r in services.audit.tail(5) if r["event"] == "query"][-1]
    assert rec["user"] == "klaus" and rec["retrieved"] and services.audit.verify()[0]
