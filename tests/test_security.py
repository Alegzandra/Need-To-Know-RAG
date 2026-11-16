import itertools
import json

import pytest

from ntk.security.audit import AuditLog
from ntk.security.markings import Level, MarkingError, parse_banner, parse_document
from ntk.security.pii import cnp_control_digit, is_valid_cnp, is_valid_iban, redact
from ntk.security.policy import AccessFilter, User, can_access

COMPS = {"ORION", "HALCYON"}


# --------------------------------------------------------------------------- markings
def test_banner_parsing_with_romanian_aliases_and_defaults():
    b = parse_banner("CONFIDENTIAL//ORION//REL TO ROU, NATO", COMPS)
    assert (b.level, b.compartments, b.rel_to) == (Level.CONFIDENTIAL, ("ORION",), ("ROU", "NATO"))
    assert parse_banner("Secret de serviciu", COMPS).level == Level.RESTRICTED
    assert parse_banner("NESECRET", COMPS).rel_to == ("ROU",)  # no REL TO -> national only


def test_unknown_compartment_fails_closed():
    with pytest.raises(MarkingError, match="not declared"):
        parse_banner("SECRET//PHOENIX", COMPS)


def test_portion_markings_and_inheritance():
    doc = parse_document("CONFIDENTIAL\nTITLE: t\n\n(U) open part\n\nunmarked part\n\n(R) restricted part", "D1", COMPS)
    assert [p.level for p in doc.paragraphs] == [Level.UNCLASSIFIED, Level.CONFIDENTIAL, Level.RESTRICTED]
    assert doc.paragraphs[0].text == "open part"


def test_portion_above_banner_is_rejected():
    with pytest.raises(MarkingError, match="exceeds banner"):
        parse_document("RESTRICTED\n\n(S) too secret", "D2", COMPS)


def test_missing_banner_is_rejected():
    with pytest.raises(MarkingError, match="banner"):
        parse_document("Just some text", "D3", COMPS)


# --------------------------------------------------------------------------- policy
def _user(level, comps=(), nat="ROU", groups=()):
    return User("u", "U", level, frozenset(comps), nat, frozenset(groups))


def test_can_access_rules():
    p = {"level": 2, "compartments": ["ORION"], "rel_to": ["ROU", "NATO"]}
    assert can_access(_user(Level.SECRET, ["ORION"]), p) == (True, "ok")
    assert can_access(_user(Level.RESTRICTED, ["ORION"]), p)[1] == "clearance"
    assert can_access(_user(Level.SECRET), p)[1] == "need_to_know"
    assert can_access(_user(Level.SECRET, ["ORION"], "DEU"), p)[1] == "releasability"
    assert can_access(_user(Level.SECRET, ["ORION"], "DEU", ["NATO"]), p)[0]
    assert can_access(_user(Level.SECRET, ["ORION"]), {"level": 0})[1] == "malformed_metadata"


def test_access_filter_agrees_with_policy_exhaustively():
    """The filter pushed into the vector DB must be equivalent to the policy for every combination."""
    comps_all = {"ORION", "HALCYON"}
    payloads = [{"level": lv, "compartments": list(c), "rel_to": list(r)}
                for lv in range(4)
                for c in [(), ("ORION",), ("HALCYON",), ("ORION", "HALCYON")]
                for r in [("ROU",), ("ROU", "NATO"), ("NATO",)]]
    users = [_user(Level(lv), c, nat, g)
             for lv in range(4)
             for c in [(), ("ORION",), ("ORION", "HALCYON")]
             for nat, g in [("ROU", ()), ("DEU", ("NATO",)), ("FRA", ())]]
    for u, p in itertools.product(users, payloads):
        assert AccessFilter.for_user(u, comps_all).matches(p) == can_access(u, p)[0], (u, p)


# --------------------------------------------------------------------------- PII
def test_cnp_validation():
    good = "190031240012" + str(cnp_control_digit("190031240012"))
    assert is_valid_cnp(good)
    assert not is_valid_cnp(good[:-1] + str((int(good[-1]) + 1) % 10))  # wrong control digit
    assert not is_valid_cnp("1901332400121")  # 32nd day
    assert not is_valid_cnp("9900312400122")  # invalid sex/century digit


def test_iban_validation():
    assert is_valid_iban("RO49 AAAA 1B31 0075 9384 0000")  # standard published example
    assert not is_valid_iban("RO48 AAAA 1B31 0075 9384 0000")


def test_redaction_and_no_false_positives():
    cnp = "190031240012" + str(cnp_control_digit("190031240012"))
    text = (f"Suspect CNP {cnp}, cont RO49 AAAA 1B31 0075 9384 0000, tel 0799 000 123, "
            "mail a.b@x.example. Invoice no. 1234567890123, total 184.000 lei.")
    r = redact(text)
    assert dict(r.counts) == {"CNP": 1, "IBAN": 1, "PHONE": 1, "EMAIL": 1}
    assert cnp not in r.text and "1234567890123" in r.text  # invalid CNP-shaped number is kept


# --------------------------------------------------------------------------- audit
def test_audit_chain_detects_tampering(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(5):
        log.log("query", user="ana", n=i)
    assert log.verify() == (True, None)
    last = log.tail(1)[0]["hash"]
    assert AuditLog(tmp_path / "a.jsonl").log("x")["prev_hash"] == last  # chain survives a restart
    assert log.verify() == (True, None)

    lines = (tmp_path / "a.jsonl").read_text().splitlines()
    rec = json.loads(lines[2])
    rec["user"] = "mallory"
    lines[2] = json.dumps(rec)
    (tmp_path / "a.jsonl").write_text("\n".join(lines) + "\n")
    assert log.verify() == (False, 3)


def test_api_key_authentication():
    from conftest import ROOT

    from ntk.security.policy import UserDirectory

    d = UserDirectory.from_yaml(ROOT / "config" / "users.yaml")
    assert d.authenticate("demo-elena").compartments == frozenset({"ORION"})
    assert d.authenticate("wrong") is None and d.authenticate(None) is None
