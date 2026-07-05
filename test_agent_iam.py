#!/usr/bin/env python3
"""
Tests for the Agent IAM authorization gate. Pure stdlib unittest, deterministic.
Run:  python3 -m unittest test_agent_iam -v
"""

import unittest

from seam7_delegation import Cap, mint_root, attenuate
from agent_iam import (
    TrustTier, ProvenanceRecord, Manifest, Tool, Request,
    SpendLedger, InMemorySink, authorize,
)

KEY = b"verifier-root-key"
T0 = 1_000_000.0
D = 4


def _child(caps=Cap.READ | Cap.ENRICH | Cap.WRITE, budget=100.0, ttl=T0 + 300):
    root = mint_root(KEY, "principal:root", Cap.ALL, ttl_expires=T0 + 3600,
                     budget=budget, difficulty=D)
    return attenuate(root, caps=caps, exp=ttl, budget=budget, actor="agent:worker")


VOUCHED = Manifest([ProvenanceRecord("db-of-record", TrustTier.ORG_ATTESTED)])
UNVOUCHED = Manifest([ProvenanceRecord("slack-scrape", TrustTier.UNATTESTED)])
WRITE_TOOL = Tool("write_record", Cap.WRITE, TrustTier.ORG_ATTESTED, est_cost=1.0)


class TestHappyPath(unittest.TestCase):
    def test_allow_when_capable_vouched_purposeful_and_funded(self):
        d = authorize(Request(_child(), WRITE_TOOL, Cap.WRITE, VOUCHED, T0),
                      KEY, SpendLedger())
        self.assertTrue(d.allowed)
        self.assertEqual(d.code, "ALLOW")
        self.assertEqual(d.claims.accountable_root, "principal:root")
        self.assertEqual(d.claims.actor, "agent:worker")


class TestRBAC(unittest.TestCase):
    def test_deny_capability_never_granted(self):
        child = _child(caps=Cap.READ)                 # no WRITE
        d = authorize(Request(child, WRITE_TOOL, Cap.WRITE, VOUCHED, T0),
                      KEY, SpendLedger())
        self.assertFalse(d.allowed)
        self.assertEqual(d.code, "CAPABILITY")


class TestPBAC(unittest.TestCase):
    def test_deny_intent_drift(self):
        # capable of WRITE, but declares an ENRICH purpose then calls the write tool
        d = authorize(Request(_child(), WRITE_TOOL, Cap.ENRICH, VOUCHED, T0),
                      KEY, SpendLedger())
        self.assertFalse(d.allowed)
        self.assertEqual(d.code, "PURPOSE")

    def test_deny_purpose_exceeding_grant(self):
        child = _child(caps=Cap.READ | Cap.WRITE)     # no DELETE granted
        d = authorize(Request(child, WRITE_TOOL, Cap.WRITE | Cap.DELETE, VOUCHED, T0),
                      KEY, SpendLedger())
        self.assertFalse(d.allowed)
        self.assertEqual(d.code, "PURPOSE")


class TestABACProvenance(unittest.TestCase):
    """The original question: act only on vouched-for data."""

    def test_deny_on_unvouched_data(self):
        d = authorize(Request(_child(), WRITE_TOOL, Cap.WRITE, UNVOUCHED, T0),
                      KEY, SpendLedger())
        self.assertFalse(d.allowed)
        self.assertEqual(d.code, "PROVENANCE")

    def test_allow_after_reanchoring_to_vouched(self):
        d = authorize(Request(_child(), WRITE_TOOL, Cap.WRITE, VOUCHED, T0),
                      KEY, SpendLedger())
        self.assertTrue(d.allowed)

    def test_weakest_link_governs(self):
        # one ORG_ATTESTED + one UNATTESTED source => min tier is UNATTESTED => deny
        mixed = Manifest([ProvenanceRecord("db", TrustTier.ORG_ATTESTED),
                          ProvenanceRecord("scrape", TrustTier.UNATTESTED)])
        d = authorize(Request(_child(), WRITE_TOOL, Cap.WRITE, mixed, T0),
                      KEY, SpendLedger())
        self.assertFalse(d.allowed)
        self.assertEqual(d.code, "PROVENANCE")

    def test_empty_lineage_is_unattested(self):
        d = authorize(Request(_child(), WRITE_TOOL, Cap.WRITE, Manifest([]), T0),
                      KEY, SpendLedger())
        self.assertFalse(d.allowed)
        self.assertEqual(d.code, "PROVENANCE")

    def test_human_vouched_required_for_delete(self):
        child = _child(caps=Cap.READ | Cap.DELETE)
        delete = Tool("delete_record", Cap.DELETE, TrustTier.HUMAN_VOUCHED, est_cost=1.0)
        # ORG_ATTESTED is not enough for a HUMAN_VOUCHED-floor tool
        d = authorize(Request(child, delete, Cap.DELETE, VOUCHED, T0), KEY, SpendLedger())
        self.assertFalse(d.allowed)
        self.assertEqual(d.code, "PROVENANCE")
        # a human-vouched source clears it
        human = Manifest([ProvenanceRecord("supervisor-signoff", TrustTier.HUMAN_VOUCHED)])
        d = authorize(Request(child, delete, Cap.DELETE, human, T0), KEY, SpendLedger())
        self.assertTrue(d.allowed)


class TestBudget(unittest.TestCase):
    def test_deny_when_budget_exhausted(self):
        ledger = SpendLedger()
        child = _child(budget=2.5)                     # ceiling 2.5, each write costs 1.0
        req = Request(child, WRITE_TOOL, Cap.WRITE, VOUCHED, T0)
        self.assertTrue(authorize(req, KEY, ledger).allowed)   # spent 1.0
        self.assertTrue(authorize(req, KEY, ledger).allowed)   # spent 2.0
        d = authorize(req, KEY, ledger)                        # 2.0 + 1.0 > 2.5
        self.assertFalse(d.allowed)
        self.assertEqual(d.code, "BUDGET")

    def test_denied_calls_do_not_charge(self):
        ledger = SpendLedger()
        # a PROVENANCE denial must not consume budget
        authorize(Request(_child(budget=1.0), WRITE_TOOL, Cap.WRITE, UNVOUCHED, T0),
                  KEY, ledger)
        self.assertEqual(ledger.spent("principal:root"), 0.0)


class TestIdentity(unittest.TestCase):
    def test_deny_expired_token(self):
        child = _child(ttl=T0 + 50)
        d = authorize(Request(child, WRITE_TOOL, Cap.WRITE, VOUCHED, T0 + 100),
                      KEY, SpendLedger())
        self.assertFalse(d.allowed)
        self.assertEqual(d.code, "IDENTITY")

    def test_deny_wrong_verifier_key(self):
        d = authorize(Request(_child(), WRITE_TOOL, Cap.WRITE, VOUCHED, T0),
                      b"attacker-key", SpendLedger())
        self.assertFalse(d.allowed)
        self.assertEqual(d.code, "IDENTITY")


class TestTriageEmission(unittest.TestCase):
    def test_denial_emits_packet_allow_does_not(self):
        sink = InMemorySink()
        authorize(Request(_child(), WRITE_TOOL, Cap.WRITE, UNVOUCHED, T0),
                  KEY, SpendLedger(), sink)          # deny
        authorize(Request(_child(), WRITE_TOOL, Cap.WRITE, VOUCHED, T0),
                  KEY, SpendLedger(), sink)          # allow
        self.assertEqual(len(sink.packets), 1)
        p = sink.packets[0]
        self.assertEqual(p["code"], "PROVENANCE")
        self.assertEqual(p["accountable_root"], "principal:root")
        self.assertTrue(p["incident_id"].startswith("inc-"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
