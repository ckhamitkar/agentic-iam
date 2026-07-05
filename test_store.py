#!/usr/bin/env python3
"""
Tests for the SQLite persistence adapter. Pure stdlib unittest, deterministic.
Run:  python3 -m unittest test_store -v
"""

import os
import tempfile
import unittest

from seam7_delegation import Cap, mint_root, attenuate
from agent_iam import TrustTier, ProvenanceRecord, Manifest, Tool, Request
from store import Store, connect

KEY = b"verifier-root-key"
T0 = 1_000_000.0


def _child(store, caps=Cap.READ | Cap.WRITE, budget=100.0):
    root = mint_root(KEY, "principal:root", Cap.ALL, ttl_expires=T0 + 3600,
                     budget=budget, difficulty=4)
    store.register_principal(root, minted_at=T0)
    return attenuate(root, caps=caps, exp=T0 + 300, budget=budget, actor="agent:worker")


WRITE = Tool("write_record", Cap.WRITE, TrustTier.ORG_ATTESTED, est_cost=1.0)
CLAIMED = Manifest([ProvenanceRecord("partner-feed", TrustTier.ORG_ATTESTED)])


class TestProvenanceIsAuthoritative(unittest.TestCase):
    def test_self_claimed_tier_is_ignored_until_vouched(self):
        store = Store(":memory:")
        child = _child(store)
        # DB has NOT vouched 'partner-feed' -> deny despite the manifest claiming ORG.
        d = store.authorize(Request(child, WRITE, Cap.WRITE, CLAIMED, T0), KEY)
        self.assertFalse(d.allowed)
        self.assertEqual(d.code, "PROVENANCE")
        # after a HITL vouch, the same call passes.
        store.vouch("partner-feed", TrustTier.ORG_ATTESTED, "human:sup", at=T0)
        d = store.authorize(Request(child, WRITE, Cap.WRITE, CLAIMED, T0 + 1), KEY)
        self.assertTrue(d.allowed)


class TestSpendPersists(unittest.TestCase):
    def test_spend_accumulates_and_ceiling_bites(self):
        store = Store(":memory:")
        child = _child(store, budget=2.5)
        store.vouch("partner-feed", TrustTier.ORG_ATTESTED, "human:sup", at=T0)
        self.assertTrue(store.authorize(Request(child, WRITE, Cap.WRITE, CLAIMED, T0), KEY).allowed)
        self.assertTrue(store.authorize(Request(child, WRITE, Cap.WRITE, CLAIMED, T0 + 1), KEY).allowed)
        d = store.authorize(Request(child, WRITE, Cap.WRITE, CLAIMED, T0 + 2), KEY)
        self.assertFalse(d.allowed)
        self.assertEqual(d.code, "BUDGET")
        self.assertEqual(store.ledger.spent("principal:root"), 2.0)

    def test_durable_across_reopen(self):
        path = os.path.join(tempfile.mkdtemp(), "iam.db")
        try:
            store = Store(path)
            child = _child(store, budget=5.0)
            store.vouch("partner-feed", TrustTier.ORG_ATTESTED, "human:sup", at=T0)
            store.authorize(Request(child, WRITE, Cap.WRITE, CLAIMED, T0), KEY)
            store.conn.close()
            # reopen: spend + vouch survived to disk.
            store2 = Store(path)
            self.assertEqual(store2.ledger.spent("principal:root"), 1.0)
            self.assertEqual(store2.provenance.tier_of("partner-feed"), TrustTier.ORG_ATTESTED)
        finally:
            if os.path.exists(path):
                os.remove(path)


class TestTriagePersistence(unittest.TestCase):
    def test_denial_writes_incident_and_dedupes(self):
        store = Store(":memory:")
        child = _child(store)
        req = Request(child, WRITE, Cap.WRITE, CLAIMED, T0)   # PROVENANCE deny
        store.authorize(req, KEY)
        store.authorize(req, KEY)                             # identical -> dedupe
        n = store.conn.execute("SELECT COUNT(*) c FROM triage_incident").fetchone()["c"]
        self.assertEqual(n, 1)
        row = store.conn.execute("SELECT code FROM triage_incident").fetchone()
        self.assertEqual(row["code"], "PROVENANCE")


class TestAuditChain(unittest.TestCase):
    def test_chain_verifies_and_tamper_is_detected(self):
        store = Store(":memory:")
        child = _child(store)
        store.vouch("partner-feed", TrustTier.ORG_ATTESTED, "human:sup", at=T0)
        for i in range(4):
            store.authorize(Request(child, WRITE, Cap.WRITE, CLAIMED, T0 + i), KEY)
        self.assertTrue(store.audit.verify_chain())
        # tamper one row (drop the append-only trigger to do it) -> chain breaks.
        store.conn.execute("DROP TRIGGER decision_audit_no_update")
        store.conn.execute("UPDATE decision_audit SET code='TAMPERED' WHERE seq=1")
        store.conn.commit()
        self.assertFalse(store.audit.verify_chain())


class TestAppendOnlyTriggers(unittest.TestCase):
    def test_decision_audit_rejects_delete(self):
        conn = connect(":memory:")
        conn.execute("INSERT INTO decision_audit(ts,request_hash,code,prev_hash,row_hash) "
                     "VALUES(1,'h','ALLOW','','r')")
        with self.assertRaises(Exception):
            conn.execute("DELETE FROM decision_audit")


if __name__ == "__main__":
    unittest.main(verbosity=2)
