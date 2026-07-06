#!/usr/bin/env python3
"""Tests for the SPIFFE-style identity issuer (SVID). Pure stdlib unittest, deterministic."""

import unittest

from issuer import Issuer, SVID, verify_svid, make_spiffe_id

SEED = b"\xaa" * 32
T0 = 1_000_000.0


class TestSVID(unittest.TestCase):
    def setUp(self):
        self.issuer = Issuer(SEED, trust_domain="axionaiapps.com")

    def test_make_spiffe_id(self):
        self.assertEqual(make_spiffe_id("axionaiapps.com", "agent/mgr"),
                         "spiffe://axionaiapps.com/agent/mgr")

    def test_valid_svid_verifies(self):
        sid = make_spiffe_id("axionaiapps.com", "agent/mgr")
        svid = self.issuer.issue_svid(sid, "deadbeef", not_after=T0 + 100)
        self.assertTrue(verify_svid(svid, now=T0))
        self.assertEqual(svid.trust_domain, "axionaiapps.com")

    def test_svid_is_identity_only_no_capabilities(self):
        svid = self.issuer.issue_svid("spiffe://td/agent/x", "aa", not_after=None)
        self.assertFalse(hasattr(svid, "caps"))     # WHO, never WHAT

    def test_tampered_holder_rejected(self):
        svid = self.issuer.issue_svid("spiffe://td/agent/x", "aaaa")
        forged = SVID(svid.spiffe_id, "bbbb", svid.not_after, svid.trust_domain,
                      svid.issuer, svid.sig)          # swap the bound holder
        self.assertFalse(verify_svid(forged, now=T0))

    def test_tampered_spiffe_id_rejected(self):
        svid = self.issuer.issue_svid("spiffe://td/agent/x", "aa")
        forged = SVID("spiffe://td/agent/attacker", svid.holder, svid.not_after,
                      svid.trust_domain, svid.issuer, svid.sig)
        self.assertFalse(verify_svid(forged, now=T0))

    def test_wrong_issuer_key_rejected(self):
        svid = self.issuer.issue_svid("spiffe://td/agent/x", "aa")
        other = Issuer(b"\xbb" * 32)
        forged = SVID(svid.spiffe_id, svid.holder, svid.not_after, svid.trust_domain,
                      other.public_key, svid.sig)     # claim a different CA
        self.assertFalse(verify_svid(forged, now=T0))

    def test_expired_svid_rejected(self):
        svid = self.issuer.issue_svid("spiffe://td/agent/x", "aa", not_after=T0 + 10)
        self.assertTrue(verify_svid(svid, now=T0))
        self.assertFalse(verify_svid(svid, now=T0 + 20))


if __name__ == "__main__":
    unittest.main(verbosity=2)
