#!/usr/bin/env python3
"""Tests for the attested-issuance authority. Pure stdlib unittest, deterministic."""

import unittest

from seam7_delegation import Cap
from issuer import Issuer, verify_attestation

SEED = b"\xaa" * 32
T0 = 1_000_000.0


class TestAttestation(unittest.TestCase):
    def setUp(self):
        self.issuer = Issuer(SEED)

    def test_valid_attestation_verifies(self):
        att = self.issuer.attest("principal:mgr", "deadbeef", Cap.READ | Cap.WRITE,
                                 not_after=T0 + 100)
        self.assertTrue(verify_attestation(att, now=T0))

    def test_tampered_caps_rejected(self):
        att = self.issuer.attest("principal:mgr", "deadbeef", Cap.READ, not_after=None)
        forged = att.__class__(att.root_id, att.holder, int(Cap.ALL), att.not_after,
                               att.issuer, att.sig)          # bump caps, keep old sig
        self.assertFalse(verify_attestation(forged, now=T0))

    def test_wrong_issuer_key_rejected(self):
        att = self.issuer.attest("principal:mgr", "deadbeef", Cap.READ, not_after=None)
        other = Issuer(b"\xbb" * 32)
        forged = att.__class__(att.root_id, att.holder, att.caps, att.not_after,
                               other.public_key, att.sig)    # claim a different issuer
        self.assertFalse(verify_attestation(forged, now=T0))

    def test_expired_attestation_rejected(self):
        att = self.issuer.attest("principal:mgr", "deadbeef", Cap.READ, not_after=T0 + 10)
        self.assertTrue(verify_attestation(att, now=T0))
        self.assertFalse(verify_attestation(att, now=T0 + 20))

    def test_holder_binding_is_signed(self):
        att = self.issuer.attest("principal:mgr", "aaaa", Cap.READ, not_after=None)
        forged = att.__class__(att.root_id, "bbbb", att.caps, att.not_after,
                               att.issuer, att.sig)          # swap the bound holder
        self.assertFalse(verify_attestation(forged, now=T0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
