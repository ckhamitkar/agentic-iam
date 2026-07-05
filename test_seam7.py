#!/usr/bin/env python3
"""
Tests for Seam 7 cross-hop delegation binding. Pure stdlib unittest, deterministic.

Run:  python3 -m unittest test_seam7 -v
"""

import unittest

from seam7_delegation import (
    Cap, Token, InvalidToken, Expired,
    mint_root, attenuate, verify, mine, pow_valid, mint_cost, _canon,
)
import hashlib
import hmac

KEY = b"verifier-root-key"
T0 = 1_000_000.0
D = 4  # low difficulty so minting is instant in tests


def _chain_raw(token, caveat):
    """Attacker-style: chain ANY caveat (macaroon lets a holder add caveats without
    the root key). Used to prove verify() fails closed on unknown caveat types."""
    s = hmac.new(bytes.fromhex(token.sig), _canon(caveat), hashlib.sha256).digest()
    return Token(identifier=dict(token.identifier), sig=s.hex(),
                 caveats=list(token.caveats) + [caveat])


class TestMintAndVerify(unittest.TestCase):
    def setUp(self):
        self.root = mint_root(KEY, "principal:root", Cap.ALL,
                              ttl_expires=T0 + 1000, budget=100.0, difficulty=D)

    def test_root_verifies_with_full_claims(self):
        c = verify(self.root, KEY, now=T0)
        self.assertEqual(c.accountable_root, "principal:root")
        self.assertEqual(c.actor, "principal:root")   # no hop yet: actor == root
        self.assertEqual(c.caps, Cap.ALL)
        self.assertEqual(c.depth, 0)

    def test_wrong_key_rejected(self):
        with self.assertRaises(InvalidToken):
            verify(self.root, b"attacker-key", now=T0)


class TestAttenuationNarrowsOnly(unittest.TestCase):
    def setUp(self):
        self.root = mint_root(KEY, "principal:root", Cap.ALL,
                              ttl_expires=T0 + 1000, budget=100.0, difficulty=D)

    def test_caps_narrow_by_intersection(self):
        child = attenuate(self.root, caps=Cap.READ | Cap.WRITE, actor="agent:a")
        self.assertEqual(verify(child, KEY, now=T0).caps, Cap.READ | Cap.WRITE)

    def test_cannot_widen_past_an_earlier_narrowing(self):
        # Narrow to READ, then try to "widen" back to ALL on the next hop.
        narrowed = attenuate(self.root, caps=Cap.READ, actor="agent:a")
        widened = attenuate(narrowed, caps=Cap.ALL, actor="agent:b")
        # AND-fold means the READ ceiling still binds -- the widen is a no-op.
        self.assertEqual(verify(widened, KEY, now=T0).caps, Cap.READ)

    def test_exp_only_shortens(self):
        child = attenuate(self.root, exp=T0 + 10, actor="agent:a")
        # A later, LATER exp cannot extend it.
        grand = attenuate(child, exp=T0 + 999, actor="agent:b")
        self.assertEqual(verify(grand, KEY, now=T0).exp, T0 + 10)

    def test_budget_only_shrinks(self):
        child = attenuate(self.root, budget=5.0, actor="agent:a")
        grand = attenuate(child, budget=50.0, actor="agent:b")
        self.assertEqual(verify(grand, KEY, now=T0).budget, 5.0)


class TestCrossHopAccountability(unittest.TestCase):
    """The heart of Seam 7: accountability survives the chain; responsibility is the leaf."""

    def setUp(self):
        self.root = mint_root(KEY, "principal:root", Cap.ALL,
                              ttl_expires=T0 + 1000, budget=100.0, difficulty=D)

    def test_root_survives_arbitrary_depth(self):
        tok = self.root
        for i in range(6):
            tok = attenuate(tok, actor=f"agent:{i}")
        c = verify(tok, KEY, now=T0)
        self.assertEqual(c.accountable_root, "principal:root")   # unchanged after 6 hops
        self.assertEqual(c.actor, "agent:5")                     # leaf bears responsibility
        self.assertEqual(c.depth, 6)

    def test_cannot_swap_the_accountable_root(self):
        child = attenuate(self.root, actor="agent:a")
        swapped = Token(identifier={**child.identifier, "root": "principal:innocent"},
                        sig=child.sig, caveats=list(child.caveats))
        with self.assertRaises(InvalidToken):
            verify(swapped, KEY, now=T0)


class TestForgeryAndTamper(unittest.TestCase):
    def setUp(self):
        self.root = mint_root(KEY, "principal:root", Cap.ALL,
                              ttl_expires=T0 + 1000, budget=100.0, difficulty=D)
        self.child = attenuate(self.root, caps=Cap.READ, actor="agent:a")

    def test_tampered_caveat_rejected(self):
        bad = Token(identifier=dict(self.child.identifier), sig=self.child.sig,
                    caveats=list(self.child.caveats))
        bad.caveats[0] = {"t": "cap", "mask": int(Cap.ALL)}   # rewrite the caveat
        with self.assertRaises(InvalidToken):
            verify(bad, KEY, now=T0)

    def test_forged_identifier_rejected(self):
        bad = Token(identifier={**self.root.identifier, "caps": int(Cap.ALL) + 128},
                    sig=self.root.sig, caveats=[])
        with self.assertRaises(InvalidToken):
            verify(bad, KEY, now=T0)

    def test_unknown_caveat_fails_closed(self):
        # Attacker chains a well-signed but UNKNOWN caveat type. Must be rejected,
        # never silently ignored.
        evil = _chain_raw(self.child, {"t": "grant_root", "mask": int(Cap.ALL)})
        with self.assertRaises(InvalidToken):
            verify(evil, KEY, now=T0)


class TestProofOfWorkCost(unittest.TestCase):
    def test_unminted_root_rejected(self):
        # Hand-craft a token whose nonce does NOT satisfy a high difficulty.
        ident = {"root": "principal:cheat", "caps": int(Cap.READ),
                 "exp": T0 + 10, "budget": 1.0, "nonce": 0, "difficulty": 20}
        sig = hmac.new(KEY, _canon(ident), hashlib.sha256).hexdigest()
        with self.assertRaises(InvalidToken):
            verify(Token(identifier=ident, sig=sig, caveats=[]), KEY, now=T0)

    def test_mint_cost_is_exponential_in_difficulty(self):
        self.assertEqual(mint_cost(0), 1.0)
        self.assertEqual(mint_cost(10), 1024.0)
        self.assertLess(mint_cost(8), mint_cost(9))

    def test_mining_finds_a_valid_nonce(self):
        nonce, hashes = mine("principal:x", 10)
        self.assertTrue(pow_valid("principal:x", nonce, 10))
        self.assertGreaterEqual(hashes, 1)


class TestTTL(unittest.TestCase):
    def test_expired_token_rejected(self):
        root = mint_root(KEY, "principal:root", Cap.ALL,
                         ttl_expires=T0 + 100, budget=10.0, difficulty=D)
        with self.assertRaises(Expired):
            verify(root, KEY, now=T0 + 200)

    def test_child_ttl_binds_even_if_root_still_valid(self):
        root = mint_root(KEY, "principal:root", Cap.ALL,
                         ttl_expires=T0 + 1000, budget=10.0, difficulty=D)
        short = attenuate(root, exp=T0 + 50, actor="agent:a")
        with self.assertRaises(Expired):
            verify(short, KEY, now=T0 + 100)          # child expired
        # root itself is still fine at the same instant
        self.assertIsNotNone(verify(root, KEY, now=T0 + 100))


if __name__ == "__main__":
    unittest.main(verbosity=2)
