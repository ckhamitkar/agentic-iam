#!/usr/bin/env python3
"""
Cross-hop delegation binding -- the capability-token core of agentic-iam.

A parent agent delegates authority to a child, which delegates to a grandchild, and
so on. This module makes that delegation chain safe with three properties:

  1. ATTENUATION -- a delegated token can only NARROW (capabilities, TTL, budget),
     never widen. Macaroon-style HMAC caveat chain: a holder attenuates WITHOUT the
     root key; the verifier detects any widening or tampering WITH it.
  2. ACCOUNTABILITY THAT SURVIVES THE CHAIN -- every token, at any delegation depth,
     is cryptographically bound to its ROOT principal. The leaf carries RESPONSIBILITY
     (the `actor`); the root keeps ACCOUNTABILITY (the `accountable_root`), which
     cannot be swapped or shed without the root key AND a fresh proof-of-work. This is
     what "cross-hop, non-fungible" means -- there is no orphan agent with nobody to
     answer for it.
  3. A REAL COST -- minting a fresh root requires proof-of-work of tunable difficulty
     D, so mint_cost(D) = 2**D is an ACTUAL number of hash evaluations. Minting is
     what makes a principal scarce (the anti-Sybil cost).

HONEST LIMITS (see also the README):
  - Proof-of-work is ONE admissible anti-Sybil cost-source (Douceur 2002), not the
    only one; a trusted-authority mint or device attestation may fit better. The cost
    the attacker pays to re-mint a clean identity is what deters reputation-shedding.
  - HMAC (symmetric) is used for the caveat chain -- correct for offline attenuation;
    the verifier holds that key. Asymmetric *identity* attestation is layered on top
    by issuer.py. Swap the ed25519 reference (ed25519_ref.py) for libsodium in
    production; the construction is unchanged.

Companion identity binding: a holder public key (see the `holder` caveat) enables
proof-of-possession in authn.py, so a stolen bearer token cannot be used.

Pure stdlib, seeded, deterministic.
"""

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from enum import IntFlag


# --- capabilities: what an agent may do; a bitmask so subset-check is one AND ------
class Cap(IntFlag):
    NONE = 0
    READ = 1
    ENRICH = 2
    WRITE = 4
    DELETE = 8
    SPEND = 16
    SPAWN = 32
    RED_FLAG = 64          # admission to fire RED on the Channel-A floor
    ALL = READ | ENRICH | WRITE | DELETE | SPEND | SPAWN | RED_FLAG


class InvalidToken(Exception):
    """Verification failed: forged, tampered, unminted, or malformed."""


class Expired(InvalidToken):
    """The token's effective TTL has passed."""


_KNOWN_CAVEATS = {"cap", "exp", "budget", "actor", "holder"}


def _canon(obj) -> bytes:
    """Canonical, stable serialization so signatures are reproducible."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# --- proof-of-work: the real, tunable cost that makes a root principal scarce ------
def _pow_digest(root_id: str, nonce: int) -> bytes:
    return hashlib.sha256(f"{root_id}:{nonce}".encode()).digest()


def _leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for b in digest:
        if b == 0:
            bits += 8
        else:
            bits += 8 - b.bit_length()
            break
    return bits


def pow_valid(root_id: str, nonce: int, difficulty: int) -> bool:
    """A root is 'minted' only if H(root_id:nonce) has >= `difficulty` leading zero bits."""
    return _leading_zero_bits(_pow_digest(root_id, nonce)) >= difficulty


def mine(root_id: str, difficulty: int, start: int = 0):
    """Find a nonce satisfying the difficulty. Returns (nonce, hashes_tried)."""
    nonce = start
    while True:
        if pow_valid(root_id, nonce, difficulty):
            return nonce, nonce - start + 1
        nonce += 1


def mint_cost(difficulty: int) -> float:
    """
    Expected SHA-256 evaluations to mint one fresh, clean root at this difficulty
    = 2**difficulty. This is `c` -- the quantity exp_e_principal_cost.py treated as
    a free knob, now a real function of a shippable parameter.
    """
    return float(2 ** difficulty)


# --- the token: an identifier (the minted root) + a chain of narrowing caveats -----
@dataclass
class Token:
    identifier: dict            # {root, caps, exp, budget, nonce, difficulty} -- signed
    sig: str                    # hex HMAC chain: root sig folded through each caveat
    caveats: list = field(default_factory=list)


@dataclass(frozen=True)
class EffectiveClaims:
    accountable_root: str       # ACCOUNTABILITY -- immutable, survives every hop
    actor: str                  # RESPONSIBILITY -- the leaf doing the work
    caps: Cap                   # intersection of root caps and every cap caveat
    exp: float                  # min of root TTL and every exp caveat
    budget: float               # min of root budget and every budget caveat
    depth: int                  # number of delegation hops below the root
    holder: str = None          # bound holder public key (hex); None = bearer token


def mint_root(root_secret: bytes, root_id: str, caps: Cap,
              ttl_expires: float, budget: float, difficulty: int) -> Token:
    """
    Mint a ROOT token. Costs proof-of-work `difficulty` (this is the anti-Sybil
    price). `root_secret` is the verifier's key (HMAC here; ed25519 in production).
    """
    nonce, _ = mine(root_id, difficulty)
    identifier = {
        "root": root_id, "caps": int(caps), "exp": ttl_expires,
        "budget": budget, "nonce": nonce, "difficulty": difficulty,
    }
    sig = hmac.new(root_secret, _canon(identifier), hashlib.sha256).digest()
    return Token(identifier=identifier, sig=sig.hex(), caveats=[])


def _chain(token: Token, caveat: dict) -> Token:
    """Append a caveat and fold the signature -- needs NO root key (macaroon property)."""
    s = hmac.new(bytes.fromhex(token.sig), _canon(caveat), hashlib.sha256).digest()
    return Token(identifier=dict(token.identifier),
                 sig=s.hex(), caveats=list(token.caveats) + [caveat])


def attenuate(token: Token, *, caps: Cap = None, exp: float = None,
              budget: float = None, actor: str = None, holder: str = None) -> Token:
    """
    Delegate DOWN a hop. Every argument can only NARROW the token; there is no way
    to widen (verify() folds caps by AND and exp/budget by min). `actor` records the
    child who now bears responsibility -- accountability stays pinned to the root.
    `holder` binds the child's ed25519 public key (hex) for proof-of-possession, so
    the token stops being a pure bearer credential from this hop down.
    """
    out = token
    if caps is not None:
        out = _chain(out, {"t": "cap", "mask": int(caps)})
    if exp is not None:
        out = _chain(out, {"t": "exp", "exp": exp})
    if budget is not None:
        out = _chain(out, {"t": "budget", "v": budget})
    if actor is not None:
        out = _chain(out, {"t": "actor", "id": actor})
    if holder is not None:
        out = _chain(out, {"t": "holder", "key": holder})
    return out


def verify(token: Token, root_secret: bytes, now: float = None) -> EffectiveClaims:
    """
    The deterministic gate. Returns EffectiveClaims or raises. Order matters:
      1. COST      -- the root's proof-of-work must be valid (it actually paid to exist)
      2. INTEGRITY -- recompute the HMAC chain; reject forgery / tampering / unknown caveats
      3. FOLD      -- collapse caveats to effective claims (narrowing only)
      4. TTL       -- reject if expired
    """
    ident = token.identifier

    # 1. cost / mint check -- an unminted or under-mined root is not a principal.
    if not pow_valid(ident["root"], ident["nonce"], ident["difficulty"]):
        raise InvalidToken("proof-of-work invalid: principal was never minted")

    # 2. integrity -- fail closed on any unknown caveat type before trusting the chain.
    s = hmac.new(root_secret, _canon(ident), hashlib.sha256).digest()
    for c in token.caveats:
        if c.get("t") not in _KNOWN_CAVEATS:
            raise InvalidToken(f"unknown caveat type {c.get('t')!r} (fail closed)")
        s = hmac.new(s, _canon(c), hashlib.sha256).digest()
    if not hmac.compare_digest(s.hex(), token.sig):
        raise InvalidToken("signature mismatch: forged or tampered")

    # 3. fold -- narrowing only, by construction.
    caps = Cap(ident["caps"])
    exp = ident["exp"]
    budget = ident["budget"]
    actor = ident["root"]
    holder = None
    depth = 0
    for c in token.caveats:
        t = c["t"]
        if t == "cap":
            caps &= Cap(c["mask"])       # AND: can only remove capabilities
        elif t == "exp":
            exp = min(exp, c["exp"])     # min: can only shorten TTL
        elif t == "budget":
            budget = min(budget, c["v"]) # min: can only shrink budget
        elif t == "actor":
            actor = c["id"]              # responsibility moves to the child
            depth += 1
        elif t == "holder":
            holder = c["key"]            # bind proof-of-possession key (latest wins)

    # 4. TTL
    if now is not None and now >= exp:
        raise Expired(f"token expired at {exp}; now={now}")

    return EffectiveClaims(accountable_root=ident["root"], actor=actor,
                           caps=caps, exp=exp, budget=budget, depth=depth, holder=holder)


# ----------------------------------------------------------------------------------
def _demo():
    import time

    KEY = b"verifier-root-key-not-held-by-agents"
    T0 = 1_000_000.0
    print("=" * 76)
    print("SEAM 7 DEMO -- cross-hop delegation binding (attenuation + accountability + cost)")
    print("=" * 76)

    # Mint a reputable root principal (difficulty 8 -> ~256 hashes, instant).
    root = mint_root(KEY, "principal:triage-manager", Cap.ALL,
                     ttl_expires=T0 + 3600, budget=100.0, difficulty=8)
    print("\n[mint]  root principal 'triage-manager' minted at difficulty 8")

    # Delegate down two hops, narrowing at each.
    child = attenuate(root, caps=Cap.READ | Cap.ENRICH | Cap.RED_FLAG,
                      exp=T0 + 300, budget=5.0, actor="agent:log-parser")
    grand = attenuate(child, caps=Cap.READ, budget=1.0, actor="agent:summarizer")

    c = verify(grand, KEY, now=T0)
    print(f"[verify] grandchild -> accountable_root = {c.accountable_root!r}")
    print(f"                       actor (responsibility) = {c.actor!r}")
    print(f"                       caps = {c.caps!r}   (narrowed to READ)")
    print(f"                       budget = {c.budget}  depth = {c.depth}")
    print("  => accountability stayed at the ROOT across 2 hops; responsibility is the LEAF.")

    # Attack 1: tamper a caveat to widen capabilities.
    forged = Token(identifier=dict(grand.identifier), sig=grand.sig,
                   caveats=list(grand.caveats))
    forged.caveats[0] = {"t": "cap", "mask": int(Cap.ALL)}   # try to re-widen
    try:
        verify(forged, KEY, now=T0)
        print("[attack1] WIDEN caveat ACCEPTED  <-- BUG")
    except InvalidToken as e:
        print(f"[attack1] widen-via-tamper REJECTED: {e}")

    # Attack 2: swap the accountable root to a clean identity (shed accountability).
    swapped = Token(identifier={**grand.identifier, "root": "principal:innocent"},
                    sig=grand.sig, caveats=list(grand.caveats))
    try:
        verify(swapped, KEY, now=T0)
        print("[attack2] ROOT-SWAP ACCEPTED  <-- BUG")
    except InvalidToken as e:
        print(f"[attack2] shed-accountability REJECTED: {e}")

    # The only lawful way to get a clean root is to PAY the mint cost again.
    print("\n[cost]  to obtain a fresh, reputation-clean root you must re-mine PoW:")
    for D in (8, 12, 16, 20):
        t = time.perf_counter()
        _, hashes = mine(f"principal:fresh-{D}", D)
        dt = time.perf_counter() - t
        print(f"          difficulty {D:>2}: mint_cost={int(mint_cost(D)):>9} hashes  "
              f"(mined in {hashes:>7} hashes, {dt*1e3:6.1f} ms)")
    print("  => that re-mint cost is exactly the `c` exp_e_principal_cost.py hand-set.")

    print("\n" + "=" * 76)
    print("HONEST VERDICT")
    print("=" * 76)
    print("""\
 SHIPPED (unconditionally, needs no economic assumption):
   - Attenuation: a delegated token can only narrow. Widening is rejected by the fold.
   - Cross-hop accountability: the root principal survives arbitrary delegation depth
     and cannot be swapped or shed without the verifier key -- so every leaf verdict
     is attributable to a named root. This is the binding HORIZONTAL_LAYER Seam 7
     called "unshipped".
 SHIPPED (conditional -- this is where the honesty lives):
   - A real cost c = 2**D. It sets c > 0. WHICH cost-source to use is a values
     decision. Server-side (today's deployment) the honest minter is a Mini, so PoW
     is a real speed-bump against a casual/single-machine adversary -- but a rented
     GPU/ASIC farm still out-hashes one honest node, so PoW alone is a speed-bump,
     not a wall. exp_e_driven.py works these numbers. See it before concluding "solved".
 NOT a safety claim:
   - Douceur still holds. This instantiates a cost; it does not repeal the
     impossibility. The deployed proof is wiring this into an out-of-band aggregator
     over a real multi-node graph (triage-backend/triage/graph.py) -- later, not here.
""")


if __name__ == "__main__":
    _demo()
