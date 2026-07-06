#!/usr/bin/env python3
"""
SPIFFE-style identity issuance -- the trust-domain CA.

Aligned to SPIFFE/SPIRE: an Issuer is a trust-domain certificate authority whose public
key is the trust anchor (a SPIFFE "trust bundle"). It issues SVIDs -- SPIFFE Verifiable
Identity Documents -- binding a SPIFFE ID (spiffe://trust-domain/path) to the holder's
public key, signed by the CA. Verifiers hold only the CA's public key.

IDENTITY ONLY. Per the SPIFFE / OIDF-AuthZEN separation of concerns, an SVID attests
WHO a workload is -- never WHAT it may do. Capabilities (the authorization ceiling) are
a separate policy concern: the store holds them as a role grant, and authorize() / the
gateway evaluate them. They are deliberately NOT baked into the signed identity document.

The SPIFFE ID path mirrors the containment tree (spiffe://td/agent/parent/child), so a
child's identity proves it is within its parent's reach (see containment.py).

Uses ed25519_ref (swap libsodium in production; the keypair/sign/verify API is identical).
Pure stdlib, deterministic.
"""

import json
from dataclasses import dataclass

from ed25519_ref import publickey, signature, checkvalid

DEFAULT_TRUST_DOMAIN = "axionaiapps.com"


def make_spiffe_id(trust_domain: str, path: str) -> str:
    """spiffe://<trust_domain>/<path>"""
    return f"spiffe://{trust_domain}/{path.lstrip('/')}"


def _svid_claim(spiffe_id: str, holder: str, not_after, trust_domain: str) -> bytes:
    return json.dumps(
        {"spiffe_id": spiffe_id, "holder": holder,
         "not_after": not_after, "trust_domain": trust_domain},
        sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class SVID:
    """A SPIFFE Verifiable Identity Document -- identity only, no capabilities."""
    spiffe_id: str       # spiffe://trust-domain/path
    holder: str          # holder public key (hex) this identity is bound to
    not_after: float     # expiry (None = none); SVIDs are short-lived and rotated
    trust_domain: str
    issuer: str          # CA public key (hex) -- the trust anchor / bundle root
    sig: str             # ed25519 signature over the identity claim


class Issuer:
    """A trust-domain CA. `public_key` is the trust anchor distributed to verifiers."""

    def __init__(self, seed: bytes, trust_domain: str = DEFAULT_TRUST_DOMAIN):
        if len(seed) != 32:
            raise ValueError("issuer seed must be 32 bytes")
        self._sk = seed
        self.public_key = publickey(seed).hex()
        self.trust_domain = trust_domain

    def issue_svid(self, spiffe_id: str, holder: str, not_after: float = None) -> SVID:
        claim = _svid_claim(spiffe_id, holder, not_after, self.trust_domain)
        sig = signature(claim, self._sk, bytes.fromhex(self.public_key)).hex()
        return SVID(spiffe_id, holder, not_after, self.trust_domain, self.public_key, sig)


def verify_svid(svid: SVID, now: float = None) -> bool:
    """True iff the CA's signature over the identity claim is valid and unexpired."""
    claim = _svid_claim(svid.spiffe_id, svid.holder, svid.not_after, svid.trust_domain)
    try:
        if not checkvalid(bytes.fromhex(svid.sig), claim, bytes.fromhex(svid.issuer)):
            return False
    except (ValueError, TypeError):
        return False
    if now is not None and svid.not_after is not None and now >= svid.not_after:
        return False
    return True
