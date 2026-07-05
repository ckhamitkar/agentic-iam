#!/usr/bin/env python3
"""
The attested-issuance authority -- a real trust root.

The macaroon token authenticates a CREDENTIAL, and holder+PoP authenticates the
PRESENTER, but nothing yet attests that a given root_id is a legitimate principal:
mint_root() just signs whatever string you hand it. This module closes that gap.

An Issuer is an ed25519 certificate authority. It ATTESTS an identity by signing a
claim that binds:  root_id  <->  holder public key  <->  a capability ceiling.
Verifiers hold only the issuer's PUBLIC key (the trust anchor). A principal is
"attested" iff a trusted issuer signed such a claim -- so a self-minted root with an
arbitrary id is rejected by an attestation-enforcing gateway.

This is the SPIFFE-SVID / enrollment analogue, kept minimal. It uses ed25519_ref
(pure Python, not constant-time); swap libsodium in production, API unchanged.

Pure stdlib. Deterministic given fixed seeds / explicit `now`.
"""

import json
from dataclasses import dataclass

from ed25519_ref import publickey, signature, checkvalid


def _claim_bytes(root_id: str, holder: str, caps: int, not_after) -> bytes:
    return json.dumps(
        {"root": root_id, "holder": holder, "caps": int(caps), "not_after": not_after},
        sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class Attestation:
    root_id: str
    holder: str          # holder pubkey hex this identity is bound to
    caps: int            # attested capability CEILING (Cap bitmask)
    not_after: float     # attestation expiry (None = no expiry)
    issuer: str          # issuer pubkey hex (the trust anchor)
    sig: str             # ed25519 signature (hex) over the identity claim


class Issuer:
    """An ed25519 CA. Its public_key is the trust anchor distributed to verifiers."""

    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise ValueError("issuer seed must be 32 bytes")
        self._sk = seed
        self.public_key = publickey(seed).hex()

    def attest(self, root_id: str, holder: str, caps, not_after: float = None) -> Attestation:
        claim = _claim_bytes(root_id, holder, int(caps), not_after)
        sig = signature(claim, self._sk, bytes.fromhex(self.public_key)).hex()
        return Attestation(root_id, holder, int(caps), not_after, self.public_key, sig)


def verify_attestation(att: Attestation, now: float = None) -> bool:
    """True iff the issuer's signature over the identity claim is valid and unexpired."""
    claim = _claim_bytes(att.root_id, att.holder, att.caps, att.not_after)
    try:
        if not checkvalid(bytes.fromhex(att.sig), claim, bytes.fromhex(att.issuer)):
            return False
    except (ValueError, TypeError):
        return False
    if now is not None and att.not_after is not None and now >= att.not_after:
        return False
    return True
