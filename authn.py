#!/usr/bin/env python3
"""
Authentication layer: agent key material + proof-of-possession (PoP).

The Seam 7 token authenticates the CREDENTIAL (its signature chain + PoW + TTL),
but on its own it is a BEARER token -- whoever holds it is the agent, so a stolen
token = impersonation. This module closes that gap: an agent holds an ed25519
keypair, its public key is BOUND into the token (seam7_delegation holder caveat),
and to USE the token the agent must sign a fresh, single-use challenge with its
private key. A thief with the token but not the private key cannot produce the
proof -> the gateway denies it.

  keypair()                 -> (sk, pk_hex)
  prove(sk, pk_hex, chal)   -> proof hex        (the holder signs the challenge)
  verify_pop(pk_hex, chal, proof) -> bool       (the gateway checks it)

Pure stdlib (uses ed25519_ref). Deterministic given a fixed sk.
"""

import os

from ed25519_ref import publickey, signature, checkvalid


def keypair(seed: bytes = None):
    """Return (secret_key_bytes, public_key_hex). Pass a 32-byte seed for determinism."""
    sk = seed if seed is not None else os.urandom(32)
    if len(sk) != 32:
        raise ValueError("ed25519 seed/secret must be 32 bytes")
    return sk, publickey(sk).hex()


def prove(sk: bytes, pk_hex: str, challenge: bytes) -> str:
    """The holder proves possession by signing the challenge."""
    return signature(challenge, sk, bytes.fromhex(pk_hex)).hex()


def verify_pop(pk_hex: str, challenge: bytes, proof_hex: str) -> bool:
    """The verifier (gateway) checks the proof against the bound public key."""
    try:
        return checkvalid(bytes.fromhex(proof_hex), challenge, bytes.fromhex(pk_hex))
    except (ValueError, TypeError):
        return False
