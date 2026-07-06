#!/usr/bin/env python3
"""
Data-provenance trust tiers -- agentic-iam's first additive layer over the standards.

SPIFFE (identity), OIDF AuthZEN (authorization), and CoSAI (principles) all gate an
action on the AGENT's identity and delegated authority. Almost none of them gate the
action on the trust tier of the DATA the agent reasoned on to reach it. That gap is
the "act only on vouched-for sources" problem, and it is where this library adds
something the standards under-cover.

The model is deliberately NOT a float score (a threshold you can slide past) but a
DISCRETE LATTICE, and a context is only as trustworthy as its WEAKEST input -- garbage
in, gospel out is exactly what this blocks.

Pairs with the authoritative resolver in store.py (SqliteProvenance), which resolves a
source_id to its tier from a vouched-sources table rather than trusting the caller's
self-reported tier. Publishing/consuming those tiers across installs is the shared
"trust root" whose adoption compounds (the network effect).
"""

from dataclasses import dataclass, field
from enum import IntEnum


class TrustTier(IntEnum):
    """Discrete trust lattice. Compare with >= / < -- never a float threshold."""
    UNATTESTED = 0        # scraped page, unauthenticated webhook, raw user upload
    SELF_SIGNED = 1       # signed by the agent/workload itself
    ORG_ATTESTED = 2      # signed by an approved org source (DB of record, attested API)
    HUMAN_VOUCHED = 3     # a human/supervisor explicitly signed off on this source


@dataclass(frozen=True)
class ProvenanceRecord:
    source_id: str
    tier: TrustTier


@dataclass
class Manifest:
    """The data lineage the agent reasoned on to reach a tool call."""
    records: list = field(default_factory=list)

    def min_tier(self) -> TrustTier:
        # weakest link: context is only as vouched as its least-vouched input.
        if not self.records:
            return TrustTier.UNATTESTED
        return TrustTier(min(r.tier for r in self.records))


class ProvenanceResolver:
    """
    Decides the authoritative trust tier of a manifest. The default trusts the
    manifest's self-reported tiers (fine for a demo). A persistence-backed resolver
    (store.SqliteProvenance) IGNORES self-reported tiers and resolves each source_id
    against a vouched-sources table -- so a caller cannot lie its way to a high tier.
    """
    def min_tier(self, manifest: "Manifest") -> TrustTier:  # pragma: no cover - interface
        raise NotImplementedError


class SelfReportedResolver(ProvenanceResolver):
    def min_tier(self, manifest: "Manifest") -> TrustTier:
        return manifest.min_tier()
