#!/usr/bin/env python3
"""
Agent IAM -- the deterministic authorization gate that sits ON TOP of the Seam 7
token (seam7_delegation.py). This is the "agentic IAM" layer: it takes a verified
token's effective claims + a tool call + the DATA PROVENANCE of what the agent
reasoned on, and returns ALLOW / DENY. No LLM, no probabilities -- boolean math,
set operations, and a discrete trust lattice.

It answers the ORIGINAL question ("can an agent act only when its data comes from
secure, vouched-for sources?") via the ABAC/provenance check below.

THE DECISION, in order (fail closed at the first failure):
  1. IDENTITY  -- the token verifies (signature chain + PoW + TTL). seam7 does this.
  2. RBAC      -- the tool's required capabilities are a subset of the token's caps.
  3. PBAC      -- the declared purpose is within the grant AND covers the tool. Intent
                  drift (a child doing something outside its declared purpose) is denied.
  4. ABAC      -- the data lineage's weakest link meets the tool's required trust tier.
                  Reasoning on an unvouched source cannot drive a high-gravity action.
  5. BUDGET    -- cumulative spend for the accountable root + this call <= the ceiling.
  6. ALLOW     -- charge the ledger; return the claims.

Design choices carried over from the grill (deliberately NOT the Gemini defaults):
  - Trust is a DISCRETE LATTICE, not a float. No `trust_score < 0.8`. A source is at a
    tier or it isn't; a threshold that slides is a threshold an adversary slides past.
  - Purpose is a CAPABILITY BITMASK, not free text. PBAC by set-subset is decidable in
    nanoseconds; semantic purpose-matching would smuggle an LLM into the gate.
  - The lineage's trust = its WEAKEST link (min). Context is only as vouched as its
    least-vouched input -- "garbage in, gospel out" is exactly what this blocks.

Denials emit a TriagePacket to an ABSTRACT sink -- NEVER to triage.axionaiapps.com,
which is the live *clinical* product, a different surface.

Pure stdlib, deterministic.
"""

import hashlib
import json
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

from seam7_delegation import Cap, Token, EffectiveClaims, verify, InvalidToken


# --- ABAC: the data-provenance trust lattice now lives in provenance.py, re-exported
#     here so existing imports (`from agent_iam import TrustTier, Manifest, ...`) keep working.
from provenance import (                                                    # noqa: E402,F401
    TrustTier, ProvenanceRecord, Manifest, ProvenanceResolver, SelfReportedResolver,
)


@dataclass(frozen=True)
class Tool:
    name: str
    required_caps: Cap           # RBAC: what capabilities the tool needs
    risk_floor: TrustTier        # ABAC: min provenance tier to run it (founder-supplied gravity)
    est_cost: float = 0.0        # budget units this call is estimated to consume
    reversible: bool = True      # gravity/reversibility classifier: False => the floor —
                                 # always gated, never granted by graduated trust


@dataclass
class Request:
    token: Token
    tool: Tool
    declared_purpose: Cap        # PBAC: what the agent SAYS this call is for
    manifest: Manifest
    now: float


# --- decision + triage --------------------------------------------------------------
@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: str                    # ALLOW | IDENTITY | CAPABILITY | PURPOSE | PROVENANCE | BUDGET
    reason: str
    claims: Optional[EffectiveClaims] = None
    triage: Optional[dict] = None


class SpendLedger:
    """Tracks cumulative spend per accountable ROOT (accountability, not the leaf)."""
    def __init__(self):
        self._spent = {}

    def spent(self, root: str) -> float:
        return self._spent.get(root, 0.0)

    def charge(self, root: str, amount: float) -> None:
        self._spent[root] = self._spent.get(root, 0.0) + amount


class TriageSink:
    """Abstract sink. Concrete impls forward elsewhere -- NEVER to the clinical host."""
    def emit(self, packet: dict) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class InMemorySink(TriageSink):
    def __init__(self):
        self.packets = []

    def emit(self, packet: dict) -> None:
        self.packets.append(packet)


def _triage_packet(code: str, req: Request, claims: Optional[EffectiveClaims],
                   detail: str, actual_tier: TrustTier) -> dict:
    body = {
        "control": "preventative",          # blocked inline, before the action
        "code": code,
        "accountable_root": claims.accountable_root if claims else None,
        "actor": claims.actor if claims else None,
        "tool": req.tool.name,
        "required_caps": int(req.tool.required_caps),
        "required_tier": int(req.tool.risk_floor),
        "actual_tier": int(actual_tier),
        "declared_purpose": int(req.declared_purpose),
        "detail": detail,
        "now": req.now,
        # NB: raw source data is intentionally NOT included -- structural metadata only.
    }
    body["incident_id"] = "inc-" + hashlib.sha256(
        json.dumps(body, sort_keys=True).encode()).hexdigest()[:12]
    return body


def authorize(req: Request, root_secret: bytes, ledger: SpendLedger,
              sink: Optional[TriageSink] = None,
              provenance: Optional[ProvenanceResolver] = None) -> Decision:
    provenance = provenance or SelfReportedResolver()
    actual_tier = provenance.min_tier(req.manifest)   # authoritative when DB-backed

    def deny(code, reason, claims=None):
        packet = _triage_packet(code, req, claims, reason, actual_tier)
        if sink is not None:
            sink.emit(packet)
        return Decision(False, code, reason, claims=claims, triage=packet)

    # 1. IDENTITY -- the token must verify (sig chain + PoW + TTL).
    try:
        claims = verify(req.token, root_secret, now=req.now)
    except InvalidToken as e:
        return deny("IDENTITY", f"token invalid: {e}")

    # 2. RBAC -- the tool's required caps must be a subset of the granted caps.
    if (req.tool.required_caps & claims.caps) != req.tool.required_caps:
        missing = req.tool.required_caps & ~claims.caps
        return deny("CAPABILITY",
                    f"role lacks capability {missing!r} for tool {req.tool.name!r}", claims)

    # 3. PBAC -- declared purpose must be WITHIN the grant and COVER the tool. Intent
    #    drift (acting outside the declared purpose) is a denial.
    if (req.declared_purpose & claims.caps) != req.declared_purpose:
        return deny("PURPOSE", "declared purpose exceeds the granted capabilities", claims)
    if (req.tool.required_caps & req.declared_purpose) != req.tool.required_caps:
        return deny("PURPOSE",
                    f"tool {req.tool.name!r} is outside the declared purpose (intent drift)",
                    claims)

    # 4. ABAC -- the data lineage's weakest link must meet the tool's trust floor.
    #    actual_tier was resolved up top (DB-authoritative when a store resolver is used).
    if actual_tier < req.tool.risk_floor:
        return deny("PROVENANCE",
                    f"data lineage tier {actual_tier.name} < required {req.tool.risk_floor.name} "
                    f"(acting on unvouched data)", claims)

    # 5. BUDGET -- cumulative spend for the accountable root + this call <= ceiling.
    if ledger.spent(claims.accountable_root) + req.tool.est_cost > claims.budget:
        return deny("BUDGET",
                    f"budget exhausted: spent {ledger.spent(claims.accountable_root)} + "
                    f"{req.tool.est_cost} > ceiling {claims.budget}", claims)

    # 6. ALLOW.
    ledger.charge(claims.accountable_root, req.tool.est_cost)
    return Decision(True, "ALLOW", "all checks passed", claims=claims)


# ----------------------------------------------------------------------------------
def _demo():
    from seam7_delegation import mint_root, attenuate

    KEY = b"verifier-root-key"
    T0 = 1_000_000.0
    ledger = SpendLedger()
    sink = InMemorySink()

    print("=" * 76)
    print("AGENT IAM DEMO -- authorize(token, tool, provenance) on top of the Seam 7 token")
    print("=" * 76)

    # A parent 'triage-manager' delegates to a child 'log-parser' scoped to READ+ENRICH,
    # with a purpose of enrichment, a 300s TTL and a budget of 5.0.
    root = mint_root(KEY, "principal:triage-manager", Cap.ALL,
                     ttl_expires=T0 + 3600, budget=5.0, difficulty=8)
    child = attenuate(root, caps=Cap.READ | Cap.ENRICH | Cap.WRITE,
                      exp=T0 + 300, budget=5.0, actor="agent:log-parser")

    write_db = Tool("write_record", required_caps=Cap.WRITE,
                    risk_floor=TrustTier.ORG_ATTESTED, est_cost=1.0)

    # (a) The child read an UNVOUCHED slack scrape, then tries to WRITE -> DENY (ABAC).
    unvouched = Manifest([ProvenanceRecord("slack-scrape", TrustTier.UNATTESTED)])
    d = authorize(Request(child, write_db, Cap.WRITE, unvouched, T0), KEY, ledger, sink)
    print(f"\n[a] write on UNVOUCHED data -> {d.code}: {d.reason}")

    # (b) Re-anchor to an ORG-ATTESTED source -> ALLOW.
    vouched = Manifest([ProvenanceRecord("db-of-record", TrustTier.ORG_ATTESTED)])
    d = authorize(Request(child, write_db, Cap.WRITE, vouched, T0), KEY, ledger, sink)
    print(f"[b] write on ORG-ATTESTED data -> {d.code}: {d.reason}")

    # (c) Intent drift: declare an enrichment purpose but call the write tool -> DENY (PBAC).
    d = authorize(Request(child, write_db, Cap.ENRICH, vouched, T0), KEY, ledger, sink)
    print(f"[c] write but purpose=ENRICH -> {d.code}: {d.reason}")

    # (d) A capability the child never had: DELETE -> DENY (RBAC).
    delete = Tool("delete_record", Cap.DELETE, TrustTier.HUMAN_VOUCHED, est_cost=1.0)
    d = authorize(Request(child, delete, Cap.DELETE, vouched, T0), KEY, ledger, sink)
    print(f"[d] delete (never granted) -> {d.code}: {d.reason}")

    # (e) Budget exhaustion after enough allowed writes -> DENY (BUDGET, 402-equivalent).
    for _ in range(6):
        d = authorize(Request(child, write_db, Cap.WRITE, vouched, T0), KEY, ledger, sink)
    print(f"[e] after repeated writes -> {d.code}: {d.reason}")

    print(f"\n  triage packets emitted (denials only): {len(sink.packets)}")
    print(f"  example incident: {sink.packets[0]['incident_id']} code={sink.packets[0]['code']}")
    print("\n  Every DENY is deterministic, attributable to the accountable root, and shipped")
    print("  to an abstract sink. No LLM in the path; no float threshold; provenance is a")
    print("  discrete tier and the lineage is judged by its weakest link.")


if __name__ == "__main__":
    _demo()
