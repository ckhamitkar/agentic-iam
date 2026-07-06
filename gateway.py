#!/usr/bin/env python3
"""
The enforcement point (PEP). Closes the "authorize() is only a decision" gap.

agent_iam.authorize() is a Policy DECISION Point -- it returns ALLOW/DENY and trusts
the caller to obey. This Gateway is the Policy ENFORCEMENT Point: the real tool
callables live in a PRIVATE registry with no public handle, so the ONLY way to run a
tool is through invoke(), which:

  1. AUTHN (proof-of-possession) -- if the token binds a holder key, the caller must
     sign a fresh, single-use challenge with the matching private key. A stolen bearer
     token, or one presented with the wrong key, fails here -- BEFORE any authZ side
     effect (so a failed auth never charges budget).
  2. AUTHZ (the PDP) -- store.authorize() runs the 5 deterministic checks, charges
     budget only on ALLOW, and appends to the tamper-evident audit log.
  2.5 CONTAINMENT (optional runtime layer) -- if an acting `node` (containment.Contained)
     is supplied, its autonomy level decides whether the authorized action may actually
     EXECUTE: a node in SHADOW observes only (recorded, not run); a reaped node is denied.
     The irreversible floor is unaffected -- it was already enforced by the tool's
     risk_floor, and no autonomy level's ceiling grants floor capabilities.
  3. EXECUTE -- only on ALLOW (+ valid PoP, + a non-shadow node) does the callable fire.

A replayed (challenge, proof) pair fails because every invoke() mints a new challenge.

Pure stdlib. Deterministic given explicit `now`.
"""

import hashlib
from dataclasses import dataclass

from seam7_delegation import Cap, verify, InvalidToken
from agent_iam import Request, AccessState
from authn import verify_pop
from issuer import verify_svid
from detective import Event
from containment import Verdict, verdict_for


@dataclass
class Result:
    executed: bool
    code: str          # EXECUTED | SHADOWED | CONTAINED_DENY | PENDING | IDENTITY |
                       # AUTHENTICATION | CAPABILITY | PURPOSE | BUDGET | UNKNOWN_TOOL
    reason: str
    output: object = None


class Gateway:
    def __init__(self, store, root_secret: bytes, trusted_issuers=None):
        self.store = store
        self.root_secret = root_secret
        self._tools = {}            # name -> (Tool, callable)  -- PRIVATE, no public getter
        self._challenges_issued = 0
        # If non-empty, EVERY principal must carry a valid attestation from one of these
        # issuer public keys. Empty (default) = legacy/bearer mode, attestation not required.
        self.trusted_issuers = set(trusted_issuers or [])
        # Out-of-band event stream for the detective layer. The live path only APPENDS;
        # the ShadowMonitor sweeps this separately (see detective.py) -- never blocking.
        self.event_log = []

    def register(self, tool, fn) -> None:
        """Bind a tool policy to its real implementation. fn is reachable ONLY via invoke()."""
        self.store.register_tool(tool)
        self._tools[tool.name] = (tool, fn)

    def _challenge(self, token, tool_name: str, now: float):
        self._challenges_issued += 1
        nonce = f"{now}:{self._challenges_issued}"           # fresh per invoke => no replay
        chal = hashlib.sha256(f"{nonce}|{token.sig}|{tool_name}".encode()).digest()
        return chal

    def _emit_authn_incident(self, claims, tool, now, detail):
        body = {
            "control": "preventative", "code": "AUTHENTICATION",
            "accountable_root": claims.accountable_root if claims else None,
            "actor": claims.actor if claims else None, "tool": tool.name,
            "required_caps": int(tool.required_caps), "required_tier": int(tool.risk_floor),
            "actual_tier": None, "declared_purpose": None, "detail": detail, "now": now,
        }
        body["incident_id"] = "inc-" + hashlib.sha256(
            repr(sorted(body.items())).encode()).hexdigest()[:12]
        self.store.sink.emit(body)

    def invoke(self, token, tool_name, purpose, manifest, now, signer=None,
               node=None, sampled=False, **kwargs) -> Result:
        if tool_name not in self._tools:
            return Result(False, "UNKNOWN_TOOL", f"no such tool {tool_name!r}")
        tool, fn = self._tools[tool_name]

        def _log(result_code, claims):
            self.event_log.append(Event(
                ts=now,
                accountable_root=claims.accountable_root if claims else None,
                actor=claims.actor if claims else None,
                tool=tool_name, purpose=int(purpose),
                payload=" ".join(f"{k}={v}" for k, v in sorted(kwargs.items())),
                provenance_tier=int(self.store.provenance.min_tier(manifest)),
                cost=tool.est_cost, decision=result_code))

        # --- 1. AUTHN first, so a failed auth never triggers an authz side effect. ----
        try:
            claims0 = verify(token, self.root_secret, now=now)   # to read the bound holder
        except InvalidToken as e:
            _log("IDENTITY", None)
            return Result(False, "IDENTITY", f"token invalid: {e}")

        # 1a. SPIFFE identity -- the principal must present a valid SVID from a trusted CA
        #     (identity), AND the token's caps must be within the AuthZEN role grant for
        #     that identity (authorization). Identity and authorization are separate.
        if self.trusted_issuers:
            svid = self.store.svid_for(claims0.accountable_root)
            if svid is None or svid.issuer not in self.trusted_issuers or not verify_svid(svid, now=now):
                self._emit_authn_incident(claims0, tool, now, "no valid SVID from a trusted issuer")
                _log("IDENTITY", claims0)
                return Result(False, "IDENTITY", "unattested principal (no valid SVID)")
            if svid.holder != claims0.holder:
                self._emit_authn_incident(claims0, tool, now, "holder does not match the SVID")
                _log("AUTHENTICATION", claims0)
                return Result(False, "AUTHENTICATION", "holder key does not match the SVID identity")
            if (claims0.caps & self.store.role_ceiling(claims0.accountable_root)) != claims0.caps:
                self._emit_authn_incident(claims0, tool, now, "token caps exceed the role grant")
                _log("CAPABILITY", claims0)
                return Result(False, "CAPABILITY", "token capabilities exceed the role grant")

        # 1b. proof-of-possession -- the presenter must hold the bound private key.
        if claims0.holder is not None:                           # holder-bound => PoP required
            if signer is None:
                self._emit_authn_incident(claims0, tool, now, "no proof-of-possession presented")
                _log("AUTHENTICATION", claims0)
                return Result(False, "AUTHENTICATION",
                              "holder-bound token requires proof-of-possession (bearer use blocked)")
            challenge = self._challenge(token, tool_name, now)
            proof = signer(challenge)
            if not verify_pop(claims0.holder, challenge, proof):
                self._emit_authn_incident(claims0, tool, now, "proof-of-possession failed")
                _log("AUTHENTICATION", claims0)
                return Result(False, "AUTHENTICATION",
                              "proof-of-possession failed (stolen token or wrong key)")

        # --- 2. AUTHZ (the PDP: 5 checks + budget charge on ALLOW + audit). -----------
        decision = self.store.authorize(Request(token, tool, purpose, manifest, now),
                                        self.root_secret)
        if not decision.allowed:
            if decision.state == AccessState.PENDING:
                # AARP: approvable, not refused -- route to a vouch and re-evaluate.
                _log("PENDING", decision.claims)
                return Result(False, "PENDING",
                              f"{decision.reason} — needs: {decision.prerequisite}")
            _log(decision.code, decision.claims)
            return Result(False, decision.code, decision.reason)

        # --- 2.5 CONTAINMENT (runtime layer): the authorize() floor passed; the acting
        #     node's autonomy level now decides whether it may actually EXECUTE. A node in
        #     SHADOW observes only -- the would-be action is recorded but NOT run. (The
        #     irreversible floor was already enforced by the tool's risk_floor above, and
        #     no autonomy level's ceiling grants floor caps.)
        if node is not None:
            verdict = verdict_for(node, reversible=tool.reversible, sampled=sampled)
            if verdict == Verdict.DENY:
                _log("CONTAINED_DENY", decision.claims)
                return Result(False, "CONTAINED_DENY", "acting node is reaped / not runnable")
            if verdict == Verdict.OBSERVE_ONLY:
                _log("SHADOWED", decision.claims)
                return Result(False, "SHADOWED",
                              f"node in SHADOW — authorize()={decision.code}, recorded but NOT executed",
                              output={"would_execute": True})

        # --- 3. EXECUTE -- the only path to the real callable. -------------------------
        output = fn(**kwargs)
        _log("EXECUTED", decision.claims)
        return Result(True, "EXECUTED", "ran under a fresh ALLOW", output=output)


# ----------------------------------------------------------------------------------
def _demo():
    from seam7_delegation import Cap, mint_root, attenuate
    from agent_iam import Tool, TrustTier, ProvenanceRecord, Manifest
    from store import Store
    from authn import keypair, prove

    KEY = b"verifier-root-key"
    T0 = 1_000_000.0
    store = Store(":memory:")
    gw = Gateway(store, KEY)

    # a real tool: appends a row to this list when it actually runs.
    written = []
    write_db = Tool("write_record", Cap.WRITE, TrustTier.ORG_ATTESTED, est_cost=1.0)
    gw.register(write_db, lambda row=None: written.append(row or "row"))

    # mint a root, delegate to an agent BOUND to its ed25519 key.
    sk, pk_hex = keypair(seed=b"\x11" * 32)
    root = mint_root(KEY, "principal:mgr", Cap.ALL, ttl_expires=T0 + 3600, budget=10.0, difficulty=8)
    store.register_principal(root, minted_at=T0)
    tok = attenuate(root, caps=Cap.WRITE, exp=T0 + 300, budget=10.0,
                    actor="agent:writer", holder=pk_hex)
    store.vouch("db-of-record", TrustTier.ORG_ATTESTED, "human:sup", at=T0)
    good_data = Manifest([ProvenanceRecord("db-of-record", TrustTier.ORG_ATTESTED)])

    print("=" * 76)
    print("GATEWAY DEMO -- a tool cannot fire without proof-of-possession + a fresh ALLOW")
    print("=" * 76)

    signer = lambda chal: prove(sk, pk_hex, chal)   # the legit holder can sign
    r = gw.invoke(tok, "write_record", Cap.WRITE, good_data, T0, signer=signer)
    print(f"\n[legit holder]        -> {r.code}: {r.reason}   (rows written: {len(written)})")

    # a thief holds the token but NOT the private key -> presents no proof.
    r = gw.invoke(tok, "write_record", Cap.WRITE, good_data, T0 + 1, signer=None)
    print(f"[thief, no key]       -> {r.code}: {r.reason}   (rows written: {len(written)})")

    # a thief with the token AND their OWN key -> signs with the wrong key.
    sk2, pk2 = keypair(seed=b"\x22" * 32)
    r = gw.invoke(tok, "write_record", Cap.WRITE, good_data, T0 + 2,
                  signer=lambda chal: prove(sk2, pk2, chal))
    print(f"[thief, wrong key]    -> {r.code}: {r.reason}   (rows written: {len(written)})")

    # legit holder but the data is unvouched -> authZ blocks it (PoP passed, PDP denies).
    bad = Manifest([ProvenanceRecord("slack-scrape", TrustTier.UNATTESTED)])
    r = gw.invoke(tok, "write_record", Cap.WRITE, bad, T0 + 3, signer=signer)
    print(f"[legit, unvouched]    -> {r.code}: {r.reason}   (rows written: {len(written)})")

    spent = store.ledger.spent("principal:mgr")
    print(f"\n  budget charged only for the ONE executed call: spent={spent}")
    print(f"  audit chain intact: {store.audit.verify_chain()}")
    print("  the raw tool fn is only reachable via gw.invoke() -- no public handle exposes it.")


if __name__ == "__main__":
    _demo()
