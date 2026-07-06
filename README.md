# agentic-iam

**Deterministic authentication, authorization, and accounting for hierarchies of AI agents.**
Zero third-party dependencies. Zero LLM in the enforcement path. 66 passing tests.

When agents spawn agents and call tools on data of varying trustworthiness, classic IAM
(static service-account keys) breaks: an agent that reads a poisoned web page can trigger a
malicious tool call. `agentic-iam` is a runtime, context-aware control plane that binds an
agent's authority to **who delegated it**, **what data it reasoned on**, and **time/cost
budgets** — enforced by plain, auditable code, not a probabilistic model.

> A probabilistic guard can be fooled by the same injection it hunts, and it can't meet a
> sub-millisecond budget. So the enforcement core is 100% deterministic: signatures, set
> math, and a discrete trust lattice. The one place ML belongs is the *detective* layer,
> which runs out of band and never blocks the live path.

---

## The model — AAA for agents

| | What it answers | How |
|---|---|---|
| **Authentication** | *Is this really the agent it claims, and does it hold the key?* | attested issuance (ed25519 CA) + proof-of-possession — a stolen bearer token is useless |
| **Authorization** | *May this agent do this, now, on this data, within budget?* | 5 deterministic checks (identity · RBAC · purpose · provenance · budget), **enforced** by a gateway |
| **Accounting** | *What happened, provably?* | hash-chained tamper-evident audit + spend ledger + append-only triage chronicle |

## Architecture

```
                                  ┌──────────────────────── GATEWAY (PEP) ────────────────────────┐
  mint_root ──attenuate(hops)──▶  │  AUTHN                    AUTHZ (PDP)              EXECUTE       │
  (macaroon capability token)     │  · attested issuance      · identity              · only path   │
        │                         │  · proof-of-possession ─▶ · RBAC  · purpose ──▶   to the real   │
   holder key bound               │    (defeats token theft)  · provenance · budget   tool callable │
                                  └───────┬───────────────────────┬───────────────────────┬────────┘
                                          │ deny                   │ every decision        │ event
                                          ▼                        ▼                       ▼
                                   triage chronicle        hash-chained audit        out-of-band
                                   (append-only)           (tamper-evident)          DETECTIVE sweep
                                                                                     (shadow triggers)
```

## The five authorization checks (all deterministic, fail-closed)

| # | Check | Blocks |
|---|---|---|
| 1 | **Identity** | forged / expired / unminted / unattested caller |
| 2 | **RBAC** | calling a capability you were never granted |
| 3 | **Purpose (PBAC)** | intent drift — acting outside your declared purpose |
| 4 | **Provenance (ABAC)** | acting on unvouched data (weakest-link, DB-authoritative — you can't self-claim a tier) |
| 5 | **Budget** | runaway cost (402-equivalent) |

## Modules

| File | Role |
|---|---|
| `seam7_delegation.py` | macaroon-style **capability tokens**: attenuation (narrow-only), cross-hop **accountability** (root survives every hop) vs **responsibility** (leaf actor), TTL, proof-of-work mint cost |
| `ed25519_ref.py` | pure-Python ed25519 (public-domain reference) — zero-dependency asymmetric signatures |
| `authn.py` | agent keypairs + **proof-of-possession** (defeats bearer-token theft) |
| `issuer.py` | the **attested-issuance authority** — an ed25519 CA binding `identity ↔ holder-key ↔ capability ceiling` |
| `agent_iam.py` | the **authorization decision point**: RBAC + PBAC + ABAC + budget, discrete trust lattice |
| `store.py` | SQLite persistence: authoritative provenance, spend ledger, hash-chained audit, mint ledger |
| `gateway.py` | the **enforcement point**: private tool registry, authN-before-authZ, execute-only-on-ALLOW |
| `detective.py` | out-of-band **shadow triggers** (injection / loop / fan-out / budget-velocity) — model-free |
| `schema.sql` | the 8-table SQLite schema (append-only audit + triage) |

## Quickstart

```python
from seam7_delegation import Cap, mint_root, attenuate
from agent_iam import Tool, TrustTier, ProvenanceRecord, Manifest
from store import Store
from issuer import Issuer
from authn import keypair, prove
from gateway import Gateway

KEY, now = b"verifier-key", 1_000_000.0
issuer = Issuer(b"\xaa" * 32)                       # the trust root (its pubkey is the anchor)
store  = Store(":memory:")
gw     = Gateway(store, KEY, trusted_issuers={issuer.public_key})

# a real tool, reachable ONLY through the gateway
gw.register(Tool("write_record", Cap.WRITE, TrustTier.ORG_ATTESTED, est_cost=1.0),
            lambda **kw: print("wrote", kw))

# an agent with a keypair, a minted root, a delegated + holder-bound token, and an attestation
sk, pk = keypair(seed=b"\x01" * 32)
root = mint_root(KEY, "principal:mgr", Cap.ALL, ttl_expires=now + 3600, budget=10.0, difficulty=8)
store.register_principal(root, minted_at=now)
tok  = attenuate(root, caps=Cap.WRITE, exp=now + 300, actor="agent:writer", holder=pk)
store.enroll(issuer.attest("principal:mgr", pk, Cap.WRITE))

# vouch a data source, then act on it
store.vouch("db-of-record", TrustTier.ORG_ATTESTED, "human:supervisor", at=now)
good = Manifest([ProvenanceRecord("db-of-record", TrustTier.ORG_ATTESTED)])

print(gw.invoke(tok, "write_record", Cap.WRITE, good, now,
                signer=lambda c: prove(sk, pk, c)).code)          # -> EXECUTED

bad = Manifest([ProvenanceRecord("slack-scrape", TrustTier.UNATTESTED)])
print(gw.invoke(tok, "write_record", Cap.WRITE, bad, now,
                signer=lambda c: prove(sk, pk, c)).code)          # -> PROVENANCE (unvouched data)

print(gw.invoke(tok, "write_record", Cap.WRITE, good, now, signer=None).code)  # -> AUTHENTICATION (stolen token, no key)
```

## Security properties (each has a test)

| Property | Test |
|---|---|
| A delegated token can only **narrow**, never widen | `test_seam7.py::test_cannot_widen_past_an_earlier_narrowing` |
| Accountability (root) **survives arbitrary delegation depth** and can't be swapped | `test_seam7.py::TestCrossHopAccountability` |
| Forgery / tamper / unknown-caveat rejected (fail closed) | `test_seam7.py::TestForgeryAndTamper` |
| A **stolen token without the private key** can't act | `test_gateway.py::test_stolen_token_without_key_is_blocked` |
| An **unattested principal** is rejected | `test_gateway.py::test_unattested_principal_rejected` |
| High-gravity action on **unvouched data** is blocked | `test_agent_iam.py::TestABACProvenance` |
| Provenance tiers are **DB-authoritative** (self-claims ignored) | `test_store.py::test_self_claimed_tier_is_ignored_until_vouched` |
| The audit log is **tamper-evident** | `test_store.py::test_chain_verifies_and_tamper_is_detected` |
| A tool **cannot fire without a fresh ALLOW** | `test_gateway.py::test_authz_denial_does_not_execute` |
| Shadow triggers catch injection / loops out of band | `test_detective.py` |

## Run it

```bash
python3 -m unittest            # 66 tests
python3 gateway.py             # end-to-end demo (theft + enforcement)
python3 detective.py           # out-of-band shadow triggers
python3 seam7_delegation.py    # token attenuation + attack demo
```

## Integrations

- **MCP control-plane server** (`mcp_server.py`) — exposes `mint_root` / `attenuate` /
  `vouch` / `authorize` / `verify` / `audit_query` as MCP tools over stdio JSON-RPC (pure
  stdlib, no SDK dependency). Any MCP host can drive governance through it. Run: `python3
  mcp_server.py`. This is the advisory/control-plane half.
- **Claude Code PreToolUse hook** (`hooks/`) — the **unbypassable** enforcement point for
  Claude agents: it runs before every tool call (the model can't skip it), maps
  irreversible actions to `ask` (a human vouch = AARP `PENDING`), hard-denies catastrophic
  ones, and hash-chains every decision to a tamper-evident audit. See
  [`hooks/README.md`](hooks/README.md).

## Honest limitations

- **`ed25519_ref.py` is a reference implementation** — not constant-time, ~ms/op. Swap
  libsodium / `cryptography` in production; the API (keypair/sign/verify over bytes) is identical.
- **The macaroon uses HMAC** for the caveat chain (correct for offline attenuation); the
  verifier holds that key. Asymmetric *identity* is layered on top via the issuer (`issuer.py`).
- **This is the preventative + detective pair, not content-correctness.** The gate checks
  *entitlement*; pair the detective layer with a statistical norm/anomaly sensor for full
  defense-in-depth.
- **No liveness reaper** — orphan authority dies on TTL (fails closed at the next call), but a
  running process isn't proactively killed.
- **The proof-of-work mint is one admissible anti-Sybil cost-source**, not the only one; the
  right source (authority mint vs device attestation) is a deployment decision.

## Standards alignment

This library **adopts the emerging agent-identity standards where they exist and adds the
few things they don't** — SPIFFE (identity), OIDF AuthZEN + AARP (authorization + approval),
OIDF OBO (delegation), Certificate-Transparency-style audit, aligned with CoSAI. The novel
layers are offline capability tokens, data-provenance tiers, and graduated-autonomy
containment. Full mapping (adopt vs. novel, module by module) in **[STANDARDS.md](STANDARDS.md)**.

## Provenance

Extracted from the **[agent-law](https://github.com/ckhamitkar/agent-law)** research project.
There, this layer is "Seam 7 — cross-hop delegation binding": the identity mechanism the
doctrine flagged as the highest-value thing to build. That repo carries the theory (the
vertical/horizontal governance model, the Sybil-cost analysis, and the honest seams).

## License

MIT — see [LICENSE](LICENSE).
