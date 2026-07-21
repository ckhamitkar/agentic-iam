# The agentic-iam ontology

*What the entities of the agent world are, how they relate, and which rules bind them.*

You cannot grant, deny, or audit what you cannot name. Classic IAM has a mature ontology
for humans and services — principal, role, group, service account — and every access
decision an enterprise makes rests on it. Agents do not fit that model: an agent acts *on
behalf of* a principal, spawns sub-agents, holds authority that was *delegated and should
attenuate* as it passes down, reasons on data of varying trust, and lives for minutes.

This document names the entity types agentic-iam actually models. It is not aspirational —
each entity is defined in code and exercised by the test suite. It is the schema the
deterministic control plane enforces, not a diagram beside it.

---

## The entities

| Entity | What it is | Defined in |
|---|---|---|
| **Principal** | A root authority. Minted with a proof-of-work cost, which makes principals *scarce* (the anti-Sybil property). A principal is the thing that can be held **accountable**. | `seam7_delegation.py` (`mint_root`) |
| **Agent (Actor)** | The acting entity at the working end of a delegation chain. Bound to a holder key and carrying **responsibility** for what it does (`actor`), while accountability stays with the root. | `seam7_delegation.py`, `authn.py` |
| **Issuer (Trust-domain CA)** | A SPIFFE/SPIRE-style certificate authority. Its public key is the **trust anchor** distributed to verifiers. Issues identity, never authority. | `issuer.py` |
| **SVID** | A SPIFFE Verifiable Identity Document: binds a **SPIFFE ID ↔ holder public key**, signed by the CA, short-lived and rotated. Attests *who a workload is* — deliberately never *what it may do*. | `issuer.py` |
| **SPIFFE ID** | The name of a workload: `spiffe://<trust-domain>/<path>`. The path mirrors the containment tree (`.../parent/child`), so a child's identity proves it lies within its parent's reach. | `issuer.py`, `containment.py` |
| **Capability** | What an agent *may do*, as a bitmask: `READ · ENRICH · WRITE · DELETE · SPEND · SPAWN · RED_FLAG`. Subset-checkable in one AND. | `seam7_delegation.py` (`Cap`) |
| **Capability Token** | A macaroon-style delegated credential carrying capabilities, TTL, budget, holder key, `actor`, and `accountable_root`. **Attenuable** — a holder can narrow it *without* the root key; the verifier detects any widening. | `seam7_delegation.py` |
| **Tool** | A privileged callable, declared with its **required capabilities** (RBAC) and a **risk floor** — the minimum data-trust tier required to invoke it (ABAC). Lives in a private registry with no public handle. | `agent_iam.py`, `gateway.py` |
| **Purpose** | A declared-intent capability mask (PBAC). A child acting outside its declared purpose is *intent drift* and is denied. | `agent_iam.py` |
| **Trust Tier** | The trustworthiness of a *data source*, as a discrete lattice — never a float: `UNATTESTED < SELF_SIGNED < ORG_ATTESTED < HUMAN_VOUCHED`. A sliding threshold is one an adversary slides past. | `provenance.py` (`TrustTier`) |
| **Provenance Record / Manifest** | The data lineage an agent reasoned on to reach a tool call. A manifest's trust is its **weakest link** (min tier) — garbage in, gospel out is exactly what this blocks. | `provenance.py` |
| **Autonomy Level (Containment state)** | How much an agent has *earned* the right to act on its own: `SHADOW → CONTAINED → SUPERVISED → TRUSTED`. Bounds an agent's **reach** (where it runs, whether it can be reaped), distinct from its authority. | `containment.py` |
| **Gateway (PEP)** | The Policy Enforcement Point. The only path to a tool: authenticate, authorize, apply containment, then execute — never before. | `gateway.py` |
| **Decision Point (PDP)** | `authorize()` — the five deterministic checks that return ALLOW/DENY. | `agent_iam.py` |
| **Ledgers** | Hash-chained, tamper-evident records: the audit chronicle, the spend ledger, the mint ledger — the **Accounting** in AAA. | `store.py`, `schema.sql` |
| **Detective** | Out-of-band shadow triggers (injection / loop / fan-out / budget-velocity). The one place a model is allowed — never on the live enforcement path. | `detective.py` |

---

## The three axes (why the ontology has more than one dimension)

The model's core claim is that three questions people usually collapse into one are
actually **orthogonal**, and each needs its own entity:

1. **Identity — *who are you?*** SPIFFE ID + SVID, issued by a CA. Says who a workload is,
   nothing about what it may do.
2. **Authority — *what may you do?*** The capability token: caps, TTL, budget, delegated
   and attenuating down the chain. Separate from identity by design (SPIFFE / AuthZEN
   separation of concerns).
3. **Reach — *where may you run, and can you be undone?*** Containment: the autonomy
   ladder and the isolation box. Trust here is *earned slowly, revoked instantly*, and
   only ever loosens **reversible** actions.

A fourth axis is agentic-iam's additive contribution over the standards:

4. **Data trust — *is what you reasoned on vouched for?*** The provenance lattice. Most
   agent-identity work gates on the agent and ignores the trust of the data that drove
   the action. This closes that gap.

---

## The relationships

```
  Issuer (CA) ──issues──▶ SVID ──binds──▶ SPIFFE ID ↔ holder key
      │                                         │
   trust anchor                          proves-possession (authn)
                                                │
  Principal ──mint_root(PoW)──▶ Capability Token ──attenuate(narrow-only)──▶ child Agent
      │                                │                                        │
   accountable_root ◀───survives every hop───┘                          actor (responsibility)
                                                │
                                        reasons-on ──▶ Manifest (weakest-link Trust Tier)
                                                │
                          Gateway (PEP): AUTHN ▶ AUTHZ (5 checks) ▶ CONTAINMENT ▶ EXECUTE
                                                │                        │
                                        Tool (required caps + risk floor)   Autonomy level
                                                │
                                        hash-chained audit + spend ledger
```

**The five authorization checks** (all deterministic, fail-closed, in order):
`IDENTITY → RBAC (capabilities) → PBAC (purpose) → ABAC (provenance vs. risk floor) → BUDGET`.

---

## The load-bearing invariants

These are the rules that make the ontology *govern* rather than merely describe. Each has a test.

- **Attenuation only narrows.** A delegated token can never widen capabilities, TTL, or
  budget past an earlier narrowing.
- **Accountability survives the chain.** Every token at any delegation depth is bound to
  its root principal; the leaf holds responsibility, the root holds accountability, and it
  cannot be swapped or shed without the root key and fresh proof-of-work. No orphan agent
  with nobody to answer for it.
- **Identity ≠ authority.** An SVID attests who a workload is and carries no capabilities;
  authority is a separate, separately-evaluated grant.
- **Trust is a discrete lattice, and a context is only as trusted as its weakest input.**
- **Provenance tiers are authoritative, not self-claimed.** A source's tier comes from the
  vouched-sources store; an agent cannot self-declare its data trustworthy.
- **The irreversible floor is always gated.** No autonomy level, however trusted, grants
  the capability to do something that cannot be undone without a fresh human vouch.
- **No model in the enforcement path.** Every ALLOW/DENY is signatures, set math, and the
  lattice. The one model that exists (Detective) runs out of band and never blocks.

---

## Standards alignment

agentic-iam is deliberately built on established shapes, then extends them:

- **SPIFFE / SPIRE** — identity issuance (`Issuer`, `SVID`, SPIFFE IDs).
- **OIDF AuthZEN** — the identity/authorization separation of concerns.
- **CoSAI** — governing principles for agentic systems.
- **Additive:** the **data-provenance trust lattice** — gating an action on the trust of
  the *data the agent reasoned on*, which the identity/authorization standards under-cover.

See `README.md` for the architecture diagram and the security-property test map, and run
`python3 -m unittest` for the full suite.
