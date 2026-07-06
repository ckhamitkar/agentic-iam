# Standards alignment

`agentic-iam` is built to **adopt the emerging agent-identity standards where they exist,
and add the two or three things they don't.** This document maps every module to the
standard it implements, and states plainly what is *adopted* versus what is *novel*.

The strategy: ride the standards' network effect (interoperate), keep a narrow, real
contribution (differentiate). Governance is a coverage problem — a widely-adopted standard
beats a better-but-isolated one — so alignment is the point, not a concession.

## The map

| This library | Module | Standard it implements | Verdict |
|---|---|---|---|
| Identity / CA | `issuer.py` | **SPIFFE/SPIRE** — trust-domain CA, SVID, trust bundle | **adopt** |
| Authorization decision (PDP) | `agent_iam.py` | **OIDF AuthZEN** — Subject/Action/Resource/Context | **adopt** |
| Approval flow | `agent_iam.py` (`PENDING`) | **AuthZEN AARP** — approvable-pending-a-prerequisite | **adopt** |
| Responsibility vs accountability | `seam7_delegation.py` (`actor` + `accountable_root`) | **OIDF OBO** — dual claims (acting + delegating) | **adopt** |
| Enforcement point (PEP) | `gateway.py` | **AuthZEN COAZ** — MCP tool authorization | **adopt** |
| Tamper-evident audit | `store.py` (`decision_audit`) | **Certificate Transparency**-style append-only log | **adopt** |
| Principles / no-orphan-agents | (whole design) | **CoSAI** Agentic IAM (OASIS) | **align + contribute** |
| **Offline capability tokens** | `seam7_delegation.py` | — (the literature chose centralized PDP) | **novel** |
| **Data-provenance tiers** | `provenance.py` | — (standards gate identity, not data trust) | **novel** |
| **Graduated-autonomy containment** | `containment.py` | — | **novel** |

## What is adopted

### SPIFFE / SPIRE — identity (`issuer.py`)
- `Issuer` is a **trust-domain CA**; its public key is the **trust bundle** root.
- `SVID` is a **SPIFFE Verifiable Identity Document**: it binds a **SPIFFE ID**
  (`spiffe://trust-domain/path`) to a holder public key, signed by the CA. Verifiers hold
  only the CA's public key (`Gateway.trusted_issuers` = the trust bundle).
- **Identity only.** An SVID attests *who*, never *what*. Capabilities are a separate
  policy concern — the store holds them as a **role grant** (`store.role_ceiling`), and the
  gateway checks the token's caps against it. This is the SPIFFE/AuthZEN separation.
- The SPIFFE ID **path mirrors the containment tree** (`…/parent/child`), so a child's
  identity proves it is within its parent's reach.

### OIDF AuthZEN — authorization (`agent_iam.py`, `gateway.py`)
- `authorize()` is a **Policy Decision Point**; `Gateway` is the **Policy Enforcement
  Point** (COAZ: an MCP-tool-authorization posture — the tool is uninvocable except
  through the gate).
- **AARP** (Access Request and Approval Profile): a provenance failure is *approvable*, so
  it returns **`PENDING`** with a `prerequisite` and a `request_handle` — routed to a vouch
  and re-evaluated — rather than a flat `DENY`. Structural failures (identity, RBAC,
  purpose, budget) stay hard `DENY`. *"A shift in shape, not in authority."*

### OIDF OBO — delegation (`seam7_delegation.py`)
- Every token carries the **acting agent** (`actor`, responsibility) and the **accountable
  root** (`accountable_root`, accountability) as **separate claims** — the OBO
  token-exchange shape, so an action always traces to who performed it *and* who answers
  for it.

### Certificate Transparency — audit (`store.py`)
- `decision_audit` is an **append-only, hash-chained** log: every row hashes the prior
  row's hash, so any edit or deletion breaks the chain downstream. Same idea as CT's public
  logs, applied to authorization decisions.

## What is novel (the contribution)

1. **Offline capability tokens** (`seam7_delegation.py`). The literature's deterministic
   pre-action authorization (e.g. arXiv 2603.20953) explicitly chose *centralized policy
   evaluation over capability tokens/macaroons*. This library takes the other fork:
   macaroon-style attenuation lets a parent delegate to a child **offline, with no PDP
   round-trip per hop**. That fits agent hierarchies at machine speed and edge/offline
   deployment — where a callback-per-action is a non-starter.

2. **Data-provenance tiers** (`provenance.py`). SPIFFE, AuthZEN, and CoSAI gate an action
   on the *agent's* identity and delegated authority. Almost none gate it on the **trust
   tier of the data the agent reasoned on**. The discrete lattice + weakest-link rule
   ("act only on vouched-for sources") is this library's clearest whitespace.

3. **Graduated-autonomy containment** (`containment.py`). A child is born in its parent's
   isolation box, starts in **shadow** (observe-only), and earns wider *reversible*
   autonomy through a verified track record — earned slowly, revoked instantly. The
   **irreversible floor is never opened by trust**. Reaping a parent tears down the whole
   subtree (no orphan processes). This unifies containment, reputation, and shadow-mode
   into one lifecycle.

## Relation to prior art

- **"Before the Tool Call: Deterministic Pre-Action Authorization for Autonomous AI
  Agents"** (arXiv 2603.20953) — same five-check thesis (identity, delegated permissions,
  provenance, capabilities); chose centralized PDP where this library chose capability
  tokens. Validates the approach; documents the fork.
- **CoSAI Agentic IAM** is an **open OASIS workstream** — the three novel layers above are
  the kind of contribution that belongs there.

## Sources

- SPIFFE Concepts — https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/
- OIDF AuthZEN (AARP + COAZ) — https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts/
- OIDF AI Identity Management CG — https://openid.net/cg/artificial-intelligence-identity-management-community-group/
- CoSAI Agentic IAM (OASIS) — https://www.oasis-open.org/2026/05/06/coalition-for-secure-ai-unveils-new-agentic-identity-and-security-research-following-high-profile-sessions-at-rsac-2026/
- "Before the Tool Call" — https://arxiv.org/pdf/2603.20953
