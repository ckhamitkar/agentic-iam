-- ============================================================================
-- Agent IAM / Seam 7 -- persistence schema (SQLite, local-first, offline).
--
-- STATUS: this is the schema the BUILT mechanisms imply. The current spike
-- (seam7_delegation.py + agent_iam.py) is 100% in-memory: SpendLedger is a dict,
-- tokens are bearer dataclasses, TriageSink is a list. Nothing here is wired yet.
-- Each table is annotated with the code artifact it backs so it is derived from
-- the build, not decorated onto it.
--
-- Conventions:
--   * caps / purpose columns are INTEGER bitmasks (seam7_delegation.Cap).
--   * trust tiers are INTEGER 0..3 (agent_iam.TrustTier): 0 UNATTESTED,
--     1 SELF_SIGNED, 2 ORG_ATTESTED, 3 HUMAN_VOUCHED.
--   * timestamps are REAL epoch seconds (matches `now` in the code).
--   * tables marked APPEND-ONLY must never take UPDATE/DELETE (enforced by
--     triggers below + operational discipline) -- this is the NFR-2 requirement
--     from governance-wall-and-flag/PRD_LOOP.md ("immutable, append-only,
--     tamper-evident; agents MUST NOT modify their own logs").
-- ============================================================================

PRAGMA foreign_keys = ON;

-- ----------------------------------------------------------------------------
-- 1. principal  --  the MINT LEDGER.   backs: seam7_delegation.mint_root()
--    A root principal is scarce (cost mint_cost(difficulty)=2**difficulty) and
--    LONG-LIVED. It persists so reputation/accountability can attach to it and
--    so a re-mint (shedding history) is observably a NEW row, not a free reset.
--    The verifier key is NOT stored here -- only a reference to a secrets store.
-- ----------------------------------------------------------------------------
CREATE TABLE principal (
    root_id         TEXT PRIMARY KEY,          -- e.g. 'principal:triage-manager'
    caps            INTEGER NOT NULL,          -- Cap bitmask granted at mint
    ttl_expires     REAL    NOT NULL,          -- root TTL (epoch seconds)
    budget          REAL    NOT NULL,          -- root spend ceiling
    pow_nonce       INTEGER NOT NULL,          -- proof-of-work nonce
    pow_difficulty  INTEGER NOT NULL,          -- leading-zero-bit difficulty (sets c)
    key_ref         TEXT    NOT NULL,          -- pointer into a secrets store (NOT the key)
    minted_at       REAL    NOT NULL,
    revoked_at      REAL                       -- NULL = live; set to hard-kill a principal
);

-- ----------------------------------------------------------------------------
-- 1b. identity_attestation -- the SPIFFE SVID record + the role grant.  backs: issuer.SVID
--    SPIFFE/AuthZEN separation: the SIGNED columns (root_id=spiffe_id, holder,
--    not_after, trust_domain, issuer, sig) are the SVID -- identity only, attested by a
--    trusted CA (verifier holds the issuer PUBLIC key only). The `caps` column is NOT
--    part of the signed identity; it is the AuthZEN ROLE GRANT (the authorization
--    ceiling) held as policy and evaluated separately by the gateway.
-- ----------------------------------------------------------------------------
CREATE TABLE identity_attestation (
    root_id      TEXT PRIMARY KEY REFERENCES principal(root_id),  -- the SPIFFE ID
    holder       TEXT NOT NULL,            -- holder pubkey hex bound to this identity
    caps         INTEGER NOT NULL,         -- ROLE GRANT: authorization ceiling (NOT signed)
    not_after    REAL,                     -- SVID expiry (NULL = none)
    trust_domain TEXT,                     -- SPIFFE trust domain
    issuer       TEXT NOT NULL,            -- CA pubkey hex (the trust anchor / bundle)
    sig          TEXT NOT NULL,            -- ed25519 signature over the SVID identity claim
    enrolled_at  REAL NOT NULL
);

-- ----------------------------------------------------------------------------
-- 2. issued_token  --  OPTIONAL audit of delegations.  backs: attenuate()
--    Tokens are bearer credentials held by agents; you normally do NOT store
--    them. Persist issuance only if you want a delegation-tree audit. The chain
--    is (parent_sig -> sig); accountable_root is invariant down the whole chain.
-- ----------------------------------------------------------------------------
CREATE TABLE issued_token (
    sig             TEXT PRIMARY KEY,          -- the token's HMAC-chain signature (hex)
    parent_sig      TEXT,                      -- NULL for a root token
    accountable_root TEXT NOT NULL REFERENCES principal(root_id),
    actor           TEXT NOT NULL,             -- leaf who bears RESPONSIBILITY
    eff_caps        INTEGER NOT NULL,          -- folded (narrowed) effective caps
    eff_exp         REAL    NOT NULL,          -- folded effective TTL
    eff_budget      REAL    NOT NULL,
    depth           INTEGER NOT NULL,          -- delegation hops below the root
    issued_at       REAL    NOT NULL
);
CREATE INDEX idx_issued_root ON issued_token(accountable_root);

-- ----------------------------------------------------------------------------
-- 3. provenance_source  --  the TRUST ROOTS (ABAC).  backs: agent_iam.TrustTier
--    In the spike, Manifest records self-report a tier. In production the tier
--    is AUTHORITATIVE here -- authorize() should resolve a source_id to its
--    persisted tier, not trust the caller's claim. This is the "vouched-for
--    sources" table: the HITL "vouch via triage" loop INSERTs/UPDATEs rows here.
-- ----------------------------------------------------------------------------
CREATE TABLE provenance_source (
    source_id       TEXT PRIMARY KEY,          -- e.g. 'db-of-record', 'slack-scrape'
    tier            INTEGER NOT NULL CHECK (tier BETWEEN 0 AND 3),
    digest          TEXT,                      -- optional content hash binding
    attested_by     TEXT,                      -- who vouched (principal or human id)
    attested_at     REAL,
    expires_at      REAL                       -- NULL = no expiry; else re-vouch needed
);

-- ----------------------------------------------------------------------------
-- 4. tool_policy  --  RBAC + ABAC gravity map.   backs: agent_iam.Tool
--    Founder-supplied (PRD_LOOP: "the gravity map is founder-supplied, not
--    learned"). required_caps = RBAC; risk_floor = min provenance tier (ABAC).
-- ----------------------------------------------------------------------------
CREATE TABLE tool_policy (
    tool_name       TEXT PRIMARY KEY,
    required_caps   INTEGER NOT NULL,          -- Cap bitmask the tool needs
    risk_floor      INTEGER NOT NULL CHECK (risk_floor BETWEEN 0 AND 3),
    est_cost        REAL    NOT NULL DEFAULT 0.0
);

-- ----------------------------------------------------------------------------
-- 5. spend_ledger  --  budget accounting.   backs: agent_iam.SpendLedger
--    Mutable running total per accountable ROOT (accountability, not the leaf).
--    authorize() reads spent, and on ALLOW does spent += tool.est_cost.
-- ----------------------------------------------------------------------------
CREATE TABLE spend_ledger (
    accountable_root TEXT PRIMARY KEY REFERENCES principal(root_id),
    spent           REAL NOT NULL DEFAULT 0.0,
    window_start    REAL,                      -- for rate/velocity windows (detective)
    updated_at      REAL NOT NULL
);

-- ----------------------------------------------------------------------------
-- 6. triage_incident  --  the CHRONICLE (APPEND-ONLY).  backs: agent_iam._triage_packet
--    One row per DENY (preventative) or detective flag. resolution_* columns
--    close the loop: a human/supervisor vouches a source (UPDATE provenance_source)
--    and marks the incident resolved. Routes to an abstract sink, NEVER to the
--    clinical host triage.axionaiapps.com.
-- ----------------------------------------------------------------------------
CREATE TABLE triage_incident (
    incident_id     TEXT PRIMARY KEY,          -- deterministic: 'inc-' + sha256(body)[:12]
    control         TEXT NOT NULL,             -- 'preventative' | 'detective'
    code            TEXT NOT NULL,             -- IDENTITY|CAPABILITY|PURPOSE|PROVENANCE|BUDGET
    accountable_root TEXT REFERENCES principal(root_id),
    actor           TEXT,
    tool            TEXT,
    required_caps   INTEGER,
    required_tier   INTEGER,
    actual_tier     INTEGER,
    declared_purpose INTEGER,
    detail          TEXT,
    ts              REAL NOT NULL,
    resolved_by     TEXT,                      -- human/supervisor id (NULL = open)
    resolved_at     REAL,
    resolution      TEXT                        -- e.g. 'vouched db-of-record -> ORG_ATTESTED'
);
CREATE INDEX idx_incident_open ON triage_incident(resolved_at) WHERE resolved_at IS NULL;

-- ----------------------------------------------------------------------------
-- 7. decision_audit  --  TAMPER-EVIDENT log of EVERY decision (APPEND-ONLY).
--    backs: agent_iam.authorize() return value (allow AND deny). NFR-2's
--    "immutable, append-only, tamper-evident ledger": each row hashes the prior
--    row's hash into its own, so any edit/deletion breaks the chain downstream.
-- ----------------------------------------------------------------------------
CREATE TABLE decision_audit (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL NOT NULL,
    request_hash    TEXT NOT NULL,             -- sha256 of the canonical Request
    code            TEXT NOT NULL,             -- ALLOW | <deny code>
    accountable_root TEXT,
    actor           TEXT,
    tool            TEXT,
    prev_hash       TEXT NOT NULL,             -- row_hash of seq-1 ('' for the genesis row)
    row_hash        TEXT NOT NULL              -- sha256(prev_hash || this row's fields)
);

-- ----------------------------------------------------------------------------
-- 8. reputation  --  HORIZONTAL LAYER (Seam 9). NOT exercised by agent_iam yet.
--    Included so the schema is coherent with HORIZONTAL_LAYER.md: weight earned
--    only on resolved ground truth, decays to baseline, capped per principal.
--    Lives separate from `principal` because principal is immutable and this is
--    mutable. Left here as a forward hook, clearly labelled unbuilt.
-- ----------------------------------------------------------------------------
CREATE TABLE reputation (
    accountable_root TEXT PRIMARY KEY REFERENCES principal(root_id),
    weight          REAL NOT NULL DEFAULT 0.0,
    resolved_correct INTEGER NOT NULL DEFAULT 0,
    resolved_total  INTEGER NOT NULL DEFAULT 0,
    decayed_at      REAL
);

-- ----------------------------------------------------------------------------
-- Append-only enforcement for the two ledgers that must never be rewritten.
-- (Discipline, not a security boundary -- a DB admin can drop a trigger; the
--  real tamper-evidence is the decision_audit hash chain.)
-- ----------------------------------------------------------------------------
CREATE TRIGGER triage_incident_no_delete
BEFORE DELETE ON triage_incident
BEGIN SELECT RAISE(ABORT, 'triage_incident is append-only'); END;

CREATE TRIGGER decision_audit_no_update
BEFORE UPDATE ON decision_audit
BEGIN SELECT RAISE(ABORT, 'decision_audit is append-only'); END;

CREATE TRIGGER decision_audit_no_delete
BEFORE DELETE ON decision_audit
BEGIN SELECT RAISE(ABORT, 'decision_audit is append-only'); END;
