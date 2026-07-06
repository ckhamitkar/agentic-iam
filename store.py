#!/usr/bin/env python3
"""
SQLite persistence adapter -- makes schema.sql load-bearing.

Swaps the in-memory pieces of agent_iam for durable, DB-backed ones that satisfy
the SAME interfaces, so agent_iam.authorize() runs unchanged:
  - SqliteSpendLedger  -> spend_ledger table          (backs SpendLedger)
  - SqliteTriageSink   -> triage_incident table       (backs TriageSink)
  - SqliteProvenance   -> provenance_source table      (AUTHORITATIVE ProvenanceResolver)
  - DecisionAuditLog   -> decision_audit table         (hash-chained, tamper-evident)
  - persist_principal  -> principal table              (the mint ledger)

The one behavioural upgrade over the spike: SqliteProvenance resolves each source_id
against the vouched-sources table and IGNORES the manifest's self-reported tier -- so a
caller can no longer claim ORG_ATTESTED for a source the system never vouched.

Pure stdlib (sqlite3). Deterministic given explicit `now`.
"""

import hashlib
import json
import os
import sqlite3

from agent_iam import TrustTier, Manifest, ProvenanceResolver, authorize as _authorize

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def connect(path: str = ":memory:") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    have = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='principal'"
    ).fetchone()
    if not have:
        with open(SCHEMA_PATH) as f:
            conn.executescript(f.read())
        conn.execute("PRAGMA foreign_keys = ON")   # re-assert after executescript
    return conn


def persist_principal(conn, token, key_ref="secretstore://root", minted_at=0.0):
    """Record a minted root so spend/incidents can FK to it and re-mints are visible."""
    i = token.identifier
    conn.execute(
        "INSERT OR IGNORE INTO principal"
        "(root_id,caps,ttl_expires,budget,pow_nonce,pow_difficulty,key_ref,minted_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (i["root"], i["caps"], i["exp"], i["budget"], i["nonce"], i["difficulty"],
         key_ref, minted_at))
    conn.commit()


class SqliteSpendLedger:
    def __init__(self, conn):
        self.conn = conn

    def spent(self, root: str) -> float:
        r = self.conn.execute(
            "SELECT spent FROM spend_ledger WHERE accountable_root=?", (root,)).fetchone()
        return r["spent"] if r else 0.0

    def charge(self, root: str, amount: float, now: float = 0.0) -> None:
        self.conn.execute(
            "INSERT INTO spend_ledger(accountable_root,spent,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(accountable_root) DO UPDATE SET "
            "spent = spent + excluded.spent, updated_at = excluded.updated_at",
            (root, amount, now))
        self.conn.commit()


class SqliteTriageSink:
    def __init__(self, conn):
        self.conn = conn

    def emit(self, p: dict) -> None:
        # INSERT OR IGNORE: incident_id is deterministic, so identical incidents dedupe.
        self.conn.execute(
            "INSERT OR IGNORE INTO triage_incident"
            "(incident_id,control,code,accountable_root,actor,tool,required_caps,"
            " required_tier,actual_tier,declared_purpose,detail,ts) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (p["incident_id"], p["control"], p["code"], p["accountable_root"], p["actor"],
             p["tool"], p["required_caps"], p["required_tier"], p["actual_tier"],
             p["declared_purpose"], p["detail"], p["now"]))
        self.conn.commit()


class SqliteProvenance(ProvenanceResolver):
    """Authoritative resolver: a source is worth the tier the DB says, not what the
    caller claims. Unknown source => UNATTESTED. min over the lineage = weakest link."""

    def __init__(self, conn):
        self.conn = conn

    def tier_of(self, source_id: str) -> TrustTier:
        r = self.conn.execute(
            "SELECT tier FROM provenance_source WHERE source_id=?", (source_id,)).fetchone()
        return TrustTier(r["tier"]) if r else TrustTier.UNATTESTED

    def min_tier(self, manifest: Manifest) -> TrustTier:
        if not manifest.records:
            return TrustTier.UNATTESTED
        return min((self.tier_of(rec.source_id) for rec in manifest.records),
                   default=TrustTier.UNATTESTED)

    def vouch(self, source_id: str, tier: TrustTier, attested_by: str, at: float = 0.0):
        """The HITL loop: a human/supervisor vouches a source, lifting its tier."""
        self.conn.execute(
            "INSERT INTO provenance_source(source_id,tier,attested_by,attested_at) "
            "VALUES(?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET "
            "tier=excluded.tier, attested_by=excluded.attested_by, attested_at=excluded.attested_at",
            (source_id, int(tier), attested_by, at))
        self.conn.commit()


class DecisionAuditLog:
    """Every decision (allow AND deny), hash-chained so any edit breaks the chain."""

    def __init__(self, conn):
        self.conn = conn

    def _last_hash(self) -> str:
        r = self.conn.execute(
            "SELECT row_hash FROM decision_audit ORDER BY seq DESC LIMIT 1").fetchone()
        return r["row_hash"] if r else ""

    @staticmethod
    def _row_hash(ts, request_hash, code, root, actor, tool, prev):
        return hashlib.sha256(
            f"{ts}|{request_hash}|{code}|{root}|{actor}|{tool}|{prev}".encode()).hexdigest()

    def record(self, req, decision) -> str:
        request_hash = hashlib.sha256(json.dumps({
            "tool": req.tool.name,
            "required_caps": int(req.tool.required_caps),
            "purpose": int(req.declared_purpose),
            "sources": sorted(r.source_id for r in req.manifest.records),
            "now": req.now,
        }, sort_keys=True).encode()).hexdigest()
        prev = self._last_hash()
        root = decision.claims.accountable_root if decision.claims else None
        actor = decision.claims.actor if decision.claims else None
        # Normalize ts to float so the hash matches on read-back from the REAL column
        # (an int `now` would hash as "0" on write but "0.0" on verify -> false mismatch).
        ts = float(req.now)
        row_hash = self._row_hash(ts, request_hash, decision.code, root, actor,
                                  req.tool.name, prev)
        self.conn.execute(
            "INSERT INTO decision_audit"
            "(ts,request_hash,code,accountable_root,actor,tool,prev_hash,row_hash) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (ts, request_hash, decision.code, root, actor, req.tool.name, prev, row_hash))
        self.conn.commit()
        return row_hash

    def verify_chain(self) -> bool:
        prev = ""
        for row in self.conn.execute("SELECT * FROM decision_audit ORDER BY seq"):
            expect = self._row_hash(row["ts"], row["request_hash"], row["code"],
                                    row["accountable_root"], row["actor"], row["tool"], prev)
            if row["prev_hash"] != prev or row["row_hash"] != expect:
                return False
            prev = row["row_hash"]
        return True


class Store:
    """Container wiring the DB-backed pieces into one govern() call point."""

    def __init__(self, path: str = ":memory:"):
        self.conn = connect(path)
        self.ledger = SqliteSpendLedger(self.conn)
        self.sink = SqliteTriageSink(self.conn)
        self.provenance = SqliteProvenance(self.conn)
        self.audit = DecisionAuditLog(self.conn)

    def register_principal(self, token, **kw):
        persist_principal(self.conn, token, **kw)

    def vouch(self, *a, **kw):
        self.provenance.vouch(*a, **kw)

    def enroll(self, svid, role_caps):
        """Persist a SPIFFE SVID (identity) + a role grant (the caps ceiling, held as
        AuthZEN policy -- NOT part of the signed identity document)."""
        self.conn.execute(
            "INSERT OR REPLACE INTO identity_attestation"
            "(root_id,holder,caps,not_after,trust_domain,issuer,sig,enrolled_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (svid.spiffe_id, svid.holder, int(role_caps), svid.not_after,
             svid.trust_domain, svid.issuer, svid.sig, 0.0))
        self.conn.commit()

    def svid_for(self, spiffe_id):
        """Return the SPIFFE SVID (identity) for a principal, or None."""
        from issuer import SVID
        r = self.conn.execute(
            "SELECT * FROM identity_attestation WHERE root_id=?", (spiffe_id,)).fetchone()
        if not r:
            return None
        return SVID(r["root_id"], r["holder"], r["not_after"], r["trust_domain"],
                    r["issuer"], r["sig"])

    def role_ceiling(self, spiffe_id):
        """The AuthZEN role grant: the max capabilities policy allows this identity."""
        from seam7_delegation import Cap
        r = self.conn.execute(
            "SELECT caps FROM identity_attestation WHERE root_id=?", (spiffe_id,)).fetchone()
        return Cap(r["caps"]) if r else Cap.NONE

    def register_tool(self, tool):
        self.conn.execute(
            "INSERT OR REPLACE INTO tool_policy(tool_name,required_caps,risk_floor,est_cost) "
            "VALUES(?,?,?,?)",
            (tool.name, int(tool.required_caps), int(tool.risk_floor), tool.est_cost))
        self.conn.commit()

    def authorize(self, req, root_secret):
        d = _authorize(req, root_secret, self.ledger, self.sink, self.provenance)
        self.audit.record(req, d)
        return d


# ----------------------------------------------------------------------------------
def _demo():
    from seam7_delegation import Cap, mint_root, attenuate
    from agent_iam import Tool, Request, ProvenanceRecord

    KEY = b"verifier-root-key"
    T0 = 1_000_000.0
    store = Store(":memory:")

    root = mint_root(KEY, "principal:triage-manager", Cap.ALL,
                     ttl_expires=T0 + 3600, budget=1.0, difficulty=8)
    store.register_principal(root, minted_at=T0)
    child = attenuate(root, caps=Cap.READ | Cap.WRITE, exp=T0 + 300, budget=1.0,
                      actor="agent:log-parser")
    write_db = Tool("write_record", Cap.WRITE, TrustTier.ORG_ATTESTED, est_cost=1.0)
    store.register_tool(write_db)

    print("=" * 76)
    print("STORE DEMO -- authorize() over SQLite; provenance is DB-authoritative")
    print("=" * 76)

    # Manifest CLAIMS the source is org-attested, but the DB has never vouched it.
    claimed = Manifest([ProvenanceRecord("partner-feed", TrustTier.ORG_ATTESTED)])
    d = store.authorize(Request(child, write_db, Cap.WRITE, claimed, T0), KEY)
    print(f"\n[a] source SELF-CLAIMS org-attested, DB unvouched -> {d.code}: {d.reason}")

    # A supervisor vouches it via triage -> now the same call passes.
    store.vouch("partner-feed", TrustTier.ORG_ATTESTED, attested_by="human:supervisor", at=T0)
    d = store.authorize(Request(child, write_db, Cap.WRITE, claimed, T0 + 1), KEY)
    print(f"[b] after HITL vouch of 'partner-feed'         -> {d.code}: {d.reason}")

    # Spend accumulates in the DB; the budget ceiling (2.0) bites on the 3rd write.
    d = store.authorize(Request(child, write_db, Cap.WRITE, claimed, T0 + 2), KEY)
    print(f"[c] 2nd write, spend would exceed ceiling 1.0  -> {d.code}: {d.reason}")

    inc = store.conn.execute("SELECT COUNT(*) n FROM triage_incident").fetchone()["n"]
    dec = store.conn.execute("SELECT COUNT(*) n FROM decision_audit").fetchone()["n"]
    spent = store.ledger.spent("principal:triage-manager")
    print(f"\n  persisted: {dec} audited decisions, {inc} triage incidents, spend={spent}")
    print(f"  decision_audit chain intact? {store.audit.verify_chain()}")

    # Tamper the audit log -> chain detects it (bypass the trigger via a raw handle).
    raw = store.conn
    raw.execute("PRAGMA foreign_keys=OFF")
    raw.execute("DROP TRIGGER decision_audit_no_update")
    raw.execute("UPDATE decision_audit SET code='ALLOW' "
                "WHERE seq=(SELECT MIN(seq) FROM decision_audit WHERE code!='ALLOW')")
    raw.commit()
    print(f"  after tampering one row -> chain intact? {store.audit.verify_chain()}  (detected)")


if __name__ == "__main__":
    _demo()
