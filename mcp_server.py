#!/usr/bin/env python3
"""
MCP control-plane server for agentic-iam.

Exposes the CONTROL PLANE (mint / attenuate / vouch / authorize / verify / audit) as MCP
tools, so any MCP host (Claude Desktop/Code, other agents) can drive governance over a
standard interface. This is the ADVISORY / management half: a supervisor or human-facing
agent calls these. The unbypassable ENFORCEMENT half is the PreToolUse hook (hooks/) and
the in-process gateway -- an MCP tool an agent can *choose* to call is not a PEP.

Transport: MCP stdio = newline-delimited JSON-RPC 2.0 over stdin/stdout. Implemented in
pure stdlib (no `mcp` SDK dependency) so it runs anywhere; the protocol is the same one
real hosts speak. `dispatch()` is exposed for direct testing without stdio.

Config (env): AGENTIC_IAM_KEY (verifier secret), AGENTIC_IAM_DB (sqlite path).
"""

import json
import os
import sys

from seam7_delegation import Cap, Token, mint_root, attenuate, verify, InvalidToken
from agent_iam import Tool, TrustTier, ProvenanceRecord, Manifest, Request
from store import Store

PROTOCOL_VERSION = "2024-11-05"
ROOT_SECRET = os.environ.get("AGENTIC_IAM_KEY", "agentic-iam-mcp-dev-key").encode()
DB = os.environ.get("AGENTIC_IAM_DB", os.path.expanduser("~/.agentic-iam/control-plane.db"))

_store = None


def store() -> Store:
    global _store
    if _store is None:
        d = os.path.dirname(DB)
        if d:
            os.makedirs(d, exist_ok=True)
        _store = Store(DB)
    return _store


def _tok_json(t: Token) -> dict:
    return {"identifier": t.identifier, "sig": t.sig, "caveats": t.caveats}


def _tok(d: dict) -> Token:
    return Token(identifier=d["identifier"], sig=d["sig"], caveats=d.get("caveats", []))


# --- control-plane tool handlers ----------------------------------------------------
def h_mint_root(a):
    now = a.get("now", 0.0)
    t = mint_root(ROOT_SECRET, a["principal"], Cap(a.get("caps", int(Cap.ALL))),
                  ttl_expires=now + a.get("ttl_seconds", 3600),
                  budget=a.get("budget", 100.0), difficulty=a.get("difficulty", 8))
    store().register_principal(t, minted_at=now)
    return {"token": _tok_json(t)}


def h_attenuate(a):
    t = _tok(a["token"])
    kw = {}
    if "caps" in a:   kw["caps"] = Cap(a["caps"])
    if "exp" in a:    kw["exp"] = a["exp"]
    if "budget" in a: kw["budget"] = a["budget"]
    if "actor" in a:  kw["actor"] = a["actor"]
    if "holder" in a: kw["holder"] = a["holder"]
    return {"token": _tok_json(attenuate(t, **kw))}


def h_vouch(a):
    tier = TrustTier(a["tier"])
    store().vouch(a["source_id"], tier, a.get("attested_by", "mcp"), at=a.get("at", 0.0))
    return {"ok": True, "source_id": a["source_id"], "tier": tier.name}


def h_authorize(a):
    td = a["tool"]
    tool = Tool(td["name"], Cap(td.get("required_caps", 0)), TrustTier(td.get("risk_floor", 0)),
                est_cost=td.get("est_cost", 0.0), reversible=td.get("reversible", True))
    manifest = Manifest([ProvenanceRecord(s, TrustTier.UNATTESTED) for s in a.get("sources", [])])
    purpose = Cap(a.get("declared_purpose", td.get("required_caps", 0)))
    d = store().authorize(Request(_tok(a["token"]), tool, purpose, manifest, a.get("now", 0.0)),
                          ROOT_SECRET)
    return {"state": str(d.state.value), "allowed": d.allowed, "code": d.code,
            "reason": d.reason, "prerequisite": d.prerequisite,
            "request_handle": d.request_handle}


def h_verify(a):
    try:
        c = verify(_tok(a["token"]), ROOT_SECRET, now=a.get("now"))
        return {"valid": True, "accountable_root": c.accountable_root, "actor": c.actor,
                "caps": int(c.caps), "exp": c.exp, "budget": c.budget,
                "depth": c.depth, "holder": c.holder}
    except InvalidToken as e:
        return {"valid": False, "error": str(e)}


def h_audit_query(a):
    rows = store().conn.execute(
        "SELECT seq,ts,code,accountable_root,actor,tool FROM decision_audit "
        "ORDER BY seq DESC LIMIT ?", (a.get("limit", 20),)).fetchall()
    return {"chain_intact": store().audit.verify_chain(),
            "decisions": [dict(r) for r in rows]}


_CAPS_DESC = "capability bitmask (READ=1 ENRICH=2 WRITE=4 DELETE=8 SPEND=16 SPAWN=32 RED_FLAG=64)"
_TIER_DESC = "trust tier (0 UNATTESTED, 1 SELF_SIGNED, 2 ORG_ATTESTED, 3 HUMAN_VOUCHED)"

TOOLS = {
    "mint_root": {
        "handler": h_mint_root,
        "description": "Mint a root principal + capability token (proof-of-work cost).",
        "inputSchema": {"type": "object", "required": ["principal"], "properties": {
            "principal": {"type": "string", "description": "SPIFFE id / principal name"},
            "caps": {"type": "integer", "description": _CAPS_DESC},
            "ttl_seconds": {"type": "number"}, "budget": {"type": "number"},
            "difficulty": {"type": "integer"}, "now": {"type": "number"}}},
    },
    "attenuate": {
        "handler": h_attenuate,
        "description": "Delegate a narrowed child token (caps/exp/budget can only shrink).",
        "inputSchema": {"type": "object", "required": ["token"], "properties": {
            "token": {"type": "object"}, "caps": {"type": "integer", "description": _CAPS_DESC},
            "exp": {"type": "number"}, "budget": {"type": "number"},
            "actor": {"type": "string"}, "holder": {"type": "string"}}},
    },
    "vouch": {
        "handler": h_vouch,
        "description": "Vouch a data source to a trust tier (the AARP/HITL prerequisite).",
        "inputSchema": {"type": "object", "required": ["source_id", "tier"], "properties": {
            "source_id": {"type": "string"}, "tier": {"type": "integer", "description": _TIER_DESC},
            "attested_by": {"type": "string"}, "at": {"type": "number"}}},
    },
    "authorize": {
        "handler": h_authorize,
        "description": "Run the deterministic PDP. Returns PERMIT/DENY/PENDING (AARP).",
        "inputSchema": {"type": "object", "required": ["token", "tool"], "properties": {
            "token": {"type": "object"},
            "tool": {"type": "object", "required": ["name"], "properties": {
                "name": {"type": "string"}, "required_caps": {"type": "integer"},
                "risk_floor": {"type": "integer"}, "est_cost": {"type": "number"},
                "reversible": {"type": "boolean"}}},
            "declared_purpose": {"type": "integer"},
            "sources": {"type": "array", "items": {"type": "string"}},
            "now": {"type": "number"}}},
    },
    "verify": {
        "handler": h_verify,
        "description": "Verify a token; return its effective claims (or invalid).",
        "inputSchema": {"type": "object", "required": ["token"], "properties": {
            "token": {"type": "object"}, "now": {"type": "number"}}},
    },
    "audit_query": {
        "handler": h_audit_query,
        "description": "Read recent decisions from the tamper-evident audit log.",
        "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer"}}},
    },
}


# --- JSON-RPC 2.0 / MCP dispatch -----------------------------------------------------
def _result(id_, result):
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _error(id_, code, message):
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def dispatch(msg: dict):
    """Handle one JSON-RPC message. Returns a response dict, or None for notifications."""
    method = msg.get("method")
    id_ = msg.get("id")
    if method == "initialize":
        return _result(id_, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "agentic-iam", "version": "0.1.0"}})
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return _result(id_, {"tools": [
            {"name": n, "description": t["description"], "inputSchema": t["inputSchema"]}
            for n, t in TOOLS.items()]})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        tool = TOOLS.get(name)
        if tool is None:
            return _error(id_, -32602, f"unknown tool {name!r}")
        try:
            out = tool["handler"](args)
            return _result(id_, {"content": [{"type": "text", "text": json.dumps(out)}]})
        except Exception as e:  # tool-level error, surfaced as isError (per MCP)
            return _result(id_, {"content": [{"type": "text", "text": f"error: {e}"}],
                                 "isError": True})
    if id_ is not None:
        return _error(id_, -32601, f"method not found: {method}")
    return None


def main():  # pragma: no cover - stdio loop
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = dispatch(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
