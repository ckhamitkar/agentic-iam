#!/usr/bin/env python3
"""Tests for the MCP control-plane server (drives dispatch() directly, no stdio)."""

import json
import unittest

import mcp_server
from mcp_server import dispatch

READ, WRITE, ORG = 1, 4, 2


class TestMCPServer(unittest.TestCase):
    def setUp(self):
        mcp_server._store = None          # isolate: fresh in-memory store per test
        mcp_server.DB = ":memory:"

    def call(self, name, args):
        r = dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": name, "arguments": args}})
        self.assertNotIn("isError", r["result"], msg=r)
        return json.loads(r["result"]["content"][0]["text"])

    def test_handshake_and_tool_list(self):
        init = dispatch({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}})
        self.assertEqual(init["result"]["protocolVersion"], mcp_server.PROTOCOL_VERSION)
        self.assertEqual(init["result"]["serverInfo"]["name"], "agentic-iam")
        tl = dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = {t["name"] for t in tl["result"]["tools"]}
        self.assertEqual(names, {"mint_root", "attenuate", "vouch", "authorize",
                                 "verify", "audit_query"})

    def test_full_control_plane_flow_with_aarp(self):
        token = self.call("mint_root",
                          {"principal": "spiffe://td/agent/mgr", "caps": 127, "now": 0})["token"]
        tool = {"name": "write_record", "required_caps": WRITE, "risk_floor": ORG, "reversible": True}

        # unvouched source -> AARP PENDING (approvable via a vouch)
        d1 = self.call("authorize", {"token": token, "tool": tool,
                                     "declared_purpose": WRITE, "sources": ["src1"], "now": 0})
        self.assertEqual(d1["state"], "PENDING")
        self.assertIsNotNone(d1["prerequisite"])
        self.assertIsNotNone(d1["request_handle"])

        # vouch the source -> now PERMIT
        self.call("vouch", {"source_id": "src1", "tier": ORG, "attested_by": "human:sup", "at": 0})
        d2 = self.call("authorize", {"token": token, "tool": tool,
                                     "declared_purpose": WRITE, "sources": ["src1"], "now": 0})
        self.assertEqual(d2["state"], "PERMIT")

        # verify + audit
        v = self.call("verify", {"token": token, "now": 0})
        self.assertTrue(v["valid"])
        self.assertEqual(v["accountable_root"], "spiffe://td/agent/mgr")
        aud = self.call("audit_query", {"limit": 10})
        self.assertTrue(aud["chain_intact"])
        self.assertGreaterEqual(len(aud["decisions"]), 2)

    def test_attenuate_narrows(self):
        token = self.call("mint_root", {"principal": "p", "caps": 127, "now": 0})["token"]
        att = self.call("attenuate", {"token": token, "caps": READ, "actor": "child"})
        v = self.call("verify", {"token": att["token"], "now": 0})
        self.assertEqual(v["caps"], READ)
        self.assertEqual(v["actor"], "child")

    def test_unknown_tool_is_an_error(self):
        r = dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "nope", "arguments": {}}})
        self.assertIn("error", r)


if __name__ == "__main__":
    unittest.main(verbosity=2)
