#!/usr/bin/env python3
"""Tests for the PreToolUse gate's classifier. Pure stdlib unittest."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "hooks"))
from pretooluse_gate import classify   # noqa: E402


def bash(cmd):
    return classify("Bash", {"command": cmd})[0]


class TestClassifier(unittest.TestCase):
    def test_read_only_allowed(self):
        self.assertEqual(classify("Read", {"file_path": "/x"})[0], "allow")
        self.assertEqual(classify("Grep", {"pattern": "x"})[0], "allow")

    def test_edits_allowed_as_reversible(self):
        self.assertEqual(classify("Write", {"file_path": "/x"})[0], "allow")
        self.assertEqual(classify("Edit", {})[0], "allow")

    def test_benign_bash_allowed(self):
        self.assertEqual(bash("ls -la && git status"), "allow")
        self.assertEqual(bash("python3 -m pytest"), "allow")

    def test_irreversible_bash_asks(self):
        self.assertEqual(bash("rm -rf build/"), "ask")
        self.assertEqual(bash("git push --force origin feature"), "ask")
        self.assertEqual(bash("git reset --hard HEAD~3"), "ask")
        self.assertEqual(bash("sudo systemctl restart nginx"), "ask")

    def test_catastrophic_bash_denied(self):
        self.assertEqual(bash("rm -rf /"), "deny")
        self.assertEqual(bash("rm -rf ~"), "deny")
        self.assertEqual(bash("git push --force origin main"), "deny")

    def test_bypass_via_chaining_is_caught(self):
        # the classifier checks EVERY segment, not just the prefix
        self.assertEqual(bash("ls && rm -rf build"), "ask")
        self.assertEqual(bash("echo hi; rm -rf /"), "deny")

    def test_unknown_tool_allowed_but_audited(self):
        self.assertEqual(classify("mcp__something__do", {})[0], "allow")


if __name__ == "__main__":
    unittest.main(verbosity=2)
