#!/usr/bin/env python3
"""
agentic-iam PreToolUse hook -- the UNBYPASSABLE enforcement point for Claude Code agents.

An MCP tool an agent can *choose* to call is not a PEP. A Claude Code PreToolUse hook is:
it runs OUTSIDE the model's control before every tool call, and the model cannot skip it.
This is the right home for the enforcement half of agentic-iam.

What it enforces: the REVERSIBILITY FLOOR. Read-only and reversible actions run; an
IRREVERSIBLE / high-gravity action is not silently executed -- it maps to AARP's PENDING,
surfaced as Claude Code's `ask` (the human vouch happens in the CC permission prompt).
A few catastrophic patterns are hard-`deny`ed. Every decision is appended to a
hash-chained, tamper-evident audit (the Certificate-Transparency idea, for the agent's
own tool calls).

Fail-open by design: any error in the hook returns `allow` (a gate bug must never brick a
session); the hard-deny patterns are simple and robust.

Wire it via .claude/settings.json (see hooks/README.md). Pure stdlib.
"""

import hashlib
import json
import os
import re
import sys

AUDIT_PATH = os.path.expanduser("~/.agentic-iam/hook-audit.jsonl")

READ_ONLY_TOOLS = {"Read", "Grep", "Glob", "LS", "NotebookRead",
                   "WebFetch", "WebSearch", "TodoWrite"}
# Edits are reversible (recoverable via git); allow but they are still audited.
REVERSIBLE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}

# Catastrophic + irrecoverable -> hard DENY.
DENY_PATTERNS = [
    r"\brm\s+-rf?\s+(/|~|\$HOME)(\s|$)",       # rm -rf / , ~ , $HOME
    r"\bmkfs\b", r"\bdd\b[^|]*\bof=/dev/",      # format / raw-write a device
    r":\(\)\s*\{.*\}\s*;\s*:",                  # fork bomb
    r"\bchmod\s+-R\s+777\s+/(\s|$)",
    r"\bgit\s+push\b[^\n]*--force[^\n]*\b(main|master)\b",  # force-push a protected branch
]
# Irreversible but sometimes legitimate -> ASK (route to a human vouch).
ASK_PATTERNS = [
    r"\brm\s+-rf?\b", r"\bgit\s+push\b[^\n]*(--force|-f)\b", r"\bgit\s+reset\s+--hard\b",
    r"\bgit\s+clean\s+-[a-z]*f", r"\bshutdown\b", r"\breboot\b", r"\bkill\s+-9\b",
    r"\bsudo\b", r"\bDROP\s+TABLE\b", r"\bTRUNCATE\b", r"\b>\s*/dev/sd",
    r"\bcurl\b[^\n]*\|\s*(sh|bash)\b", r"\bwget\b[^\n]*\|\s*(sh|bash)\b",
]


def _segments(command: str):
    return [s.strip() for s in re.split(r"[\n;]|&&|\|\|", command or "") if s.strip()]


def classify(tool_name: str, tool_input: dict):
    """Return (decision, reason) where decision is allow | ask | deny."""
    if tool_name in READ_ONLY_TOOLS:
        return "allow", "read-only tool"
    if tool_name in REVERSIBLE_TOOLS:
        return "allow", "reversible edit (recoverable via version control)"
    if tool_name == "Bash":
        cmd = (tool_input or {}).get("command", "")
        for seg in _segments(cmd):
            for p in DENY_PATTERNS:
                if re.search(p, seg, re.IGNORECASE):
                    return "deny", f"catastrophic/irreversible pattern: /{p}/"
        for seg in _segments(cmd):
            for p in ASK_PATTERNS:
                if re.search(p, seg, re.IGNORECASE):
                    return "ask", f"irreversible action needs a human vouch: /{p}/"
        return "allow", "reversible shell command"
    # Unknown / MCP tools: allow by default, but audited.
    return "allow", f"unclassified tool {tool_name!r} (audited)"


def _audit(entry: dict):
    try:
        os.makedirs(os.path.dirname(AUDIT_PATH), exist_ok=True)
        prev = ""
        if os.path.exists(AUDIT_PATH):
            with open(AUDIT_PATH) as f:
                last = None
                for line in f:
                    if line.strip():
                        last = line
                if last:
                    prev = json.loads(last).get("row_hash", "")
        entry["prev_hash"] = prev
        entry["row_hash"] = hashlib.sha256(
            (prev + json.dumps(entry, sort_keys=True)).encode()).hexdigest()
        with open(AUDIT_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass   # never block a tool call because the audit failed


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)   # can't parse -> fail open

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    try:
        decision, reason = classify(tool_name, tool_input)
    except Exception:
        decision, reason = "allow", "classifier error (fail open)"

    _audit({"session": payload.get("session_id"), "tool": tool_name,
            "decision": decision, "reason": reason,
            "input": {k: str(v)[:200] for k, v in tool_input.items()}})

    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": f"agentic-iam: {reason}",
    }}))
    sys.exit(0)


if __name__ == "__main__":
    main()
