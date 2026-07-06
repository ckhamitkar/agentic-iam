# agentic-iam PreToolUse hook

The **unbypassable enforcement point** for Claude Code agents. A `PreToolUse` hook runs
outside the model's control before every tool call — the model cannot skip it — so it is
a real PEP (unlike an MCP tool the agent chooses to call).

It enforces the **reversibility floor**: read-only/reversible actions run; an irreversible
one maps to AARP's `PENDING`, surfaced as Claude Code's **`ask`** (the human vouch happens
in the permission prompt); a few catastrophic patterns are hard-**`deny`**ed. Every
decision is appended to a hash-chained tamper-evident audit at `~/.agentic-iam/hook-audit.jsonl`.

## Install

Add to `~/.claude/settings.json` (or a project `.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|MultiEdit",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /ABSOLUTE/PATH/TO/agentic-iam/hooks/pretooluse_gate.py"
          }
        ]
      }
    ]
  }
}
```

Use the absolute path to `pretooluse_gate.py`. Match more tools by widening the `matcher`
(e.g. add `|mcp__.*` to gate MCP tool calls too).

## Decision mapping

| Tool call | Decision | Claude Code effect |
|---|---|---|
| `Read`, `Grep`, `Glob`, `LS`, `WebFetch`, … | `allow` | runs |
| `Write` / `Edit` (recoverable via git) | `allow` | runs (audited) |
| `Bash` reversible (`ls`, `git status`, tests) | `allow` | runs |
| `Bash` irreversible (`rm -rf dir`, `git push --force`, `sudo`, …) | `ask` | you are prompted — approving **is** the human vouch |
| `Bash` catastrophic (`rm -rf /`, force-push to `main`, `mkfs`, fork bomb) | `deny` | blocked |

Fail-open: any error in the hook returns `allow` — a gate bug never bricks a session.

## Audit

```bash
cat ~/.agentic-iam/hook-audit.jsonl        # every tool-call decision, hash-chained
```
Each line carries `prev_hash`/`row_hash`; editing or deleting a line breaks the chain
downstream (Certificate-Transparency-style, for the agent's own actions).
