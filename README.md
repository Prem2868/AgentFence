# AgentFence

**Offline-first policy testing and audit summaries for AI-agent tool calls.** AgentFence evaluates recorded or synthetic tool-call events against a small, explicit JSON policy. It does not call models, contact network services, launch tools, or claim to enforce a live agent runtime.

## Why this exists

Prompt-injection detectors inspect suspicious inputs. AgentFence focuses on a separate question: given a proposed tool and action, does a local policy allow it, deny it, or require a human approval step? That makes it useful for policy unit tests, trace review, and CI checks without depending on an LLM.

## Quick start

Requires Python 3.10+; runtime uses only the standard library.

```bash
python cli.py --policy examples/policy.json --events examples/events.jsonl
```

Input is JSON Lines, one object per proposed tool call:

```json
{"event_id":"evt-1","tool":"search_docs","action":"query","arguments":{"query":"local docs"}}
```

Each output line is a JSON decision with event ID, tool/action, reason, optional timestamp, and a SHA-256 digest of canonicalized arguments. **Argument values are not copied to output.** The digest may still reveal equality between repeated argument sets; do not treat it as anonymization for low-entropy or sensitive values.

## Policy format

```json
{
  "version": 1,
  "default_effect": "deny",
  "rules": [
    {"tool": "search_docs", "action": "query", "effect": "allow", "reason": "Read-only search"},
    {"tool": "workspace", "action": "write_file", "effect": "require_approval", "reason": "Human review"},
    {"tool": "shell", "action": "*", "effect": "deny", "reason": "Not allowed"}
  ]
}
```

Tool/action values may be exact strings or `"*"`. With multiple matching rules, `deny` overrides `require_approval`, which overrides `allow`. If no rule matches, `default_effect` applies; the default is `deny`. `require_approval` is only a decision result: AgentFence does not collect approval, execute a call, or turn approval into permission.

## CI usage

The CLI streams one JSON decision per input event. `--fail-on` controls the process exit status:

```bash
python cli.py --policy examples/policy.json --events examples/events.jsonl --fail-on require_approval
```

Options are `deny` (default), `require_approval`, or `never`. Invalid policies or malformed events exit with status 2; a matching `--fail-on` decision exits 1.

Run tests with:

```bash
python -m pytest -q
```

## Security boundary and limitations

AgentFence is an **evaluation helper**, not an enforcement proxy or sandbox. A caller must independently enforce decisions before any real tool executes. The MVP supports exact tool/action matching only. It does not validate argument schemas, path traversal, identity, delegated authority, policy signatures, time limits, revocation, or tamper-evident audit storage. Rules are only as trustworthy as the policy file and the event producer. Keep policies and raw traces access-controlled, and test the integration in a disposable environment before relying on it.

No real credentials or sensitive operational traces belong in examples or tests. Contributions should add deterministic tests for both allowed and denied cases.

## Project status

Early MVP. The policy format is intentionally small and may change before a stable release. This project is not affiliated with or certified by OWASP, NIST, or any standards body.
