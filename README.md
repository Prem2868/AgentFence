# AgentFence

**Offline-first policy testing and audit summaries for AI-agent tool calls.** AgentFence evaluates recorded or synthetic tool-call events against a small, explicit JSON policy. It does not call models, contact network services, launch tools, or claim to enforce a live agent runtime.

## Why this exists

Prompt-injection detectors inspect suspicious inputs. AgentFence focuses on a separate question: given a proposed tool and action, does a local policy allow it, deny it, or require a human approval step? That makes it useful for policy unit tests, trace review, and CI checks without depending on an LLM.

## Usage

Requires Python 3.10+. Runtime dependencies are standard-library only; install pytest only if you want to run the tests.

### 1. Install and enter the repository

```bash
git clone https://github.com/Prem2868/AgentFence.git
cd AgentFence
python -m pip install -e .
```

For development and tests, use `python -m pip install -e '.[test]'` instead.

### 2. Define the policy

Create `policy.json`. Start with `default_effect: "deny"`, then explicitly allow only the tool/action pairs the agent needs. This example allows read-only search, requires a human checkpoint for file writes, and denies shell execution:

```json
{
  "version": 1,
  "default_effect": "deny",
  "rules": [
    {"tool": "search_docs", "action": "query", "effect": "allow", "reason": "Read-only documentation search"},
    {"tool": "workspace", "action": "write_file", "effect": "require_approval", "reason": "Review file changes first"},
    {"tool": "shell", "action": "*", "effect": "deny", "reason": "Shell is not permitted"}
  ]
}
```

### 3. Prepare a JSONL event trace

Save one proposed tool call per line in `events.jsonl`. Use synthetic data when learning the format:

```jsonl
{"event_id":"evt-001","tool":"search_docs","action":"query","arguments":{"query":"local security docs"}}
{"event_id":"evt-002","tool":"workspace","action":"write_file","arguments":{"path":"notes.txt","content":"example"}}
{"event_id":"evt-003","tool":"shell","action":"run","arguments":{"command":"whoami"}}
{"event_id":"evt-004","tool":"unknown_tool","action":"execute","arguments":{}}
```

### 4. Evaluate the trace

```bash
agentfence --policy policy.json --events events.jsonl
```

AgentFence prints one JSON result per input event. The example produces decisions `allow`, `require_approval`, `deny`, and `deny`, respectively. For example:

```json
{"action":"query","arguments_sha256":"…","decision":"allow","event_id":"evt-001","reason":"Read-only documentation search","tool":"search_docs"}
```

Each result contains the event ID, tool/action, decision, reason, optional timestamp, and a SHA-256 digest of canonicalized arguments. **Argument values are not copied to output.** The digest can still reveal equality between repeated argument sets; it is not anonymization for low-entropy or sensitive values. Avoid storing raw production traces unless your privacy and retention controls allow it.

You can also run the CLI from a checkout without installing it: `python cli.py --policy policy.json --events events.jsonl`. Use `--events -` to read JSONL from standard input.

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
