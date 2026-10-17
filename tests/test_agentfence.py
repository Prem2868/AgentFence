import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agentfence import PolicyError, evaluate  # noqa: E402


def test_default_is_deny_and_secrets_are_not_emitted():
    result = evaluate({"version": 1}, {"tool": "unknown", "action": "run", "arguments": {"token": "do-not-leak"}})
    assert result["decision"] == "deny"
    assert "do-not-leak" not in json.dumps(result)
    assert len(result["arguments_sha256"]) == 64


def test_argument_digest_is_canonical_and_content_sensitive():
    policy = {"version": 1}
    first = evaluate(policy, {"tool": "search", "arguments": {"query": "alpha", "scope": "docs"}})
    reordered = evaluate(policy, {"tool": "search", "arguments": {"scope": "docs", "query": "alpha"}})
    changed = evaluate(policy, {"tool": "search", "arguments": {"scope": "docs", "query": "beta"}})

    assert first["arguments_sha256"] == reordered["arguments_sha256"]
    assert first["arguments_sha256"] != changed["arguments_sha256"]


def test_allow_rule_matches_exact_tool_and_action():
    policy = {"version": 1, "rules": [{"tool": "search", "action": "query", "effect": "allow"}]}
    assert evaluate(policy, {"tool": "search", "action": "query"})["decision"] == "allow"
    assert evaluate(policy, {"tool": "search", "action": "delete"})["decision"] == "deny"


def test_approval_gate_and_deny_override_allow():
    policy = {"version": 1, "rules": [
        {"tool": "*", "action": "*", "effect": "allow"},
        {"tool": "workspace", "action": "write", "effect": "require_approval"},
        {"tool": "workspace", "action": "write", "effect": "deny", "reason": "blocked"},
    ]}
    assert evaluate(policy, {"tool": "workspace", "action": "write"})["decision"] == "deny"


def test_approval_gate_beats_broad_allow():
    policy = {"version": 1, "rules": [
        {"tool": "*", "action": "*", "effect": "allow"},
        {"tool": "workspace", "action": "write", "effect": "require_approval"},
    ]}
    assert evaluate(policy, {"tool": "workspace", "action": "write"})["decision"] == "require_approval"


def test_timestamp_and_event_id_are_preserved():
    result = evaluate({"version": 1}, {"event_id": "x", "timestamp": "2026-01-01T00:00:00Z", "tool": "a"})
    assert result["event_id"] == "x"
    assert result["timestamp"].startswith("2026-")


@pytest.mark.parametrize("policy", [None, {}, {"version": 2}, {"version": 1, "default_effect": "maybe"},
                                    {"version": 1, "rules": "not-a-list"},
                                    {"version": 1, "rules": [{"tool": "a", "effect": "maybe"}]}])
def test_invalid_policy_rejected(policy):
    with pytest.raises(PolicyError):
        evaluate(policy, {"tool": "a"})


def test_cli_fail_on_deny_exits_nonzero(tmp_path):
    policy = tmp_path / "policy.json"
    events = tmp_path / "events.jsonl"
    policy.write_text('{"version":1,"rules":[{"tool":"ok","action":"read","effect":"allow"}]}')
    events.write_text('{"tool":"ok","action":"read"}\n{"tool":"other","action":"run"}\n')
    proc = subprocess.run([sys.executable, str(ROOT / "cli.py"), "--policy", str(policy), "--events", str(events), "--fail-on", "deny"], capture_output=True, text=True)
    assert proc.returncode == 1
    assert [json.loads(line)["decision"] for line in proc.stdout.splitlines()] == ["allow", "deny"]


@pytest.mark.parametrize(
    ("effect", "fail_on", "expected_returncode"),
    [("require_approval", "require_approval", 1), ("deny", "never", 0)],
)
def test_cli_fail_on_modes(tmp_path, effect, fail_on, expected_returncode):
    policy = tmp_path / "policy.json"
    events = tmp_path / "events.jsonl"
    policy.write_text(json.dumps({"version": 1, "rules": [
        {"tool": "workspace", "action": "write_file", "effect": effect}
    ]}))
    events.write_text('{"tool":"workspace","action":"write_file"}\n')
    proc = subprocess.run(
        [sys.executable, str(ROOT / "cli.py"), "--policy", str(policy), "--events", str(events), "--fail-on", fail_on],
        capture_output=True, text=True,
    )
    assert proc.returncode == expected_returncode
