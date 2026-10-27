"""Offline policy evaluation for agent tool-call traces. No network or model calls."""
from __future__ import annotations

import hashlib
import json
from typing import Any

_ALLOWED_EFFECTS = {"allow", "deny", "require_approval"}


class PolicyError(ValueError):
    """Raised for malformed policy documents or tool-call events."""


def _validate_policy(policy: dict[str, Any]) -> list[dict[str, str]]:
    if not isinstance(policy, dict):
        raise PolicyError("policy must be a JSON object")
    unknown_policy_fields = set(policy) - {"version", "default_effect", "rules"}
    if unknown_policy_fields:
        fields = ", ".join(sorted(map(repr, unknown_policy_fields)))
        raise PolicyError(f"unsupported policy field(s): {fields}")
    if type(policy.get("version")) is not int or policy["version"] != 1:
        raise PolicyError("policy version must be 1")
    default = policy.get("default_effect", "deny")
    if not isinstance(default, str) or default not in _ALLOWED_EFFECTS:
        raise PolicyError(f"invalid default_effect: {default!r}")
    rules = policy.get("rules", [])
    if not isinstance(rules, list):
        raise PolicyError("rules must be a list")
    normalized = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise PolicyError(f"rule {index} must be an object")
        unknown_rule_fields = set(rule) - {"tool", "action", "effect", "reason"}
        if unknown_rule_fields:
            fields = ", ".join(sorted(map(repr, unknown_rule_fields)))
            raise PolicyError(f"rule {index} has unsupported field(s): {fields}")
        tool, action, effect = rule.get("tool"), rule.get("action", "*") , rule.get("effect")
        if not isinstance(tool, str) or not tool.strip() or not isinstance(action, str) or not action.strip():
            raise PolicyError(f"rule {index} needs non-empty string tool and action fields")
        if not isinstance(effect, str) or effect not in _ALLOWED_EFFECTS:
            raise PolicyError(f"rule {index} has invalid effect: {effect!r}")
        reason = rule.get("reason", "")
        if not isinstance(reason, str):
            raise PolicyError(f"rule {index} reason must be a string")
        normalized.append({"tool": tool, "action": action, "effect": effect, "reason": reason})
    return normalized


def _argument_digest(arguments: Any) -> str:
    """Hash canonical arguments; never include argument values in audit output."""
    try:
        canonical = json.dumps(
            arguments,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise PolicyError("arguments must be JSON-serializable") from exc
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def evaluate(policy: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    """Evaluate one event and return a safe summary without argument contents.

    The evaluator reports require_approval; it does not itself grant approval,
    execute tools, or enforce a runtime boundary.
    """
    rules = _validate_policy(policy)
    if not isinstance(event, dict):
        raise PolicyError("event must be a JSON object")
    tool, action = event.get("tool"), event.get("action", "*")
    if not isinstance(tool, str) or not tool.strip():
        raise PolicyError("event needs a non-empty string tool field")
    if not isinstance(action, str) or not action.strip():
        raise PolicyError("event action must be a non-empty string")

    matched = [r for r in rules if r["tool"] in (tool, "*") and r["action"] in (action, "*")]
    if matched:
        # A deny always wins. Otherwise approval gates beat allow rules.
        effects = {r["effect"] for r in matched}
        effect = "deny" if "deny" in effects else (
            "require_approval" if "require_approval" in effects else "allow"
        )
        reasons = list(dict.fromkeys(r["reason"] for r in matched if r["effect"] == effect and r["reason"]))
        reason = "; ".join(reasons) or "Matched policy rule"
    else:
        effect = policy.get("default_effect", "deny")
        reason = "No matching policy rule"

    event_id = event.get("event_id")
    if event_id is not None and not (isinstance(event_id, str) or type(event_id) is int):
        raise PolicyError("event_id must be a string or integer")
    result = {
        "event_id": event_id,
        "tool": tool,
        "action": action,
        "decision": effect,
        "reason": reason,
        "arguments_sha256": _argument_digest(event.get("arguments", {})),
    }
    if "timestamp" in event:
        if not isinstance(event["timestamp"], str):
            raise PolicyError("timestamp must be a string")
        result["timestamp"] = event["timestamp"]
    return result
