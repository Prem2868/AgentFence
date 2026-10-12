"""Command-line entry point for AgentFence."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentfence import PolicyError, evaluate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate agent tool-call traces against a local JSON policy.")
    parser.add_argument("--policy", required=True, help="Policy JSON file")
    parser.add_argument("--events", required=True, help="JSONL tool-call events, or - for stdin")
    parser.add_argument("--fail-on", choices=("deny", "require_approval", "never"), default="deny",
                        help="Exit 1 if any event has this decision (default: deny)")
    args = parser.parse_args(argv)

    try:
        policy = json.loads(Path(args.policy).read_text(encoding="utf-8"))
        source = sys.stdin if args.events == "-" else Path(args.events).open(encoding="utf-8")
        matched_fail_on = False
        with source:
            for line_number, line in enumerate(source, 1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    result = evaluate(policy, event)
                    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
                    if result["decision"] == args.fail_on:
                        matched_fail_on = True
                except (json.JSONDecodeError, PolicyError) as exc:
                    print(f"agentfence: event line {line_number}: {exc}", file=sys.stderr)
                    return 2
    except (OSError, json.JSONDecodeError, PolicyError) as exc:
        print(f"agentfence: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0

    return 1 if matched_fail_on else 0


if __name__ == "__main__":
    raise SystemExit(main())
