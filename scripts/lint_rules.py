"""Enforce the two load-bearing rule constraints mechanically.

Both constraints are brittle by nature -- a rule author who forgets either one
produces a rule that *looks* fine and silently misbehaves -- so they are checked
in CI rather than at review time.

1. Match call expressions, never bare identifiers.
   A rule matching the token ``rsa`` flags ``rsa = "some string"``.

2. Interpolate captured values into the message.
   Semgrep OSS emits no ``metavars`` field, so the message is the only channel
   that can carry a key size back to the scanner. A rule that captures a size
   metavariable and does not interpolate it loses the size, and the finding
   degrades to NEEDS_CONTEXT without anyone noticing.

Run: python scripts/lint_rules.py rules/
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

#: Metavariables whose value is meaningful to Trinetra and must therefore be
#: interpolated into the message if captured.
VALUE_BEARING = {"$BITS", "$MODE", "$CURVE", "$ALGO", "$TRANSFORM", "$SIZE"}

#: A pattern that is only a metavariable or a bare dotted name -- no call, no
#: argument list -- matches identifiers and is rejected.
BARE_IDENTIFIER = re.compile(r"^[\w.$]+$")

CAPTURE = re.compile(r"trinetra:([a-z_]+)=(\$?\S+)")


def collect_patterns(node: object, *, keys: set[str] | None = None) -> list[str]:
    """Return every pattern string under a rule, at any nesting depth."""
    keys = keys or {"pattern", "pattern-not", "pattern-inside"}
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in keys and isinstance(value, str):
                found.append(value)
            else:
                found.extend(collect_patterns(value, keys=keys))
    elif isinstance(node, list):
        for item in node:
            found.extend(collect_patterns(item, keys=keys))
    return found


def match_patterns(rule: dict) -> list[str]:
    """Patterns that decide whether a rule FIRES.

    Excludes pattern-sources: a taint source is a value being read (a field
    access such as ``$OBJ.aadhaar_number``), and requiring a call expression
    there would make taint analysis impossible. The call-expression rule exists
    to stop a bare token matching an unrelated assignment, and taint sources are
    already constrained by having to reach a sink.
    """
    sources = set(collect_patterns(rule.get("pattern-sources", []), keys={"pattern"}))
    everything = collect_patterns(rule)
    return [p for p in everything if p not in sources]


def check_rule(rule: dict, path: Path) -> list[str]:
    problems: list[str] = []
    rule_id = rule.get("id", "<unnamed>")
    where = f"{path.name}:{rule_id}"

    message = rule.get("message", "")
    patterns = match_patterns(rule)

    if not patterns:
        problems.append(f"{where}: rule declares no patterns")

    for pattern in patterns:
        stripped = pattern.strip()
        if BARE_IDENTIFIER.match(stripped):
            problems.append(
                f"{where}: pattern {stripped!r} matches a bare identifier. "
                "It would flag `rsa = \"some string\"`. Match a call expression."
            )

    # Constraint 2: a captured value-bearing metavariable must be interpolated.
    # pattern-not is exempt: its job is to suppress a match, not to report a
    # value, so referencing $BITS there carries nothing back to the scanner.
    reporting = collect_patterns(rule, keys={"pattern", "pattern-inside"})
    for pattern in reporting:
        for metavar in VALUE_BEARING:
            if metavar in pattern and metavar not in message:
                problems.append(
                    f"{where}: pattern captures {metavar} but the message does not "
                    f"interpolate it. Semgrep OSS emits no metavars field, so the "
                    f"value is lost and the finding degrades to NEEDS_CONTEXT."
                )
                break

    # An interpolation that names a metavariable the patterns never capture is
    # a typo that silently yields the literal string "$BITS".
    for key, value in CAPTURE.findall(message):
        if value.startswith("$") and not any(value in p for p in patterns):
            problems.append(
                f"{where}: message interpolates {value} for {key!r}, but no pattern "
                f"captures it. The literal text would be emitted as the value."
            )

    if not rule.get("metadata", {}).get("trinetra"):
        problems.append(
            f"{where}: missing metadata.trinetra. The adapter ignores rules "
            "without it, so this rule would never produce a finding."
        )

    return problems


def main(argv: list[str]) -> int:
    root = Path(argv[1] if len(argv) > 1 else "rules")
    rule_files = sorted(root.rglob("*.yml")) + sorted(root.rglob("*.yaml"))

    if not rule_files:
        print(f"no rule files found under {root}", file=sys.stderr)
        return 1

    problems: list[str] = []
    rule_count = 0

    for path in rule_files:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for rule in document.get("rules", []):
            rule_count += 1
            problems.extend(check_rule(rule, path))

    if problems:
        print(f"Rule pack lint FAILED ({len(problems)} problems):", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(f"Rule pack lint passed: {rule_count} rules in {len(rule_files)} files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
