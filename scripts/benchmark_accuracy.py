"""Measure detection precision and recall against the labelled corpus (2.7e).

A scanner that cannot state its false-positive rate cannot be trusted, and
adopting an upstream engine does not transfer responsibility for its accuracy to
its authors. This measures **the pipeline as integrated** -- rules, adapter and
CBOM builder together -- not what any upstream project claims in isolation.

The expectations below are the ground truth. Each entry is a location that a
human has confirmed by reading the fixture, so a regression shows up as a named
missing finding rather than a changed number.

Run: python scripts/benchmark_accuracy.py
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES = REPO_ROOT / "rules"
FIXTURES = REPO_ROOT / "tests" / "fixtures"

#: Expected findings in the positive corpus, keyed by "file:line".
#: The value is the algorithm each site must yield. Key sizes and modes are
#: checked separately so a partial detection is visible rather than averaged away.
EXPECTED: dict[str, str] = {
    # Python
    "crypto_usage.py:11": "rsa",
    "crypto_usage.py:16": "rsa",
    "crypto_usage.py:22": "aes",
    "crypto_usage.py:27": "aes",
    "crypto_usage.py:32": "md5",
    "crypto_usage.py:37": "sha2",
    "crypto_usage.py:42": "ecdsa",
    "crypto_usage.py:47": "3des",
    # Go
    "crypto_usage.go:15": "rsa",
    "crypto_usage.go:20": "md5",
    "crypto_usage.go:25": "aes",
    "crypto_usage.go:30": "ecdsa",
    # Java
    "CryptoUsage.java:12": "aes",
    "CryptoUsage.java:17": "aes",
    "CryptoUsage.java:22": "aes",
    "CryptoUsage.java:27": "md5",
    "CryptoUsage.java:32": "rsa",
    # JavaScript
    "crypto_usage.js:6": "md5",
    "crypto_usage.js:11": "sha256",
    "crypto_usage.js:16": "aes",
    "crypto_usage.js:22": "rsa",
    # C
    "crypto_usage.c:7": "md5",
    "crypto_usage.c:10": "rsa",
    "crypto_usage.c:13": "aes",
}

#: Sites that must carry a resolved key size. This is the message-interpolation
#: contract measured end to end: if it breaks, these degrade to NEEDS_CONTEXT.
EXPECTED_KEY_SIZES: dict[str, int] = {
    "crypto_usage.py:11": 1024,
    "crypto_usage.py:16": 2048,
    "crypto_usage.go:15": 2048,
    "crypto_usage.js:16": 256,
    "crypto_usage.c:10": 2048,
}

#: Sites that must carry a resolved cipher mode. ECB is a finding in its own
#: right, so losing the mode loses the finding.
EXPECTED_MODES: dict[str, str] = {
    "crypto_usage.py:22": "cbc",
    "crypto_usage.py:27": "gcm",
    "CryptoUsage.java:12": "cbc",
    "CryptoUsage.java:17": "gcm",
    "CryptoUsage.java:22": "ecb",
    "crypto_usage.js:16": "cbc",
}


@dataclass
class Report:
    true_positives: list[str] = field(default_factory=list)
    false_negatives: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    false_positives_negative_corpus: list[str] = field(default_factory=list)
    missing_key_sizes: list[str] = field(default_factory=list)
    missing_modes: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        """Against the negative corpus, which is where false positives live.

        The positive corpus deliberately contains extra real crypto (a second
        hash on one line, helper ciphers), so counting anything unlisted there
        as a false positive would penalise correct detections.
        """
        detected = len(self.true_positives) + len(self.false_positives_negative_corpus)
        if detected == 0:
            return 0.0
        return len(self.true_positives) / detected

    @property
    def recall(self) -> float:
        total = len(self.true_positives) + len(self.false_negatives)
        if total == 0:
            return 0.0
        return len(self.true_positives) / total

    @property
    def key_size_resolution(self) -> float:
        total = len(EXPECTED_KEY_SIZES)
        if total == 0:
            return 0.0
        return (total - len(self.missing_key_sizes)) / total

    @property
    def mode_resolution(self) -> float:
        total = len(EXPECTED_MODES)
        if total == 0:
            return 0.0
        return (total - len(self.missing_modes)) / total

    @property
    def passed(self) -> bool:
        return (
            not self.false_positives_negative_corpus
            and not self.false_negatives
            and not self.missing_key_sizes
            and not self.missing_modes
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "expected_sites": len(EXPECTED),
            "true_positives": len(self.true_positives),
            "false_negatives": len(self.false_negatives),
            "false_positives_negative_corpus": len(self.false_positives_negative_corpus),
            "precision": self.precision,
            "recall": self.recall,
            "key_size_resolution": self.key_size_resolution,
            "mode_resolution": self.mode_resolution,
            "passed": self.passed,
            "details": {
                "missing_findings": self.false_negatives,
                "false_positives": self.false_positives_negative_corpus,
                "missing_key_sizes": self.missing_key_sizes,
                "missing_modes": self.missing_modes,
            },
        }

    def to_junit_xml(self) -> str:
        cases = []
        if self.false_positives_negative_corpus:
            cases.append(
                f'<testcase name="precision" classname="accuracy"><failure message="False positives detected">{", ".join(self.false_positives_negative_corpus)}</failure></testcase>'
            )
        else:
            cases.append('<testcase name="precision" classname="accuracy"/>')

        if self.false_negatives:
            cases.append(
                f'<testcase name="recall" classname="accuracy"><failure message="False negatives detected">{", ".join(self.false_negatives)}</failure></testcase>'
            )
        else:
            cases.append('<testcase name="recall" classname="accuracy"/>')

        if self.missing_key_sizes:
            cases.append(
                f'<testcase name="key_size_resolution" classname="accuracy"><failure message="Missing key sizes">{", ".join(self.missing_key_sizes)}</failure></testcase>'
            )
        else:
            cases.append('<testcase name="key_size_resolution" classname="accuracy"/>')

        if self.missing_modes:
            cases.append(
                f'<testcase name="mode_resolution" classname="accuracy"><failure message="Missing modes">{", ".join(self.missing_modes)}</failure></testcase>'
            )
        else:
            cases.append('<testcase name="mode_resolution" classname="accuracy"/>')

        failures = sum(1 for c in cases if "<failure" in c)
        return (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            f'<testsuite name="accuracy_benchmark" tests="{len(cases)}" failures="{failures}">\n'
            + "\n".join(f"  {c}" for c in cases)
            + "\n</testsuite>\n"
        )


def run_semgrep(target: Path) -> list[dict]:
    """Run the rule packs over a target and return parsed results."""
    command = [
        "semgrep",
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--disable-version-check",
        "--metrics=off",
        # Semgrep's built-in ignores skip tests/ and vendor/, which would make
        # a fixture corpus silently yield nothing.
        "--x-ignore-semgrepignore-files",
        "--config",
        str(RULES / "crypto"),
        "--config",
        str(RULES / "taint"),
        str(target),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if not completed.stdout.strip():
        raise RuntimeError(f"semgrep produced no output: {completed.stderr[:400]}")
    return json.loads(completed.stdout).get("results", [])


def site_of(result: dict) -> str:
    return f"{Path(result['path']).name}:{result['start']['line']}"


CAPTURE_PATTERN = re.compile(r"trinetra:([a-z_]+)=(\S+)")


def captures_of(result: dict) -> dict[str, str]:
    pattern = CAPTURE_PATTERN
    found = {}
    for key, value in pattern.findall(result["extra"]["message"]):
        cleaned = value.strip("\"'")
        if cleaned and not cleaned.startswith("$"):
            found[key] = cleaned
    return found


def benchmark() -> Report:
    report = Report()

    positive = run_semgrep(FIXTURES / "positive")
    negative = run_semgrep(FIXTURES / "negative")

    # Any finding in the negative corpus is a false positive by construction:
    # that code performs no cryptography.
    for result in negative:
        report.false_positives_negative_corpus.append(
            f"{site_of(result)} ({result['check_id'].split('.')[-1]})"
        )

    detected: dict[str, set[str]] = {}
    detail: dict[str, dict[str, str]] = {}

    for result in positive:
        if "taint" in result["check_id"]:
            continue  # taint findings annotate, they are not artefacts
        site = site_of(result)
        meta = result["extra"]["metadata"].get("trinetra", {})
        captured = captures_of(result)

        algorithm = meta.get("algorithm", "")
        if not algorithm:
            transform = captured.get("transformation", "")
            algorithm = captured.get("algorithm", transform.split("/")[0]).lower()
            algorithm = algorithm.split("-")[0]

        detected.setdefault(site, set()).add(algorithm)
        merged = detail.setdefault(site, {})
        merged.update(captured)

    for site, expected_algorithm in EXPECTED.items():
        found = detected.get(site, set())
        if any(expected_algorithm.startswith(a) or a.startswith(expected_algorithm)
               for a in found if a):
            report.true_positives.append(site)
        else:
            got = sorted(found) or "nothing"
            report.false_negatives.append(
                f"{site} (expected {expected_algorithm}, got {got})"
            )

    for site, expected_size in EXPECTED_KEY_SIZES.items():
        captured = detail.get(site, {})
        raw = captured.get("key_size") or captured.get("transformation", "")
        if str(expected_size) not in str(raw):
            report.missing_key_sizes.append(f"{site} (expected {expected_size})")

    for site, expected_mode in EXPECTED_MODES.items():
        captured = detail.get(site, {})
        blob = (
            captured.get("mode", "") + " " + captured.get("transformation", "")
        ).lower()
        if expected_mode not in blob:
            report.missing_modes.append(f"{site} (expected {expected_mode})")

    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Trinetra source-detection accuracy benchmark")
    parser.add_argument("--json", action="store_true", help="Output results as JSON to stdout")
    parser.add_argument("--junit-xml", metavar="PATH", help="Write JUnit XML report to file")
    args = parser.parse_args(argv)

    try:
        report = benchmark()
    except FileNotFoundError:
        print("semgrep is not installed; cannot benchmark", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(f"benchmark failed: {exc}", file=sys.stderr)
        return 2

    if args.junit_xml:
        junit_path = Path(args.junit_xml)
        junit_path.parent.mkdir(parents=True, exist_ok=True)
        junit_path.write_text(report.to_junit_xml(), encoding="utf-8")

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0 if report.passed else 1

    print("Trinetra source-detection accuracy")
    print("=" * 52)
    print(f"  expected sites          {len(EXPECTED)}")
    print(f"  detected (true pos)     {len(report.true_positives)}")
    print(f"  missed (false neg)      {len(report.false_negatives)}")
    print(f"  false positives         {len(report.false_positives_negative_corpus)}")
    print()
    print(f"  precision               {report.precision:.1%}")
    print(f"  recall                  {report.recall:.1%}")
    print(f"  key size resolution     {report.key_size_resolution:.1%}"
          f"  ({len(EXPECTED_KEY_SIZES) - len(report.missing_key_sizes)}"
          f"/{len(EXPECTED_KEY_SIZES)})")
    print(f"  mode resolution         {report.mode_resolution:.1%}"
          f"  ({len(EXPECTED_MODES) - len(report.missing_modes)}"
          f"/{len(EXPECTED_MODES)})")

    for label, items in (
        ("FALSE POSITIVES (negative corpus)", report.false_positives_negative_corpus),
        ("MISSED", report.false_negatives),
        ("KEY SIZE NOT RESOLVED", report.missing_key_sizes),
        ("MODE NOT RESOLVED", report.missing_modes),
    ):
        if items:
            print(f"\n{label}:")
            for item in items:
                print(f"  - {item}")

    print()
    print("RESULT:", "PASS" if report.passed else "FAIL")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
