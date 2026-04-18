"""Auto-grader for student YARA/Sigma/Suricata rule deliverables.

This module is both a pytest suite (instructor-baseline regression) and a CLI
student self-check: `python -m tests.test_detection_rules --rule my.yar`.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

import pytest

yara = pytest.importorskip("yara")

REPO_ROOT = pathlib.Path(__file__).parent.parent
CASEFILE = REPO_ROOT / "module-casefile"


def _load_corpus(round_num: int) -> tuple[list[pathlib.Path], list[pathlib.Path]]:
    root = CASEFILE / f"round-{round_num}" / "yara-corpus"
    pos = sorted((root / "positive").glob("*"))
    neg = sorted((root / "negative").glob("*"))
    return pos, neg


def grade(rule_source: str, round_num: int) -> dict:
    """Run a YARA rule against the round's corpus; return precision/recall."""
    compiled = yara.compile(source=rule_source)
    pos, neg = _load_corpus(round_num)
    tp = sum(1 for p in pos if compiled.match(str(p)))
    fn = len(pos) - tp
    fp = sum(1 for n in neg if compiled.match(str(n)))
    tn = len(neg) - fp
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall,
        "positive_corpus_size": len(pos),
        "negative_corpus_size": len(neg),
    }


# --- Regression on the instructor baseline ---------------------------------

REFERENCE_R1_RULE = r"""
rule Ghost_R1_Naive_Spyware
{
    meta:
        author = "instructor"
        round = "1"
    strings:
        $lab_header = "GHOST-IN-THE-BOX LAB"
        $c2_ip = "10.13.37.1"
        $field1 = "screenshot_bytes"
        $field2 = "\"keys\""
        $import_http = "import exfil_http"
    condition:
        $lab_header and (3 of ($c2_ip, $field1, $field2, $import_http))
}
"""


def test_reference_r1_rule_perfect_on_corpus():
    result = grade(REFERENCE_R1_RULE, round_num=1)
    assert result["recall"] == 1.0, result
    assert result["precision"] >= 0.95, result


def test_overbroad_rule_is_caught_by_grader():
    """A rule that only matches a shared substring must fail precision."""
    overbroad = r"""
rule Overbroad { strings: $s = "workstation-042" condition: $s }
"""
    result = grade(overbroad, round_num=1)
    # This hits the positive AND at least one negative (benign-http-client.py mentions the hostname).
    assert result["precision"] < 0.95, result


def test_too_narrow_rule_fails_recall():
    """A rule that fails to match the positive must fail recall."""
    too_narrow = r"""
rule Narrow { strings: $s = "completely-unrelated-literal-xyz" condition: $s }
"""
    result = grade(too_narrow, round_num=1)
    assert result["recall"] == 0.0, result


# --- CLI mode (student self-check) ----------------------------------------

def _cli(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rule", type=pathlib.Path, required=True)
    ap.add_argument("--round", type=int, default=1)
    ap.add_argument("--min-precision", type=float, default=0.95)
    ap.add_argument("--min-recall", type=float, default=1.0)
    args = ap.parse_args(argv)

    source = args.rule.read_text(encoding="utf-8")
    result = grade(source, round_num=args.round)
    print(f"precision={result['precision']:.3f} recall={result['recall']:.3f} "
          f"tp={result['tp']} fp={result['fp']} fn={result['fn']}")
    if result["precision"] < args.min_precision or result["recall"] < args.min_recall:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
