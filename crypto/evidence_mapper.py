#!/usr/bin/env python3
"""ZEUS evidence mapper: pinned source, Rust declarations and adjacent test references.

Only passive public-source inspection. Function ownership is textual proximity,
NOT an AST, code coverage, vulnerability validation, or a runnable PoC.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "crypto"))
import zeus
from crypto.autohunt import (
    POLICY_PATH, MANIFEST_PATH, check_policy, load_json, verify_source_review,
    compact_digest,
)
from crypto.base_everest_intake import validate as validate_manifest

# Authenticated against Git blob SHA in immutable competition fork.
RELATED_TESTS = {
    "crates/execution/base-tx-rpc-node/tests/rpc.rs":
        "aa07dd98c7a9abcc288af21599f4062376847c91",
    "crates/proof/challenge/tests/driver.rs":
        "9fbea31bedb9bed354ce31cc6e0d34e7f948bd35",
}
TEST_ASSOCIATIONS = {
    "EVEREST-TX-GATE": ("crates/execution/base-tx-rpc-node/tests/rpc.rs",),
    "EVEREST-ROOT-VALIDATION": ("crates/proof/challenge/tests/driver.rs",),
}
MAX_BYTES = 1024 * 1024
FN = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:(?:async|unsafe|const)\s+)*"
    r"fn\s+([A-Za-z_]\w*)\b"
)
TEST_ATTR = re.compile(r"^\s*#\[(?:tokio::test(?:\([^]]*\))?|test|rstest(?:\([^]]*\))?)\]")
HEX64 = re.compile(r"^[a-f0-9]{64}$")


def fetch_related_test(path: str) -> bytes:
    if path not in RELATED_TESTS or path.startswith("/") or ".." in path.split("/"):
        raise ValueError("Source path outside allowlisted test references")
    req = Request(
        zeus.RAW + path, method="GET",
        headers={"User-Agent": "Garcar-ZEUS-TestInventory/1.0", "Accept": "text/plain"},
    )
    with urlopen(req, timeout=20) as reply:
        final = urlparse(reply.geturl())
        if final.scheme != "https" or final.netloc != "raw.githubusercontent.com":
            raise ValueError("Unexpected source redirect")
        raw = reply.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Oversize test reference")
    return raw


def index_rust(raw: bytes) -> dict:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("Invalid UTF-8 Rust input") from exc
    declarations = []
    test_declarations = []
    for i, line in enumerate(lines):
        found = FN.match(line)
        if not found:
            continue
        fn = {"name": found.group(1), "line": i + 1}
        declarations.append(fn)
        attrs = []
        for prior in reversed(lines[max(0, i-5):i]):
            if prior.strip().startswith("#["):
                attrs.append(prior)
            elif prior.strip() == "":
                continue
            else:
                break
        if any(TEST_ATTR.match(attr) for attr in attrs):
            test_declarations.append(fn)
    return {
        "line_count": len(lines),
        "function_declarations": declarations,
        "attributed_test_declarations": test_declarations,
        "test_declaration_count": len(test_declarations),
    }


def line_anchors(raw: bytes, patterns: list[str]) -> list[dict]:
    lines = raw.decode("utf-8").splitlines()
    declarations = index_rust(raw)["function_declarations"]
    output = []
    for pattern in patterns:
        regex = re.compile(pattern, flags=re.IGNORECASE)
        matches = []
        for number, line in enumerate(lines, 1):
            if not regex.search(line):
                continue
            prior = next((fn for fn in reversed(declarations) if fn["line"] <= number), None)
            if prior is not None and number - prior["line"] <= 50:
                context = {"nearest_declaration": prior["name"],
                           "declaration_line": prior["line"],
                           "context_kind": "textual_proximity_only"}
            else:
                context = {"nearest_declaration": None,
                           "declaration_line": None,
                           "context_kind": "unresolved_file_context"}
            matches.append({"line": number, **context})
            if len(matches) >= 5:
                break
        output.append({"signal": pattern, "locations": matches})
    return output


def verify_autohunt_queue(queue: dict, review: dict, policy: dict) -> None:
    receipt = queue.get("receipt_sha256")
    if not isinstance(receipt, str) or not HEX64.fullmatch(receipt):
        raise ValueError("Missing queue integrity receipt")
    if compact_digest({k: v for k, v in queue.items() if k != "receipt_sha256"}) != receipt:
        raise ValueError("AutoHunt queue integrity mismatch")
    if queue.get("schema_version") != 1 or queue.get("organ") != "base-everest-hunter":
        raise ValueError("Unknown queue schema/organ")
    if queue.get("mode") != "passive_offline_priority_assembly":
        raise ValueError("Queue does not describe passive source research")
    if queue.get("competition_window") != "open":
        raise ValueError("Competition queue is not open")
    if queue.get("source_commit") != zeus.COMMIT or queue.get("source_evidence_sha256") != review.get("source_evidence_sha256"):
        raise ValueError("Pinned source provenance mismatch")
    if queue.get("policy_sha256") != compact_digest(policy):
        raise ValueError("Queue policy revision mismatch")
    if any(queue.get(k) != 0 for k in
           ("findings_confirmed", "pocs_reproduced", "reports_submitted", "verified_earnings_usd")):
        raise ValueError("Invalid finding/revenue claims")
    if queue.get("proof_hash") is not None or queue.get("axiom_12_score") is not None:
        raise ValueError("Source queue cannot assert a PoC")
    cards = queue.get("review_queue")
    if not isinstance(cards, list) or len(cards) != 5:
        raise ValueError("Incomplete research queue")
    expected = {q["id"] for q in policy["research_questions"]}
    seen = [c.get("research_question_id") for c in cards if isinstance(c, dict)]
    if set(seen) != expected or len(seen) != 5:
        raise ValueError("Unknown or duplicate research questions")
    for card in cards:
        if card.get("status") != "research_question_not_a_finding" or card.get("submittable") is not False:
            raise ValueError("Unsupported research escalation")


def build_map(review: dict, queue: dict, policy: dict, manifest: dict,
              *, fetch_source=zeus.fetch_pinned, fetch_test=fetch_related_test,
              at: datetime | None = None) -> dict:
    validate_manifest(manifest)
    check_policy(policy, manifest)
    indexed = verify_source_review(review, policy)
    verify_autohunt_queue(queue, review, policy)
    cards = {c["research_question_id"]: c for c in queue["review_queue"]}
    tests = {}
    for path, blob in sorted(RELATED_TESTS.items()):
        raw = fetch_test(path)
        if len(raw) > MAX_BYTES or zeus.blob_sha1(raw) != blob:
            raise ValueError("Related test reference Git blob mismatch")
        reference = index_rust(raw)
        tests[path] = {
            "path": path,
            "git_blob_sha1": blob,
            "sha256": sha256(raw).hexdigest(),
            "lines": reference["line_count"],
            "test_declarations": reference["attributed_test_declarations"][:40],
            "observed_test_count": reference["test_declaration_count"],
            "role": "adjacent_test_inventory_not_asserted_coverage",
        }
    records = []
    for question in policy["research_questions"]:
        path = question["path"]
        baseline = indexed[path]
        raw = fetch_source(path)
        if len(raw) > MAX_BYTES or zeus.blob_sha1(raw) != baseline["observed_git_blob_sha1"]:
            raise ValueError("Authenticated source blob mismatch")
        if sha256(raw).hexdigest() != baseline["content_sha256"]:
            raise ValueError("Authenticated source SHA-256 mismatch")
        index = index_rust(raw)
        records.append({
            "question_id": question["id"],
            "queue_id": cards[question["id"]]["id"],
            "review_priority": cards[question["id"]]["review_priority"],
            "path": path,
            "blob_sha1": baseline["observed_git_blob_sha1"],
            "sha256": baseline["content_sha256"],
            "source_lines": index["line_count"],
            "function_count": len(index["function_declarations"]),
            "functions": index["function_declarations"][:70],
            "inline_test_count": index["test_declaration_count"],
            "inline_test_declarations": index["attributed_test_declarations"][:40],
            "signal_locations": line_anchors(raw, question["signals"]),
            "adjacent_test_references": [
                tests[p] for p in TEST_ASSOCIATIONS.get(question["id"], ())
            ],
            "validation_question": question["verification_question"],
            "next_action": "manual_in_scope_review_then_local_component_test",
            "scope_verified_for_testing": False,
            "coverage_verified": False,
            "finding_verified": False,
            "poc_reproduced": False,
            "note": "Textual Rust parsing only; test references do not establish measured coverage.",
        })
    records.sort(key=lambda r: (-r["review_priority"], r["question_id"]))
    at = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    result = {
        "schema_version": 1,
        "at_utc": at.isoformat(timespec="seconds"),
        "kind": "authenticated_static_source_evidence_map",
        "competition": manifest["id"],
        "source_commit": zeus.COMMIT,
        "source_review_sha256": review["source_evidence_sha256"],
        "autohunt_queue_sha256": queue["receipt_sha256"],
        "source_files_verified": len(records),
        "related_test_references_verified": len(tests),
        "records": records,
        "analysis_method": "bounded_line_index_not_complete_rust_parser",
        "rust_tests_executed": False,
        "devnet_started": False,
        "findings_verified": 0,
        "pocs_reproduced": 0,
        "reports_submitted": 0,
        "proof_hash": None,
        "axiom_12_score": None,
        "verified_earnings_usd": 0,
    }
    result["receipt_sha256"] = compact_digest(result)
    return result


def write_reports(result: dict, outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "evidence-map.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# ZEUS — pinned-source evidence and validation backlog", "",
        "All entries are **research observations**, never verified vulnerabilities.", "",
        f"Source files authenticated: {result['source_files_verified']}",
        f"Adjacent test files authenticated: {result['related_test_references_verified']}",
        "Rust tests run: **none**",
        "Findings / reproduced PoCs / reports / earnings: **0 / 0 / 0 / $0**", "",
        "Function associations use textual proximity only, not compiler semantics.", "",
    ]
    for r in result["records"]:
        lines += [f"## {r['question_id']}", "",
                  "**Validation question:** " + r["validation_question"], "",
                  "**Source:** " + r["path"], "",
                  f"Observed functions: {r['function_count']}; in-file test declarations: {r['inline_test_count']}.",
                  "Next step: verify scope and run authorized local component tests.", ""]
        for test in r["adjacent_test_references"]:
            lines.append(f"- Related test file: {test['path']} ({test['observed_test_count']} observed test declarations)")
        lines.append("")
    lines += ["No devnet started. No proof or accepted finding established.", "",
              "Unsigned SHA-256 evidence receipt: " + result["receipt_sha256"], ""]
    (outdir / "EVIDENCE_MAP.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-review", type=Path, required=True)
    p.add_argument("--autohunt-queue", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    args = p.parse_args()
    report = build_map(
        load_json(args.source_review),
        load_json(args.autohunt_queue),
        load_json(POLICY_PATH),
        load_json(MANIFEST_PATH),
    )
    write_reports(report, args.output_dir)
    print(json.dumps({
        "source_files_verified": report["source_files_verified"],
        "adjacent_test_references_verified": report["related_test_references_verified"],
        "review_backlog": len(report["records"]),
        "findings_verified": 0,
        "pocs_reproduced": 0,
        "receipt_sha256": report["receipt_sha256"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
