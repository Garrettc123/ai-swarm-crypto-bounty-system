#!/usr/bin/env python3
"""ZEUS AutoHunt: passive, evidence-bound research prioritization.

Consumes only an authenticated pinned-source review and public bounty-listing
metadata. Produces REVIEW QUESTIONS, not vulnerability findings, PoCs, reports
or rewards. Network, devnet execution, issuance and payments are out of scope.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone, timedelta
from hashlib import sha256
import json
from pathlib import Path
import re

from base_everest_intake import validate as validate_competition
from bounty_triage import triage as triage_public_listings

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "crypto" / "autohunt_policy.json"
MANIFEST_PATH = ROOT / "crypto" / "base_everest_target.json"
HEX64 = re.compile(r"^[a-f0-9]{64}$")
HEX40 = re.compile(r"^[a-f0-9]{40}$")
EXPECTED_IDS = {
    "EVEREST-PROOF-GATE", "EVEREST-AGGREGATE-ABI", "EVEREST-TX-GATE",
    "EVEREST-BATCH-VALIDITY", "EVEREST-ROOT-VALIDATION",
}
NO_PROOF_FIELDS = {
    "proof_hash": None, "srr_hash": None, "seal_hash": None,
    "axiom_12_score": None,
}
FALSE_FIELDS = ("automatic_target_scanning", "automatic_exploit_execution",
                "automatic_bounty_submission", "new_paid_host_provisioning")


def compact_digest(value: object) -> str:
    return sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")).hexdigest()


def load_json(path: Path) -> dict:
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        raise ValueError("Expected JSON object: " + str(path))
    return result


def check_policy(policy: dict, manifest: dict) -> None:
    if policy.get("schema_version") != 1 or policy.get("mode") != "passive_authenticated_source_triage":
        raise ValueError("Unknown or permissive AutoHunt policy")
    if policy.get("competition") != manifest["id"]:
        raise ValueError("Policy competition mismatch")
    if policy.get("pinned_repository") != "immunefi-team/audit-comp-base-everest-base":
        raise ValueError("Unexpected source repo")
    if policy.get("pinned_commit") != "689054ee14933cb2ee5bd54eadcd8dacbe1cc517":
        raise ValueError("Unrecognized immutable audit version")
    if any(policy.get(k) is not False for k in FALSE_FIELDS):
        raise ValueError("Target testing, submissions and paid provisioning must stay disabled")
    if policy.get("allow_public_artifacts") is not True:
        raise ValueError("Public outputs require an explicit bounded artifact policy")
    if type(policy.get("max_review_cards")) is not int or not 1 <= policy["max_review_cards"] <= 5:
        raise ValueError("Review queue must be bounded")
    if type(policy.get("max_discovery_rows")) is not int or not 1 <= policy["max_discovery_rows"] <= 1000:
        raise ValueError("Discovery queue must be bounded")
    reqs = policy.get("manual_requirements")
    if not isinstance(reqs, list) or set(reqs) != {
        "fresh_scope_and_known_issues_review", "eligibility_and_duplicate_check",
        "authorized_local_test_environment", "independent_runnable_poc", "private_report_review",
    }:
        raise ValueError("Required safety and eligibility gates missing")
    q = policy.get("research_questions")
    if not isinstance(q, list) or len(q) != 5:
        raise ValueError("Expected exactly five defined hypotheses")
    ids, paths = set(), set()
    for row in q:
        if not isinstance(row, dict):
            raise ValueError("Malformed research question")
        path, id_ = row.get("path"), row.get("id")
        if id_ in ids or id_ not in EXPECTED_IDS or not isinstance(path, str) or path in paths:
            raise ValueError("Unexpected or duplicated research question")
        ids.add(id_)
        paths.add(path)
        if not HEX40.fullmatch(str(row.get("git_blob", ""))):
            raise ValueError("Unpinned research question")
        if not isinstance(row.get("signals"), list) or not all(
            isinstance(s, str) and 0 < len(s) < 80 for s in row["signals"]
        ):
            raise ValueError("Missing bounded inspection signals")
        if type(row.get("priority_base")) is not int or not 0 <= row["priority_base"] <= 90:
            raise ValueError("Invalid review priority")
        if not isinstance(row.get("focus"), str) or not isinstance(row.get("verification_question"), str):
            raise ValueError("Missing review framing")
    if ids != EXPECTED_IDS:
        raise ValueError("Research question coverage incomplete")


def verify_source_review(review: dict, policy: dict) -> dict[str, dict]:
    if review.get("schema_version") != 1 or review.get("organ") != "base-everest-hunter":
        raise ValueError("Unrecognized ZEUS review evidence")
    if review.get("upstream_repository") != policy["pinned_repository"] or (
        review.get("upstream_pinned_commit") != policy["pinned_commit"]
    ):
        raise ValueError("ZEUS source revision mismatch")
    if review.get("source_review_status") != "completed_not_exploit_validation":
        raise ValueError("ZEUS source inspection is not complete")
    if review.get("evidence_kind") != "authenticated_immutable_source_inspection_only":
        raise ValueError("Unrecognized evidence classification")
    for key, expected in NO_PROOF_FIELDS.items():
        if review.get(key, "missing") is not expected:
            raise ValueError("Source-only report improperly asserts " + key)
    if review.get("poc_reproduced") is not False or review.get("vulnerability_finding") is not None:
        raise ValueError("AutoHunt cannot accept a purported vulnerability from static source")
    if review.get("devnet_status") != "not_executed":
        raise ValueError("Unexpected source-only devnet status")
    if review.get("verified_earnings_usd") != 0:
        raise ValueError("Source-only report cannot credit revenue")
    files = review.get("files")
    if not isinstance(files, list) or review.get("reviewed_source_files") != len(files):
        raise ValueError("Missing source review coverage")
    mapped = {}
    for row in files:
        if not isinstance(row, dict):
            raise ValueError("Malformed source record")
        path = row.get("path")
        if not isinstance(path, str) or path in mapped:
            raise ValueError("Duplicated/invalid source file")
        if (not HEX64.fullmatch(str(row.get("content_sha256", "")))
                or not HEX40.fullmatch(str(row.get("observed_git_blob_sha1", "")))
                or row.get("expected_git_blob_sha1") != row.get("observed_git_blob_sha1")):
            raise ValueError("Unauthenticated pinned-source file")
        if row.get("classification") != "static_review_anchor_not_a_vulnerability":
            raise ValueError("Source review classification must be passive")
        mapped[path] = row
    expected_paths = {q["path"] for q in policy["research_questions"]}
    if set(mapped) != expected_paths:
        raise ValueError("Reviewed source set does not match allowed competition paths")
    for q in policy["research_questions"]:
        row = mapped[q["path"]]
        if row["observed_git_blob_sha1"] != q["git_blob"]:
            raise ValueError("Pinned file does not match expected immutable Git blob")
        counts = row.get("match_counts")
        if not isinstance(counts, dict) or set(counts) != set(q["signals"]):
            raise ValueError("Missing expected research signals")
        if any(type(value) is not int or value < 0 for value in counts.values()):
            raise ValueError("Invalid signal counts")
    inputs = [{
        "path": path,
        "sha256": mapped[path]["content_sha256"],
        "git_blob_sha1": mapped[path]["observed_git_blob_sha1"],
    } for path in sorted(mapped)]
    if review.get("source_evidence_sha256") != compact_digest(inputs):
        raise ValueError("Source evidence digest mismatch")
    return mapped


def discovery_summary(discovery: dict | None, policy: dict) -> dict:
    if discovery is None:
        return {"coverage": "unavailable", "listing_count": None, "errors": None,
                "live_awards_verified": 0}
    # Existing hardened parser enforces exact export count, canonical origins, and duplicates.
    result = triage_public_listings(discovery)
    if result["discovered"] > policy["max_discovery_rows"]:
        raise ValueError("Public discovery export exceeds allowed bounded size")
    return {
        "coverage": result["source_coverage"],
        "listing_count": result["discovered"],
        "by_source": result["source_counts"],
        "errors": len(result["source_errors"]),
        "qualification": "listed_not_eligible_until_manual_rules_review",
        "live_awards_verified": 0,
    }


def compile_queue(policy: dict, manifest: dict, review: dict,
                  discovery: dict | None, *, at: datetime | None = None) -> dict:
    validate_competition(manifest)
    check_policy(policy, manifest)
    by_path = verify_source_review(review, policy)
    listings = discovery_summary(discovery, policy)
    now = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start = datetime.fromisoformat(manifest["start_utc"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(manifest["end_utc"].replace("Z", "+00:00"))
    window = "not_started" if now < start else "closed" if now >= end else "open"
    cards = []
    for q in policy["research_questions"]:
        row = by_path[q["path"]]
        coverage = sum(1 for sig in q["signals"] if row["match_counts"][sig] > 0)
        # Review priority only: calibrated severity, exploitability and probability are UNKNOWN.
        priority = min(100, q["priority_base"] + coverage * 2)
        cards.append({
            "id": sha256((q["id"] + "|" + row["content_sha256"]).encode()).hexdigest()[:20],
            "research_question_id": q["id"],
            "review_priority": priority,
            "priority_meaning": "manual_code_review_order_only_not_vulnerability_severity",
            "focus": q["focus"],
            "verification_question": q["verification_question"],
            "source_path": q["path"],
            "source_git_blob_sha1": row["observed_git_blob_sha1"],
            "matched_review_signals": coverage,
            "total_expected_signals": len(q["signals"]),
            "status": "research_question_not_a_finding",
            "scope_status": "fresh_manual_check_required",
            "known_issue_status": "unverified",
            "proof_reproduced": False,
            "verified_impact": None,
            "submittable": False,
        })
    cards.sort(key=lambda x: (-x["review_priority"], x["research_question_id"]))
    eligible = window == "open"
    result = {
        "schema_version": 1,
        "generated_at_utc": now.isoformat(timespec="seconds"),
        "organ": "base-everest-hunter",
        "mode": "passive_offline_priority_assembly",
        "source_repo": policy["pinned_repository"],
        "source_commit": policy["pinned_commit"],
        "source_evidence_sha256": review["source_evidence_sha256"],
        "policy_sha256": compact_digest(policy),
        "competition_window": window,
        "competition_open_for_review": eligible,
        "review_queue": cards[:policy["max_review_cards"]] if eligible else [],
        "review_questions_defined": len(cards),
        "review_questions_queued": min(len(cards), policy["max_review_cards"]) if eligible else 0,
        "bounty_discovery": listings,
        "manual_requirements": policy["manual_requirements"],
        "fresh_issues_and_scope_verification": "pending",
        "authorized_public_target_tests": False,
        "local_devnet_started": False,
        "findings_confirmed": 0,
        "pocs_reproduced": 0,
        "reports_submitted": 0,
        "proof_hash": None,
        "axiom_12_score": None,
        "verified_earnings_usd": 0,
        "readme": "Priority cards reflect source-code review coverage, not bugs, severity, eligibility or payout.",
    }
    result["receipt_sha256"] = compact_digest(result)  # Unsigned metadata integrity only
    return result


def write_outputs(queue: dict, outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "autohunt-queue.json").write_text(
        json.dumps(queue, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# ZEUS AutoHunt — source-backed research queue", "",
        "Mode: **passive code review only**. All cards are hypotheses, not confirmed bugs.", "",
        "Competition window: " + queue["competition_window"],
        "Pinned source files reviewed: 5",
        "Review questions queued: " + str(queue["review_questions_queued"]),
        "Bounty listings from public scan: " + str(queue["bounty_discovery"]["listing_count"]),
        "Verified findings / submissions / revenue: **0 / 0 / $0**", "",
        "Known issues, eligibility, and local reproducibility must be checked manually before any report.", "",
        "## Review order", "",
    ]
    for i, item in enumerate(queue["review_queue"], 1):
        lines.append(f"{i}. **{item['focus']}** — priority {item['review_priority']}/100 "
                     f"(review order only); {item['source_path']}.")
    lines += ["", "No exploit code, sensitive candidate details, claims, or automated submissions are produced.", "",
              "Receipt SHA-256 (unsigned): " + queue["receipt_sha256"], ""]
    (outdir / "AUTOHUNT.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-review", type=Path, required=True)
    p.add_argument("--discovery", type=Path)
    p.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    args = p.parse_args()
    if args.discovery is not None and not args.discovery.is_file():
        p.error("Requested public scanner export is missing")
    report = compile_queue(
        load_json(POLICY_PATH), load_json(MANIFEST_PATH),
        load_json(args.source_review),
        load_json(args.discovery) if args.discovery is not None else None,
    )
    write_outputs(report, args.output_dir)
    print(json.dumps({
        "competition_window": report["competition_window"],
        "review_questions_queued": report["review_questions_queued"],
        "public_listings": report["bounty_discovery"]["listing_count"],
        "findings_confirmed": 0,
        "pocs_reproduced": 0,
        "reports_submitted": 0,
        "verified_earnings_usd": 0,
        "receipt_sha256": report["receipt_sha256"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
