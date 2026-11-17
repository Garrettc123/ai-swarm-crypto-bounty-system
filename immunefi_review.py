"""Immunefi manual program-intake gate. No Immunefi network requests.

Immunefi Terms of Use restrict robot access and Immunefi Rules prohibit
unauthorized target testing and low-quality automated submissions. Program
information may be manually reviewed by the operator through the official
website; this module validates ONLY non-sensitive checklist metadata. It
never stores findings, vulnerability details, credentials or reward claims.

Calling evaluate_program is NOT consent to security test or submit anything.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

PROGRAM_PATH = re.compile(r"^/bug-bounty/([a-z0-9][a-z0-9-]{0,90})/information/$")
SCOPE_PATH = re.compile(r"^/bug-bounty/([a-z0-9][a-z0-9-]{0,90})/scope/$")
MAX_AGE_SECONDS = 7 * 24 * 3600
REQUIRED_CHECKS = (
    "program_current",
    "scope_current",
    "asset_ownership_reviewed",
    "excluded_impacts_reviewed",
    "research_method_allowed",
    "poc_requirements_reviewed",
    "eligibility_and_kyc_reviewed",
    "fees_and_payout_terms_reviewed",
    "responsible_disclosure_reviewed",
)
ALLOWED_FIELDS = frozenset({"program_url", "scope_url", "reviewed_at",
                            "source_mode", "checks"})
OFFICIAL_LINKS = {
    "programs": "https://immunefi.com/bug-bounty/",
    "rules": "https://immunefi.com/rules/",
    "terms": "https://immunefi.com/terms-of-use/",
    "exclusions": "https://immunefi.com/common-vulnerabilities-to-exclude/",
}


def _program_slug(url: object, pattern: re.Pattern) -> str | None:
    if not isinstance(url, str) or len(url) > 250:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if (parts.scheme != "https" or parts.netloc != "immunefi.com"
            or parts.query or parts.fragment or parts.username or parts.password):
        return None
    match = pattern.fullmatch(parts.path)
    return match.group(1) if match else None


def evaluate_program(record: object, *, now: datetime | None = None) -> dict:
    """Fail-closed operator review of a manually supplied checklist.

    This is a metadata readiness assessment, not verification of Immunefi
    contents, target scope, funding, or legal authority to execute tests.
    """
    flags: list[str] = []
    output = {
        "platform": "immunefi",
        "mode": "manual_operator_review_only",
        "source_access": "none_by_software",
        "review_status": "blocked",
        "human_review_checklist_complete": False,
        "program_information_authenticated": False,
        "scope_authorization_verified": False,
        "security_testing_enabled": False,
        "automatic_submission_enabled": False,
        "payout_verified": False,
        "permission_to_access_external_targets": False,
        "checks_required": list(REQUIRED_CHECKS),
        "blocking_reasons": flags,
    }
    if not isinstance(record, dict):
        flags.append("invalid_record")
        return output
    if set(record) - ALLOWED_FIELDS:
        flags.append("unexpected_fields_rejected")
        return output
    slug = _program_slug(record.get("program_url"), PROGRAM_PATH)
    scope_slug = _program_slug(record.get("scope_url"), SCOPE_PATH)
    if slug is None or slug != scope_slug:
        flags.append("canonical_program_scope_url_mismatch")
    if record.get("source_mode") != "operator_manual":
        flags.append("automatic_or_unattributed_collection_not_allowed")
    checks = record.get("checks")
    if not isinstance(checks, dict) or set(checks) != set(REQUIRED_CHECKS):
        flags.append("review_checklist_incomplete")
    elif not all(checks.get(key) is True for key in REQUIRED_CHECKS):
        flags.append("operator_review_unfinished")
    reviewed_at = record.get("reviewed_at")
    current = now or datetime.now(timezone.utc)
    try:
        if not isinstance(reviewed_at, str):
            raise ValueError("time missing")
        seen = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
        if seen.tzinfo is None:
            raise ValueError("timezone required")
        age = (current - seen.astimezone(timezone.utc)).total_seconds()
        if not 0 <= age <= MAX_AGE_SECONDS:
            raise ValueError("review expired or future")
    except (ValueError, TypeError, OverflowError):
        flags.append("review_timestamp_missing_or_stale")
    if flags:
        return output
    output["review_status"] = "human_checklist_recorded"
    output["human_review_checklist_complete"] = True
    # A checked box is NOT cryptographic evidence, program authorization,
    # accepted research, or an invitation to attack the listed assets.
    return output


def public_policy() -> dict:
    """Safe to expose on public dashboard; contains no program/claim data."""
    return {
        "platform": "immunefi",
        "integration": "manual_review_only",
        "automated_website_access": False,
        "authorized_immunefi_api_connected": False,
        "programs_imported": 0,
        "security_testing_enabled": False,
        "automatic_submission_enabled": False,
        "onchain_payout_verification_enabled": False,
        "official_links": dict(OFFICIAL_LINKS),
        "checklist_fields": list(REQUIRED_CHECKS),
        "notice": (
            "Use the official Immunefi website manually. Verify each program, "
            "asset, impact, exclusion, PoC requirement, fees and eligibility. "
            "No automated Immunefi collection, scanning, submissions or payouts."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate an operator's Immunefi review checklist offline")
    parser.add_argument("record", help="Local JSON metadata only; never include secrets or findings")
    args = parser.parse_args()
    record = json.loads(Path(args.record).read_text(encoding="utf-8"))
    print(json.dumps(evaluate_program(record), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
