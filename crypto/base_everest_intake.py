#!/usr/bin/env python3
"""Validate and register the curated Base Everest competition as research preparation.

Read-only offline intake; never probes target networks, claims findings or submits
reports. It is deliberately separate from regular Immunefi bug-bounty listings.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any

COMPETITION_PREFIX = 'https://immunefi.com/audit-competition/audit-comp-base-everest/'
HEX_COMMIT = re.compile(r'^[a-f0-9]{40}

def parse_utc(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith('Z'):
        raise ValueError('Competition dates must use UTC Z timestamps')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.utcoffset().total_seconds() != 0:
        raise ValueError('Expected UTC time')
    return result


def validate(manifest: dict[str, Any]) -> None:
    if not isinstance(manifest, dict):
        raise ValueError('Manifest must be a JSON object')
    if manifest.get('schema_version') != 1 or manifest.get('id') != 'immunefi:audit-comp-base-everest':
        raise ValueError('Unrecognized competition manifest')
    if manifest.get('kind') != 'audit_competition':
        raise ValueError('Competition must not be passed to regular bounty feed')
    start = parse_utc(manifest.get('start_utc'))
    end = parse_utc(manifest.get('end_utc'))
    if not start < end:
        raise ValueError('Invalid competition time window')
    for key, suffix in (
        ('official_information_url', 'information/'),
        ('official_scope_url', 'scope/'),
        ('official_resources_url', 'resources/'),
    ):
        if manifest.get(key) != COMPETITION_PREFIX + suffix:
            raise ValueError('Unexpected official source link: ' + key)
    if manifest.get('advertised_total_pool_usd') != 250000:
        raise ValueError('Unexpected advertised total pool')
    organ = manifest.get('organ')
    if not isinstance(organ, dict) or organ.get('name') != 'base-everest-hunter':
        raise ValueError('Missing real ZEUS research organ reference')
    if organ.get('source_repo') != 'Garrettc123/zeus-dashboard':
        raise ValueError('Unexpected organ repository')
    if organ.get('source_path') != 'organs/base-everest-hunter-organ.yaml':
        raise ValueError('Unexpected organ file')
    if not isinstance(organ.get('source_commit'), str) or not HEX_COMMIT.fullmatch(organ['source_commit']):
        raise ValueError('Organ source revision must be a full commit SHA')
    targets = manifest.get('targets_to_verify')
    if not isinstance(targets, list) or not targets:
        raise ValueError('Missing pinned audit targets')
    seen = set()
    for target in targets:
        if not isinstance(target, dict) or not HEX_COMMIT.fullmatch(str(target.get('pinned_commit', ''))):
            raise ValueError('Each target needs a complete, pinned SHA')
        repo = target.get('upstream_repo')
        if repo in seen or repo not in BASELINE_PINS:
            raise ValueError('Duplicate or unknown competition asset')
        seen.add(repo)
        if target['pinned_commit'] != BASELINE_PINS[repo]:
            raise ValueError('Official competition revision mismatch: ' + repo)
        if target.get('status') not in ('manual_scope_review_required', 'verify_exact_component_scope_before_testing'):
            raise ValueError('Unverified target must be gated for scope review')
        if repo == 'base/reth':
            if target.get('scope_class') != 'declared_dependency_scope_limited':
                raise ValueError('Do not declare all base/reth components in scope')
            if target.get('status') != 'verify_exact_component_scope_before_testing':
                raise ValueError('Execution-client dependency requires exact component scope check')
        elif not str(target.get('scope_class', '')).startswith('in_scope_') and repo not in ('base/contracts', 'base/nitro-validator'):
            raise ValueError('Missing explicit asset scope classification')
    if seen != set(BASELINE_PINS):
        raise ValueError('Competition asset registry is incomplete')
    if manifest.get('testing_environment') != 'designated_local_everest_devnet_only':
        raise ValueError('Live/public testing is forbidden by this intake')
    if manifest.get('runnable_poc_required') is not True:
        raise ValueError('Required runnable PoC cannot be waived')
    verification = manifest.get('verification')
    if not isinstance(verification, dict):
        raise ValueError('Verification block missing')
    for key in ('host_runtime_verified','zeus_run_once_verified','local_devnet_verified','finding_verified'):
        if verification.get(key) is not False:
            raise ValueError('Claims of verification require a separate evidence pipeline: ' + key)
    for key in ('proof_hash','srr_hash','seal_hash','axiom_12_score'):
        if verification.get(key, 'MISSING') is not None:
            raise ValueError('No proof or AXIOM-12 score may be asserted by intake: ' + key)
    if verification.get('reward_verified_usd') != 0:
        raise ValueError('No reward earnings may be attributed to discovery')


def produce(manifest_path: Path, output_path: Path, at: datetime | None = None) -> dict[str, Any]:
    raw = manifest_path.read_bytes()
    data = json.loads(raw)
    validate(data)
    at = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start, end = parse_utc(data['start_utc']), parse_utc(data['end_utc'])
    window = 'not_started' if at < start else 'closed' if at >= end else 'open'
    result = {
        'id': data['id'],
        'kind': 'audit_competition',
        'intake_mode': 'curated_offline_scope_reference',
        'generated_at': at.isoformat(timespec='seconds'),
        'manifest_sha256': hashlib.sha256(raw).hexdigest(),
        'competition_window': window,
        'reported_pool_usd': data['advertised_total_pool_usd'],
        'organ': data['organ'],
        'official_scope_url': data['official_scope_url'],
        'target_baselines': data['targets_to_verify'],
        'research_state': 'blocked_pending_scope_and_host_proof',
        'authorized_execution': False,
        'allowed_test_environment': data['testing_environment'],
        'known_issues_recheck_required': True,
        'proof_hash': None,
        'srr_hash': None,
        'seal_hash': None,
        'axiom_12_score': None,
        'verified_reward_usd': 0,
        'note': 'Static intake is not a live feed scan, vulnerability, PoC, submission, or payout.'
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', default='crypto/base_everest_target.json')
    parser.add_argument('--output', default='artifacts/base-everest-intake.json')
    args = parser.parse_args()
    result = produce(Path(args.manifest), Path(args.output))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
)
# Full immutable revisions from Immunefi's official Base Everest scope/resources.
# base/reth is a limited declared dependency, NOT a blanket in-scope asset.
BASELINE_PINS = {
    'base/base': '689054ee14933cb2ee5bd54eadcd8dacbe1cc517',
    'base/reth': '2b20e42de9c42b51ea0fb56599fda3c2f22640ef',
    'base/contracts': 'b9b76d97dca3c420098f597ebc65bee4f28001b7',
    'base/contract-deployments': 'e6797dfd6ac03b35d0ddd7eb369ab94bbc5fcd31',
    'base/nitro-validator': '0ea0d12366b4fa44f9e07e4755f2ad36561cb674',
}


def parse_utc(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith('Z'):
        raise ValueError('Competition dates must use UTC Z timestamps')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.utcoffset().total_seconds() != 0:
        raise ValueError('Expected UTC time')
    return result


def validate(manifest: dict[str, Any]) -> None:
    if not isinstance(manifest, dict):
        raise ValueError('Manifest must be a JSON object')
    if manifest.get('schema_version') != 1 or manifest.get('id') != 'immunefi:audit-comp-base-everest':
        raise ValueError('Unrecognized competition manifest')
    if manifest.get('kind') != 'audit_competition':
        raise ValueError('Competition must not be passed to regular bounty feed')
    start = parse_utc(manifest.get('start_utc'))
    end = parse_utc(manifest.get('end_utc'))
    if not start < end:
        raise ValueError('Invalid competition time window')
    for key, suffix in (
        ('official_information_url', 'information/'),
        ('official_scope_url', 'scope/'),
        ('official_resources_url', 'resources/'),
    ):
        if manifest.get(key) != COMPETITION_PREFIX + suffix:
            raise ValueError('Unexpected official source link: ' + key)
    if manifest.get('advertised_total_pool_usd') != 250000:
        raise ValueError('Unexpected advertised total pool')
    organ = manifest.get('organ')
    if not isinstance(organ, dict) or organ.get('name') != 'base-everest-hunter':
        raise ValueError('Missing real ZEUS research organ reference')
    if organ.get('source_repo') != 'Garrettc123/zeus-dashboard':
        raise ValueError('Unexpected organ repository')
    if organ.get('source_path') != 'organs/base-everest-hunter-organ.yaml':
        raise ValueError('Unexpected organ file')
    if not isinstance(organ.get('source_commit'), str) or not HEX_COMMIT.fullmatch(organ['source_commit']):
        raise ValueError('Organ source revision must be a full commit SHA')
    targets = manifest.get('targets_to_verify')
    if not isinstance(targets, list) or not targets:
        raise ValueError('Missing pinned audit targets')
    for target in targets:
        if not isinstance(target, dict) or not HEX_COMMIT.fullmatch(str(target.get('pinned_commit', ''))):
            raise ValueError('Each target needs a complete, pinned SHA')
        if target.get('status') not in ('manual_scope_review_required', 'verify_exact_component_scope_before_testing'):
            raise ValueError('Unverified target must be gated for scope review')
    if manifest.get('testing_environment') != 'designated_local_everest_devnet_only':
        raise ValueError('Live/public testing is forbidden by this intake')
    if manifest.get('runnable_poc_required') is not True:
        raise ValueError('Required runnable PoC cannot be waived')
    verification = manifest.get('verification')
    if not isinstance(verification, dict):
        raise ValueError('Verification block missing')
    for key in ('host_runtime_verified','zeus_run_once_verified','local_devnet_verified','finding_verified'):
        if verification.get(key) is not False:
            raise ValueError('Claims of verification require a separate evidence pipeline: ' + key)
    for key in ('proof_hash','srr_hash','seal_hash','axiom_12_score'):
        if verification.get(key, 'MISSING') is not None:
            raise ValueError('No proof or AXIOM-12 score may be asserted by intake: ' + key)
    if verification.get('reward_verified_usd') != 0:
        raise ValueError('No reward earnings may be attributed to discovery')


def produce(manifest_path: Path, output_path: Path, at: datetime | None = None) -> dict[str, Any]:
    raw = manifest_path.read_bytes()
    data = json.loads(raw)
    validate(data)
    at = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start, end = parse_utc(data['start_utc']), parse_utc(data['end_utc'])
    window = 'not_started' if at < start else 'closed' if at >= end else 'open'
    result = {
        'id': data['id'],
        'kind': 'audit_competition',
        'intake_mode': 'curated_offline_scope_reference',
        'generated_at': at.isoformat(timespec='seconds'),
        'manifest_sha256': hashlib.sha256(raw).hexdigest(),
        'competition_window': window,
        'reported_pool_usd': data['advertised_total_pool_usd'],
        'organ': data['organ'],
        'official_scope_url': data['official_scope_url'],
        'target_baselines': data['targets_to_verify'],
        'research_state': 'blocked_pending_scope_and_host_proof',
        'authorized_execution': False,
        'allowed_test_environment': data['testing_environment'],
        'known_issues_recheck_required': True,
        'proof_hash': None,
        'srr_hash': None,
        'seal_hash': None,
        'axiom_12_score': None,
        'verified_reward_usd': 0,
        'note': 'Static intake is not a live feed scan, vulnerability, PoC, submission, or payout.'
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', default='crypto/base_everest_target.json')
    parser.add_argument('--output', default='artifacts/base-everest-intake.json')
    args = parser.parse_args()
    result = produce(Path(args.manifest), Path(args.output))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
