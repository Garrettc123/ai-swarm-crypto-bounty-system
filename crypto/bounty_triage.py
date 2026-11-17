#!/usr/bin/env python3
"""Evidence-only triage of public bounty listings. No outreach or exploitation."""
import argparse
import csv
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
from pathlib import Path


def valid_reward(value):
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        return None
    return float(value) if math.isfinite(value) and value >= 0 else None


def table_safe(value):
    return str(value or '').replace('|', '\\|').replace('\r', ' ').replace('\n', ' ')[:300]


def csv_safe(value):
    value = str(value or '').replace('\r', ' ').replace('\n', ' ')
    return "'" + value if value.lstrip().startswith(('=', '+', '-', '@')) else value


def triage(data):
    if not isinstance(data, dict) or not isinstance(data.get('top'), list):
        raise ValueError('Scanner JSON must contain a top array')
    discovered = data.get('discovered')
    if type(discovered) is not int or discovered < 0:
        raise ValueError('Missing or invalid discovered count')
    source_errors = data.get('source_errors')
    if not isinstance(source_errors, list):
        raise ValueError('Missing source_errors array')
    parsed, seen = [], set()
    for row in data['top']:
        if not isinstance(row, dict):
            raise ValueError('Malformed listing')
        id_, source, url = row.get('id'), row.get('platform'), row.get('url')
        if not isinstance(id_, str) or not isinstance(source, str) or not isinstance(url, str):
            raise ValueError('Listing missing identifier or URL')
        if id_ in seen:
            raise ValueError('Duplicated listing: ' + id_)
        if source == 'github':
            if not (id_.startswith('github:') and url.startswith('https://github.com/') and '/issues/' in url):
                raise ValueError('Malformed GitHub listing')
        elif source == 'immunefi':
            if not (id_.startswith('immunefi:') and url.startswith('https://immunefi.com/bug-bounty/')):
                raise ValueError('Malformed Immunefi listing')
        else:
            raise ValueError('Unexpected listing source')
        seen.add(id_)
        parsed.append({
            'id': id_, 'source': source, 'title': str(row.get('title') or '')[:300],
            'url': url, 'advertised_max_usd': valid_reward(row.get('reward_max_usd')),
            'eligibility': str(row.get('eligibility') or 'unknown'),
            'kyc_required': row.get('kyc_required') if isinstance(row.get('kyc_required'), bool) else None,
            'review_state': 'manual_review_required',
            'award_status': 'unverified',
        })
    if len(parsed) != discovered:
        raise ValueError('Export is incomplete: %d rows vs %d discovered' % (len(parsed), discovered))
    github = [r for r in parsed if r['source'] == 'github']
    immunefi = [r for r in parsed if r['source'] == 'immunefi']
    github.sort(key=lambda r: (r['advertised_max_usd'] is None, -(r['advertised_max_usd'] or 0), r['id']))
    immunefi.sort(key=lambda r: (r['eligibility'] == 'invite_only', r['kyc_required'] is True,
                                 -(r['advertised_max_usd'] or 0), r['id']))
    return {
        'generated_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'source_scan_at': data.get('scanned_at'),
        'source_coverage': 'partial' if source_errors else 'both_sources_reported',
        'source_errors': source_errors,
        'discovered': discovered, 'exported': len(parsed),
        'source_counts': {'immunefi': len(immunefi), 'github': len(github)},
        'known_advertised_maximums': sum(r['advertised_max_usd'] is not None for r in parsed),
        'unknown_reward_count': sum(r['advertised_max_usd'] is None for r in parsed),
        'kyc_flagged_programs': sum(r['kyc_required'] is True for r in immunefi),
        'invite_only_programs': sum(r['eligibility'] == 'invite_only' for r in immunefi),
        'security_programs_to_review': immunefi[:15],
        'coding_issues_to_review': github[:25],
        'all_review_rows': sorted(parsed, key=lambda r: (r['source'], r['id'])),
        'verified_earnings_usd': 0.0,
        'payout_verification': 'not_integrated',
        'qualification_note': 'Discovery is not acceptance, authorization, eligibility, or a promise of payment.',
    }


def markdown_report(result, digest):
    lines = [
        '# Garcar bounty intelligence — read-only discovery', '',
        '*Source scan:* ' + table_safe(result['source_scan_at']),
        '*Source coverage:* ' + result['source_coverage'],
        '*Rows discovered / exported:* %d / %d' % (result['discovered'], result['exported']),
        '*Listing source counts:* Immunefi %d; GitHub %d' % (
            result['source_counts']['immunefi'], result['source_counts']['github']),
        '*Unknown advertised reward:* %d' % result['unknown_reward_count'],
        '*KYC-flagged Immunefi programs:* %d' % result['kyc_flagged_programs'],
        '*Verified earnings:* $0 — no payout integration',
        '*Scanner JSON SHA-256:* ' + digest, '',
        ('**Important:** Listings and reward amounts are unverified. Read the official scope, eligibility, '
         'deadline, duplicates policy, submission terms, and payout rules before any activity. No exploits, '
         'submissions, transfers, or earnings have been generated by this workflow.'), '',
    ]
    for key, heading in [('coding_issues_to_review', 'GitHub issues for manual review'),
                         ('security_programs_to_review', 'Immunefi programs for manual review')]:
        lines += ['## ' + heading, '', '| Listing | Advertised maximum (unverified) | Review status |',
                  '|---|---:|---|']
        for r in result[key]:
            val = 'Not stated' if r['advertised_max_usd'] is None else '$' + '{:,.0f}'.format(r['advertised_max_usd'])
            title = table_safe(r['title']).replace('[', '\\[').replace(']', '\\]')
            lines.append('| [%s](%s) | %s | Manual scope check |' % (title, r['url'], val))
        lines.append('')
    if result['source_errors']:
        lines += ['## Source errors', ''] + [table_safe(s) for s in result['source_errors']]
    return '\n'.join(lines) + '\n'


def write_outputs(input_path, output_dir):
    raw = Path(input_path).read_bytes()
    data = json.loads(raw)
    report = triage(data)
    digest = sha256(raw).hexdigest()
    dest = Path(output_dir)
    dest.mkdir(parents=True, exist_ok=True)
    (dest / 'triage-report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    with (dest / 'review-queue.csv').open('w', newline='', encoding='utf-8') as f:
        columns = ['id', 'source', 'title', 'url', 'advertised_max_usd', 'eligibility',
                   'kyc_required', 'review_state', 'award_status']
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for r in report['all_review_rows']:
            writer.writerow({k: csv_safe(r.get(k)) for k in columns})
    (dest / 'TRIAGE.md').write_text(markdown_report(report, digest), encoding='utf-8')
    print(json.dumps({k: v for k, v in report.items()
                      if k not in ('all_review_rows', 'security_programs_to_review', 'coding_issues_to_review')},
                     indent=2))
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', required=True)
    p.add_argument('--output-dir', required=True)
    args = p.parse_args()
    write_outputs(args.input, args.output_dir)


if __name__ == '__main__':
    main()
