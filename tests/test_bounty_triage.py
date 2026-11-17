import csv
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

path=Path(__file__).resolve().parents[1]/'crypto'/'bounty_triage.py'
spec=importlib.util.spec_from_file_location('bounty_triage',path)
b=importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)

def sample():
    return {'discovered':2,'scanned_at':'2026-11-17T18:52:50+00:00','source_errors':[], 'top':[
        {'id':'immunefi:demo','platform':'immunefi','title':'Secure','url':'https://immunefi.com/bug-bounty/demo/information/','reward_max_usd':1000,'eligibility':'check_program_rules','kyc_required':True},
        {'id':'github:abc/repo/issues/3','platform':'github','title':'=HYPERLINK("bad")','url':'https://github.com/abc/repo/issues/3','reward_max_usd':None,'eligibility':'check_issue_rules','kyc_required':None}]}

class TestTriage(unittest.TestCase):
    def test_source_counts_and_safeguards(self):
        r=b.triage(sample())
        self.assertEqual(r['exported'],2)
        self.assertEqual(r['source_counts']['github'],1)
        self.assertEqual(r['known_advertised_maximums'],1)
        self.assertEqual(r['unknown_reward_count'],1)
        self.assertEqual(r['verified_earnings_usd'],0)
        self.assertEqual(r['kyc_flagged_programs'],1)

    def test_rejects_partial_export(self):
        d=sample();d['discovered']=3
        with self.assertRaisesRegex(ValueError,'incomplete'):b.triage(d)

    def test_rejects_duplicate_and_unknown_host(self):
        d=sample();d['top'].append(d['top'][0]);d['discovered']=3
        with self.assertRaisesRegex(ValueError,'Duplicated'):b.triage(d)
        d=sample();d['top'][0]['url']='https://other.example/bad'
        with self.assertRaisesRegex(ValueError,'Malformed'):b.triage(d)

    def test_outputs_and_csv_spreadsheet_injection(self):
        with tempfile.TemporaryDirectory() as tmp:
            src=Path(tmp)/'input.json'
            src.write_text(json.dumps(sample()),encoding='utf-8')
            out=b.write_outputs(src,Path(tmp)/'result')
            self.assertTrue((Path(tmp)/'result'/'TRIAGE.md').exists())
            self.assertEqual(out['exported'],2)
            with (Path(tmp)/'result'/'review-queue.csv').open(newline='',encoding='utf-8') as f:
                rows=list(csv.DictReader(f))
            self.assertTrue(next(r for r in rows if r['source']=='github')['title'].startswith("'="))
