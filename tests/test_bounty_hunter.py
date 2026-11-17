import asyncio
import importlib.util
import tempfile
import unittest
from pathlib import Path

file_path=Path(__file__).resolve().parents[1]/"crypto"/"bounty_hunter.py"
spec=importlib.util.spec_from_file_location("bounty_hunter",file_path)
b=importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)

class BountyTests(unittest.TestCase):
    def test_immunefi_live_only(self):
        rows=b.immunefi_rows([
            {"slug":"live","project":"Live","maxBounty":"$250,000","isPaused":False},
            {"slug":"paused","isPaused":True},
            {"slug":"expired","endDate":"2020-01-01T00:00:00Z"}])
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]["reward_max_usd"],250000)

    def test_github_unknown_reward(self):
        rows=b.github_rows({"items":[
            {"html_url":"https://github.com/a/b/issues/1","title":"Crypto bounty","body":"Open issue"},
            {"html_url":"https://github.com/a/b/issues/2","title":"Reward: $150","body":""}]})
        self.assertIsNone(rows[0]["reward_max_usd"])
        self.assertEqual(rows[1]["reward_max_usd"],150)

    def test_fail_closed_and_db(self):
        with tempfile.TemporaryDirectory() as folder:
            path=str(Path(folder)/"bounties.db")
            con=b.database(path)
            rows=b.immunefi_rows([{"slug":"example","maxBounty":1000}])
            b.save(con,"immunefi",rows)
            b.save(con,"immunefi",rows)
            self.assertEqual(con.execute("SELECT count(*) FROM opportunities").fetchone()[0],1)
            con.close()
            hunter=b.CryptoBountyHunter(db_path=path)
            self.assertEqual(hunter.get_earnings_report()["verified_earnings_usd"],0.0)
            status=asyncio.run(hunter.execute_bounty_collection("immunefi:example"))
            self.assertEqual(status["status"],"not_implemented_approval_required")
            with self.assertRaises(RuntimeError):
                asyncio.run(hunter.process_payment(rows[0],"unverified"))
