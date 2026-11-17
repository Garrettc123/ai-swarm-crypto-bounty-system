"""Hermetic tests for evidence gate; fixtures do not represent real payouts."""
import unittest
from blockscout_evidence import Expectation, assess_transaction, assess_json_document

RECIPIENT = "0x" + "a" * 40
TOKEN = "0x" + "b" * 40
TX = "0x" + "c" * 64
WRONG = "0x" + "d" * 40

def expected():
    return Expectation("8453", TX, RECIPIENT, TOKEN, 1000000)

def event(to=RECIPIENT, token=TOKEN, raw="1500000"):
    return {"to": {"hash": to}, "token": {"address_hash": token, "type": "ERC-20", "decimals": "6"}, "total": {"value": raw, "decimals": "6"}}

def tx(*, status="ok", transfers=None, block=100):
    return {"hash": TX, "status": status, "block_number": block,
            "token_transfers": [event()] if transfers is None else transfers}

def check(transaction=None, **kwargs):
    return assess_transaction(
        expectation=kwargs.pop("expectation", expected()),
        observed_chain_id=kwargs.pop("observed_chain_id", "8453"),
        transaction=transaction if transaction is not None else tx(),
        latest_block=kwargs.pop("latest_block", 115),
        **kwargs
    )

class TestBlockscoutEvidence(unittest.TestCase):
    def test_matching_transfer_is_not_payout_proof(self):
        r = check()
        self.assertEqual(r["status"], "transfer_consistent_with_expectation")
        self.assertTrue(r["onchain_match"])
        self.assertFalse(r["bounty_payout_verified"])
        self.assertEqual(r["matched_raw_amount"], "1500000")

    def test_mismatched_chain_fails(self):
        self.assertEqual(check(observed_chain_id="1")["reasons"], ["chain_mismatch"])

    def test_missing_or_wrong_hash_fails(self):
        self.assertEqual(check({**tx(), "hash": "0x" + "e" * 64})["reasons"],
                         ["transaction_hash_mismatch"])

    def test_failed_transaction_fails(self):
        self.assertEqual(check(tx(status="error"))["reasons"], ["transaction_not_successful"])

    def test_unconfirmed_transaction_fails(self):
        self.assertEqual(check(latest_block=105)["reasons"], ["insufficient_confirmations"])

    def test_no_head_block_fails_closed(self):
        self.assertEqual(check(latest_block=None)["reasons"], ["block_finality_unavailable"])

    def test_spoof_token_or_recipient_fails(self):
        for transfers in ([event(token=WRONG)], [event(to=WRONG)]):
            with self.subTest(transfers=transfers):
                self.assertFalse(check(tx(transfers=transfers))["onchain_match"])

    def test_small_amount_fails(self):
        r = check(tx(transfers=[event(raw="999999")]))
        self.assertEqual(r["reasons"], ["amount_below_pinned_threshold"])

    def test_float_amount_rejected(self):
        self.assertFalse(check(tx(transfers=[event(raw=1000000.0)]))["onchain_match"])

    def test_invalid_expectation_rejected(self):
        r = check(expectation=Expectation("8453", TX, RECIPIENT, TOKEN, 0))
        self.assertEqual(r["reasons"], ["invalid_or_unpinned_expectation"])

    def test_wrong_token_type_rejected(self):
        transfer = event()
        transfer["token"]["type"] = "ERC-721"
        self.assertEqual(check(tx(transfers=[transfer]))["reasons"], ["no_matching_erc20_transfer"])

    def test_zero_gas_transfer_not_inferred_as_payout(self):
        r = check(tx(transfers=[]))
        self.assertFalse(r["bounty_payout_verified"])

    def test_no_input_produces_unverified(self):
        r = assess_json_document({})
        self.assertEqual(r["status"], "unverified")

if __name__ == "__main__":
    unittest.main()
