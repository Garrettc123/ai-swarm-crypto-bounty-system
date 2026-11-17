"""Fail-closed, offline evaluation of Blockscout EVM transaction evidence.

Never treats a GitHub bounty label, a transaction hash, or a token transfer
alone as proof that a bounty was won or paid. Input is a separately captured
Blockscout transaction response; this module does not connect to wallets,
submit transactions, discover targets or access secrets.

A matching transfer is only evidence of on-chain movement. The sponsor,
claim, entitlement, and acceptance must be independently verified.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

ADDRESS = re.compile(r"^0x[a-fA-F0-9]{40}$")
TX_HASH = re.compile(r"^0x[a-fA-F0-9]{64}$")
CHAINS = frozenset({"1", "8453", "10", "42161", "137"})
MIN_CONFIRMATIONS = 12


def _address(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("hash") or value.get("address") or value.get("address_hash")
    return value.lower() if isinstance(value, str) and ADDRESS.fullmatch(value) else None


def _integer(value: Any) -> int | None:
    # Explicitly reject floating-point and booleans: raw token amounts must
    # not silently lose precision.
    if type(value) is int:
        return value if value >= 0 else None
    if isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        return int(value)
    return None


def _raw_amount(value: Any) -> int | None:
    if isinstance(value, dict):
        value = value.get("value")
    return _integer(value)


def _hash(value: Any) -> str | None:
    return value.lower() if isinstance(value, str) and TX_HASH.fullmatch(value) else None


@dataclass(frozen=True)
class Expectation:
    chain_id: str
    transaction_hash: str
    recipient: str
    token_contract: str
    min_raw_amount: int
    # A designated payout recipient and authentic token contract must be
    # established externally. We do not infer them from bounty issue text.
    def validated(self) -> bool:
        return (
            self.chain_id in CHAINS
            and _hash(self.transaction_hash) is not None
            and _address(self.recipient) is not None
            and _address(self.token_contract) is not None
            and type(self.min_raw_amount) is int and self.min_raw_amount > 0
        )


def assess_transaction(
    *,
    expectation: Expectation,
    observed_chain_id: str,
    transaction: dict,
    latest_block: int | None,
    minimum_confirmations: int = MIN_CONFIRMATIONS,
) -> dict:
    """Evaluate a supplied Blockscout tx snapshot against pinned expectations.

    Never emits an absolute 'payout confirmed' result: the trusted funding
    source, authorization, bounty acceptance and beneficiary association are
    independent steps outside the scope of a blockchain explorer.
    """
    reasons: list[str] = []
    result = {
        "status": "unverified",
        "onchain_match": False,
        "bounty_payout_verified": False,
        "source": "supplied_blockscout_snapshot_not_authenticated",
        "chain_id": expectation.chain_id,
        "transaction_hash": expectation.transaction_hash,
        "confirmations": None,
        "matched_raw_amount": None,
        "reasons": reasons,
        "required_external_checks": [
            "Authenticate the Blockscout result against the chain independently",
            "Verify the token contract against the original sponsor program",
            "Verify sponsor identity, funded terms, eligible claimant and accepted work",
            "Verify the recipient belongs to the accepted claimant",
        ],
    }
    if not expectation.validated():
        reasons.append("invalid_or_unpinned_expectation")
        return result
    if observed_chain_id != expectation.chain_id:
        reasons.append("chain_mismatch")
        return result
    if not isinstance(transaction, dict):
        reasons.append("transaction_payload_invalid")
        return result
    if _hash(transaction.get("hash")) != expectation.transaction_hash.lower():
        reasons.append("transaction_hash_mismatch")
        return result
    if str(transaction.get("status", "")).lower() not in {"ok", "success", "1"}:
        reasons.append("transaction_not_successful")
        return result
    block = _integer(transaction.get("block_number"))
    head = _integer(latest_block)
    if block is None or head is None or head < block:
        reasons.append("block_finality_unavailable")
        return result
    confirmations = head - block + 1
    result["confirmations"] = confirmations
    if type(minimum_confirmations) is not int or minimum_confirmations < 1:
        reasons.append("invalid_finality_policy")
        return result
    if confirmations < minimum_confirmations:
        reasons.append("insufficient_confirmations")
        return result

    transfers = transaction.get("token_transfers")
    if not isinstance(transfers, list):
        reasons.append("token_transfer_evidence_missing")
        return result

    matches: list[int] = []
    for transfer in transfers:
        if not isinstance(transfer, dict):
            continue
        token = transfer.get("token")
        if not isinstance(token, dict):
            continue
        token_address = _address(
            token.get("address") or token.get("address_hash")
            or token.get("contract_address")
        )
        recipient = _address(transfer.get("to"))
        standard = str(token.get("type") or "ERC-20").upper().replace("_", "-")
        if standard not in {"ERC-20", "ERC20"}:
            continue
        if token_address != expectation.token_contract.lower():
            continue
        if recipient != expectation.recipient.lower():
            continue
        raw = _raw_amount(transfer.get("total"))
        if raw is None:
            raw = _raw_amount(transfer.get("amount"))
        if raw is None:
            continue
        matches.append(raw)

    if not matches:
        reasons.append("no_matching_erc20_transfer")
        return result
    total = sum(matches)
    result["matched_raw_amount"] = str(total)
    if total < expectation.min_raw_amount:
        reasons.append("amount_below_pinned_threshold")
        return result
    result["onchain_match"] = True
    result["status"] = "transfer_consistent_with_expectation"
    reasons.append("matching_erc20_transfer_observed")
    reasons.append("payout_entitlement_and_source_authenticity_unverified")
    return result


def assess_json_document(payload: dict) -> dict:
    """Convenience contract for a manually captured, operator-reviewed file."""
    exp = payload.get("expectation", {})
    try:
        expectation = Expectation(
            chain_id=exp["chain_id"],
            transaction_hash=exp["transaction_hash"],
            recipient=exp["recipient"],
            token_contract=exp["token_contract"],
            min_raw_amount=exp["min_raw_amount"],
        )
    except (TypeError, KeyError):
        return {"status": "unverified", "onchain_match": False,
                "bounty_payout_verified": False,
                "reasons": ["missing_expectation"]}
    return assess_transaction(
        expectation=expectation,
        observed_chain_id=payload.get("observed_chain_id"),
        transaction=payload.get("transaction", {}),
        latest_block=payload.get("latest_block"),
    )


def main() -> None:
    """Evaluate a local input file without importing wallets or broadcasting."""
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_json", help="Existing captured transaction evidence JSON")
    args = parser.parse_args()
    data = json.loads(Path(args.evidence_json).read_text(encoding="utf-8"))
    print(json.dumps(assess_json_document(data), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
