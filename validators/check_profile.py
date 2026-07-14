#!/usr/bin/env python3
"""Validate Screening Decisions Profile receipts.

This file intentionally keeps the profile layer thin: stock base verification,
then profile checks.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from allowly_receipt_format import VerificationError, load_keys_from_json, verify_receipt

PII_KEYS = {
    "address",
    "dob",
    "email",
    "first_name",
    "last_name",
    "linkedin_url",
    "name",
    "phone",
    "photo_url",
    "ssn",
}

SCREEN_REASONS = {
    ("allow", "criteria_met"),
    ("deny", "knockout_failed"),
    ("confirm", "confirm_threshold"),
    ("escalate", "criteria_below_confirm"),
    ("escalate", "parse_warning"),
    ("escalate", "accommodation_requested"),
    ("escalate", "context_field_missing"),
}


def validate_receipt(
    receipt: dict[str, Any],
    scope: dict[str, dict] | None = None,
    keys: dict[str, Any] | None = None,
) -> str | None:
    base_error = _base_verify(receipt, keys)
    if base_error is not None:
        return base_error
    profile_error = _profile_check(receipt)
    if profile_error is not None:
        return profile_error
    if scope is not None:
        return _chain_check(receipt, scope)
    return None


def validate_vectors(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    keys = data["keys"]
    receipts = [item["receipt"] for item in data.get("valid", [])]
    receipts.extend(item["receipt"] for item in data.get("invalid", []))
    scope = {receipt["receipt_id"]: receipt for receipt in receipts}
    failures: list[str] = []
    for item in data.get("valid", []):
        reason = validate_receipt(item["receipt"], scope, keys)
        if reason is not None:
            failures.append(f"valid {item['name']} failed: {reason}")
    for item in data.get("invalid", []):
        reason = validate_receipt(item["receipt"], scope, keys)
        if reason != item["reason"]:
            failures.append(
                f"invalid {item['name']} expected {item['reason']} got {reason or 'pass'}"
            )
    return failures


def _base_verify(receipt: dict[str, Any], keys: dict[str, Any] | None) -> str | None:
    if keys is None:
        return "base_keys_required"
    try:
        verify_receipt(
            receipt,
            load_keys_from_json(keys),
            expected_workspace_id=keys.get("workspace_id"),
        )
    except VerificationError as exc:
        if "non-integer numbers" in str(exc):
            return "float_in_context"
        return "base_verification_failed"
    return None


def _profile_check(receipt: dict[str, Any]) -> str | None:
    context = receipt["context"]
    pii_error = _pii_check(context)
    if pii_error is not None:
        return pii_error
    action = receipt.get("action") or receipt.get("event")
    decision = receipt["decision"]
    reason = receipt["reason"]
    if action == "candidate.screen":
        if (decision, reason) not in SCREEN_REASONS:
            return "vocabulary_mispairing"
        return _candidate_screen_check(receipt)
    if action == "candidate.review":
        if decision not in {"allow", "deny"} or not reason.startswith("review_"):
            return "vocabulary_mispairing"
        return _review_check(receipt)
    if action == "adverse_action.issue":
        if (decision, reason) != ("allow", "letter_issued"):
            return "vocabulary_mispairing"
        return None if "decision_refs" in context else "missing_decision_refs"
    if action == "audit.export":
        if (decision, reason) != ("allow", "export_generated"):
            return "vocabulary_mispairing"
        if "manifest_digest" not in context or "filter" not in context:
            return "missing_audit_context"
        return None
    if action == "authorization.create":
        if decision != "authorization_granted":
            return "vocabulary_mispairing"
        return None if "policy" in context else "missing_policy_context"
    if action == "authorization.revoke":
        if decision != "authorization_revoked":
            return "vocabulary_mispairing"
        return None if "revoked_by" in context else "missing_revoke_context"
    return "vocabulary_mispairing"


def _candidate_screen_check(receipt: dict[str, Any]) -> str | None:
    context = receipt["context"]
    if "subject" not in context or "requisition_id" not in context:
        return "missing_subject_or_requisition"
    if receipt["decision"] != "deny":
        if "criteria_passed" not in context or "criteria_failed" not in context:
            return "missing_criteria_context"
        if receipt["reason"] == "parse_warning" and "parse_warning" not in context:
            return "missing_parse_warning"
        return None
    policy_eval = receipt.get("policy_eval")
    if not isinstance(policy_eval, dict):
        return "missing_policy_eval"
    matched = policy_eval.get("matched_condition")
    if not isinstance(matched, dict) or "field" not in matched:
        return "missing_policy_eval"
    if "citation" not in context:
        return "missing_citation"
    supplied = context.get("fields_supplied_by")
    if isinstance(supplied, dict):
        field = matched["field"]
        if field not in supplied.get("customer", []):
            return "provenance_gate_violation"
    return None


def _review_check(receipt: dict[str, Any]) -> str | None:
    context = receipt["context"]
    if "replaces_receipt" not in context:
        return "missing_replaces_receipt"
    if "requisition_id" not in context:
        return "missing_requisition_id"
    return None


def _chain_check(receipt: dict[str, Any], scope: dict[str, dict]) -> str | None:
    replaces = receipt.get("context", {}).get("replaces_receipt")
    if replaces is None:
        return None
    if replaces not in scope:
        return "broken_replaces_chain"
    seen = {receipt["receipt_id"]}
    cursor = replaces
    while cursor is not None:
        if cursor in seen:
            return "broken_replaces_chain"
        seen.add(cursor)
        cursor = scope.get(cursor, {}).get("context", {}).get("replaces_receipt")
    return None


def _pii_check(value: Any) -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in PII_KEYS:
                return "pii_in_context"
            child_error = _pii_check(child)
            if child_error is not None:
                return child_error
    elif isinstance(value, list):
        for child in value:
            child_error = _pii_check(child)
            if child_error is not None:
                return child_error
    elif isinstance(value, str) and "@" in value:
        return "pii_in_context"
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt")
    parser.add_argument("--vectors", action="store_true")
    args = parser.parse_args(argv)
    path = Path(args.receipt)
    if args.vectors:
        failures = validate_vectors(path)
        if failures:
            for failure in failures:
                print(failure)
            return 1
        print("profile vectors passed")
        return 0
    doc = json.loads(path.read_text(encoding="utf-8"))
    receipt = doc.get("receipt", doc)
    keys = doc.get("keys")
    reason = validate_receipt(receipt, keys=keys)
    if reason is not None:
        print(reason)
        return 1
    print("profile receipt passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
