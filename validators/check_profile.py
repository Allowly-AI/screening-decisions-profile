#!/usr/bin/env python3
"""Validate Screening Decisions Profile receipts.

This file intentionally keeps the profile layer thin: stock base verification,
then profile checks.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from allowly_receipt_format import (
    VerificationError,
    load_keys_from_json,
    public_key_fingerprint,
    verify_receipt,
)


TRUSTED_KEY_FINGERPRINT_RE = re.compile(r"sha256:[0-9a-f]{64}")
DIGEST_PREFIX = "sha256:"
OPAQUE_SOURCE_ID_RE = re.compile(
    r"^[a-z][a-z0-9_]{1,31}:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)
OPAQUE_WORKSPACE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
POLICY_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]*(?:/[A-Za-z0-9][A-Za-z0-9._:-]*)*$"
)
POLICY_VERSION_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)

CANDIDATE_PREFIX = "candidate:"

# Profile 6: the producer's knockout attestation is exactly these four keys —
# no fewer (the compared scalar is the evidence) and no more (a fifth key is
# where a second copy of the candidate's data would ride along).
KNOCKOUT_KEYS = frozenset({"field", "op", "value", "field_value"})

# Profile 7: the provenance map is exactly these two keys, each a list of
# field names.
PROVENANCE_KEYS = frozenset({"customer", "cv"})

# Profile 5: a screen's subject is the opaque candidate id plus the digest
# that distinguishes one submitted payload from the next; a scan digest is
# the one permitted addition.
SUBJECT_KEYS = frozenset({"uuid", "payload_digest"})
SUBJECT_OPTIONAL_KEYS = frozenset({"file_digest"})

PII_KEYS = {
    "address",
    "dob",
    "email",
    "first_name",
    "full_name",
    "last_name",
    "linkedin_url",
    "name",
    "phone",
    "photo_url",
    "ssn",
}

# v0.3: `reason` is the ISSUER's machine code (base spec 3.1); the producer's
# screening semantics live in context (tier, detail_code, knockout, review_*).
SCREEN_REASONS = {
    ("allow", "authorization_granted_action_active"),
    ("deny", "deny_condition_matched"),
    ("confirm", "confirm_condition_matched"),
    ("confirm", "context_field_missing"),
    ("escalate", "escalate_condition_matched"),
    ("escalate", "context_field_missing"),
}

# Profile 4: the decision verb and the tier are different vocabularies and are
# resolved through this table, never by comparing the two strings.
TIER_BY_DECISION = {
    "allow": "advance",
    "deny": "deny",
    "confirm": "confirm",
    "escalate": "escalate",
}
REVIEW_DECISION_BY_DECISION = {"allow": "advance", "deny": "reject"}
STANDARD_CONTEXT_KEYS = {
    "candidate.screen": frozenset(
        {
            "subject",
            "requisition_id",
            "fields_supplied_by",
            "tier",
            "criteria_passed",
            "criteria_failed",
            "detail_code",
            "knockout",
            "knockout_id",
            "citation",
            "replaces_receipt",
            "on_behalf_of",
            "organization",
            "operator",
        }
    ),
    "candidate.review": frozenset(
        {
            "review_decision",
            "replaces_receipt",
            "requisition_id",
            "review_basis",
            "subject",
            "on_behalf_of",
            "organization",
            "operator",
        }
    ),
    "adverse_action.issue": frozenset(
        {"decision_refs", "subject", "on_behalf_of", "organization", "operator"}
    ),
    "audit.export": frozenset(
        {"manifest_digest", "filter", "on_behalf_of", "organization", "operator"}
    ),
    "authorization.create": frozenset(
        {
            "policy",
            "replaces",
            "on_behalf_of",
            "organization",
            "operator",
            "approval_schema_version",
            "approval_id",
            "approval_digest",
            "approving_user_id",
            "organization_id",
            "identity_assurance",
            "authentication_credential_id",
            "funnelops_workspace_id",
        }
    ),
    "authorization.revoke": frozenset(
        {
            "revoked_by",
            "superseded_by",
            "on_behalf_of",
            "organization",
            "operator",
        }
    ),
}


def validate_receipt(
    receipt: dict[str, Any],
    scope: dict[str, dict] | None = None,
    keys: dict[str, Any] | None = None,
    *,
    expected_workspace_id: str | None = None,
    trusted_key_fingerprints: set[str] | frozenset[str] | None = None,
    notes: list[str] | None = None,
) -> str | None:
    """Return the first failing check, or None. Conditions that are reported
    without failing the receipt (see `_chain_check`) are appended to `notes`."""
    base_error = _base_verify(
        receipt,
        keys,
        expected_workspace_id=expected_workspace_id,
        trusted_key_fingerprints=trusted_key_fingerprints,
    )
    if base_error is not None:
        return base_error
    profile_error = _profile_check(receipt)
    if profile_error is not None:
        return profile_error
    if scope is not None:
        return _chain_check(receipt, scope, notes if notes is not None else [])
    return None


def validate_vectors(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    keys = data["keys"]
    expected_workspace_id = keys["workspace_id"]
    trusted_key_fingerprints = {
        public_key_fingerprint(key) for key in load_keys_from_json(keys)
    }
    receipts = [item["receipt"] for item in data.get("valid", [])]
    receipts.extend(item["receipt"] for item in data.get("invalid", []))
    scope = {receipt["receipt_id"]: receipt for receipt in receipts}
    failures: list[str] = []
    for item in data.get("valid", []):
        notes: list[str] = []
        reason = validate_receipt(
            item["receipt"],
            scope,
            keys,
            expected_workspace_id=expected_workspace_id,
            trusted_key_fingerprints=trusted_key_fingerprints,
            notes=notes,
        )
        if reason is not None:
            failures.append(f"valid {item['name']} failed: {reason}")
            continue
        if sorted(notes) != sorted(item.get("notes", [])):
            failures.append(
                f"valid {item['name']} expected notes {item.get('notes', [])} "
                f"got {notes}"
            )
    for item in data.get("invalid", []):
        reason = validate_receipt(
            item["receipt"],
            scope,
            keys,
            expected_workspace_id=expected_workspace_id,
            trusted_key_fingerprints=trusted_key_fingerprints,
        )
        if reason != item["reason"]:
            failures.append(
                f"invalid {item['name']} expected {item['reason']} got {reason or 'pass'}"
            )
    return failures


def _base_verify(
    receipt: dict[str, Any],
    keys: dict[str, Any] | None,
    *,
    expected_workspace_id: str | None,
    trusted_key_fingerprints: set[str] | frozenset[str] | None,
) -> str | None:
    if keys is None:
        return "base_keys_required"
    if not expected_workspace_id:
        return "base_workspace_required"
    if not trusted_key_fingerprints:
        return "base_key_fingerprint_required"
    if keys.get("workspace_id") != expected_workspace_id:
        return "base_workspace_mismatch"
    try:
        verify_receipt(
            receipt,
            load_keys_from_json(keys),
            expected_workspace_id=expected_workspace_id,
            trusted_key_fingerprints=trusted_key_fingerprints,
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
    value_error = _candidate_value_check(receipt)
    if value_error is not None:
        return value_error
    extension_error = _context_key_check(receipt)
    if extension_error is not None:
        return extension_error
    organization_error = _organization_check(context)
    if organization_error is not None:
        return organization_error
    action = receipt.get("action") or receipt.get("event")
    decision = receipt["decision"]
    reason = receipt["reason"]
    if action == "candidate.screen":
        if (decision, reason) not in SCREEN_REASONS:
            return "vocabulary_mispairing"
        return _candidate_screen_check(receipt)
    if action == "candidate.review":
        review_reasons = {"authorization_granted_action_active", "deny_condition_matched"}
        if decision not in {"allow", "deny"} or reason not in review_reasons:
            return "vocabulary_mispairing"
        return _review_check(receipt)
    if action == "adverse_action.issue":
        if (decision, reason) != ("allow", "authorization_granted_action_active"):
            return "vocabulary_mispairing"
        refs = context.get("decision_refs")
        if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
            return "missing_decision_refs"
        return None
    if action == "audit.export":
        if (decision, reason) != ("allow", "authorization_granted_action_active"):
            return "vocabulary_mispairing"
        if "manifest_digest" not in context or "filter" not in context:
            return "missing_audit_context"
        return None
    if action == "authorization.create":
        if decision != "authorization_granted":
            return "vocabulary_mispairing"
        policy_error = _policy_context_check(context.get("policy"))
        approval_error = _approval_context_check(context)
        lifecycle_error = policy_error or approval_error
        if lifecycle_error is not None:
            return lifecycle_error
        if "approval_id" in context and receipt.get("user_id") != context.get(
            "approving_user_id"
        ):
            return "approval_user_mismatch"
        return policy_error
    if action == "authorization.revoke":
        if decision != "authorization_revoked":
            return "vocabulary_mispairing"
        return None if "revoked_by" in context else "missing_revoke_context"
    return "vocabulary_mispairing"


def _candidate_uuid(resource: Any) -> str | None:
    """The `<uuid>` of a `candidate:<uuid>` resource, else None."""
    if isinstance(resource, str) and resource.startswith(CANDIDATE_PREFIX):
        return resource[len(CANDIDATE_PREFIX) :]
    return None


def _candidate_screen_check(receipt: dict[str, Any]) -> str | None:
    context = receipt["context"]
    if "subject" not in context or "requisition_id" not in context:
        return "missing_subject_or_requisition"
    # Profile 5: `resource` is the canonical candidate link, and a screen's
    # subject must name the same candidate.
    subject = context["subject"]
    resource_uuid = _candidate_uuid(receipt.get("resource"))
    if not isinstance(subject, dict) or resource_uuid is None:
        return "subject_resource_mismatch"
    if subject.get("uuid") != resource_uuid:
        return "subject_resource_mismatch"
    # Without `payload_digest` the uuid alone cannot say which submitted
    # payload a screen decided on, so a correction and the screen it corrects
    # become indistinguishable.
    subject_keys = frozenset(subject)
    if not SUBJECT_KEYS <= subject_keys:
        return "invalid_subject_shape"
    if not subject_keys <= (SUBJECT_KEYS | SUBJECT_OPTIONAL_KEYS):
        return "invalid_subject_shape"
    if not _digest(subject.get("payload_digest")):
        return "invalid_subject_shape"
    if "file_digest" in subject and not _digest(subject.get("file_digest")):
        return "invalid_subject_shape"
    if context.get("tier") != TIER_BY_DECISION[receipt["decision"]]:
        return "tier_decision_mismatch"
    if "fields_supplied_by" in context:
        shape_error = _provenance_map_check(context["fields_supplied_by"])
        if shape_error is not None:
            return shape_error
    if receipt["decision"] != "deny":
        if not _string_list(context.get("criteria_passed")) or not _string_list(
            context.get("criteria_failed")
        ):
            return "missing_criteria_context"
        if receipt["decision"] == "escalate" and "detail_code" not in context:
            return "missing_detail_code"
        return None
    policy_eval = receipt.get("policy_eval")
    if not isinstance(policy_eval, dict):
        return "missing_policy_eval"
    matched = policy_eval.get("matched_condition")
    if matched != {"field": "tier", "op": "eq", "value": "deny"}:
        return "missing_policy_eval"
    if policy_eval.get("field_value") != "deny":
        return "missing_policy_eval"
    knockout = context.get("knockout")
    if not isinstance(knockout, dict):
        return "missing_knockout_context"
    if frozenset(knockout) != KNOCKOUT_KEYS:
        return "invalid_knockout_shape"
    if "citation" not in context:
        return "missing_citation"
    # Profile 6: the provenance map is mandatory on knockout denials, so the
    # customer-asserted-field gate is checkable from the receipt alone. Its
    # shape was validated above, so `customer` here is a list of field names
    # and the gate is a membership test.
    if "fields_supplied_by" not in context:
        return "missing_fields_supplied_by"
    if knockout["field"] not in context["fields_supplied_by"]["customer"]:
        return "provenance_gate_violation"
    return None


def _provenance_map_check(supplied: Any) -> str | None:
    """Profile 7: `fields_supplied_by` is `{"customer": [...], "cv": [...]}`,
    each a list of field names.

    The shape carries the §6 gate. A bare string under `"customer"` would turn
    the gate's membership test into substring containment, so that a knockout
    on `work_authorization` would clear a map that supplies only
    `"work_authorization_asserted_by_vendor"` — the CV-only case §6 declares
    non-conformant, admitted by a spelling. Both provenance keys are required
    and no others are accepted, on the same reasoning as the four-key knockout
    shape: an extra key is where a second copy of the candidate's data rides.
    """
    if not isinstance(supplied, dict) or frozenset(supplied) != PROVENANCE_KEYS:
        return "invalid_fields_supplied_by"
    for names in supplied.values():
        if not isinstance(names, list):
            return "invalid_fields_supplied_by"
        if any(not isinstance(name, str) for name in names):
            return "invalid_fields_supplied_by"
    return None


def _review_check(receipt: dict[str, Any]) -> str | None:
    context = receipt["context"]
    if context.get("review_decision") != REVIEW_DECISION_BY_DECISION[receipt["decision"]]:
        return "missing_review_decision"
    if "replaces_receipt" not in context:
        return "missing_replaces_receipt"
    if "requisition_id" not in context:
        return "missing_requisition_id"
    return None


def _context_key_check(receipt: dict[str, Any]) -> str | None:
    action = receipt.get("action") or receipt.get("event")
    allowed = STANDARD_CONTEXT_KEYS.get(action)
    if allowed is None:
        return None
    for key in receipt["context"]:
        if key not in allowed and not key.startswith("x_"):
            return "unprefixed_extension_context"
    return None


def _policy_context_check(policy: Any) -> str | None:
    if not isinstance(policy, dict) or set(policy) != {"id", "version", "digest"}:
        return "missing_policy_context"
    policy_id = policy["id"]
    policy_version = policy["version"]
    if (
        not isinstance(policy_id, str)
        or not 1 <= len(policy_id) <= 128
        or not POLICY_ID_RE.fullmatch(policy_id)
        or _has_funnelops_secret_component(policy_id)
        or not isinstance(policy_version, str)
        or not 5 <= len(policy_version) <= 32
        or not POLICY_VERSION_RE.fullmatch(policy_version)
    ):
        return "missing_policy_context"
    return None if _digest(policy.get("digest")) else "missing_policy_context"


def _organization_check(context: dict[str, Any]) -> str | None:
    organization = context.get("organization")
    if organization is None:
        return None
    if not isinstance(organization, dict) or set(organization) != {
        "id",
        "workspace_id",
    }:
        return "invalid_organization_context"
    if not OPAQUE_SOURCE_ID_RE.fullmatch(str(organization.get("id", ""))):
        return "invalid_organization_context"
    workspace_id = organization.get("workspace_id")
    if (
        not isinstance(workspace_id, str)
        or not OPAQUE_WORKSPACE_ID_RE.fullmatch(workspace_id)
        or _has_funnelops_secret_component(workspace_id)
    ):
        return "invalid_organization_context"
    operator = context.get("operator")
    if not isinstance(operator, str) or not operator:
        return "missing_operator_context"
    return None


def _approval_context_check(context: dict[str, Any]) -> str | None:
    approval_keys = {
        "approval_schema_version",
        "approval_id",
        "approval_digest",
        "approving_user_id",
        "organization_id",
        "identity_assurance",
        "authentication_credential_id",
        "funnelops_workspace_id",
    }
    present = approval_keys.intersection(context)
    if not present:
        return None
    if present != approval_keys:
        return "missing_approval_context"
    if context["approval_schema_version"] != "policy_approval.v1":
        return "unsupported_approval_schema"
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(context["approval_digest"])):
        return "invalid_approval_digest"
    for key in (
        "approval_id",
        "approving_user_id",
        "organization_id",
        "authentication_credential_id",
    ):
        value = context[key]
        if (
            not isinstance(value, str)
            or not OPAQUE_SOURCE_ID_RE.fullmatch(value)
            or _has_funnelops_secret_component(value)
        ):
            return "invalid_approval_identity"
    approval_workspace_id = context["funnelops_workspace_id"]
    if (
        not isinstance(approval_workspace_id, str)
        or not OPAQUE_WORKSPACE_ID_RE.fullmatch(approval_workspace_id)
        or _has_funnelops_secret_component(approval_workspace_id)
    ):
        return "invalid_approval_identity"
    if context["identity_assurance"] not in {
        "authenticated_user",
        "organization_asserted",
    }:
        return "invalid_identity_assurance"
    organization = context.get("organization")
    if (
        not isinstance(organization, dict)
        or organization.get("id") != context["organization_id"]
        or organization.get("workspace_id") != context["funnelops_workspace_id"]
    ):
        return "organization_approval_mismatch"
    if context.get("operator") != "FunnelOps":
        return "approval_operator_mismatch"
    return None


def _has_funnelops_secret_component(value: str) -> bool:
    """Recognize FunnelOps API-key-shaped components, not arbitrary semantics."""
    return any(component.startswith("fops_") for component in re.split(r"[:/]", value))


def _digest(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(DIGEST_PREFIX) and len(value) > len(
        DIGEST_PREFIX
    )


def _string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _chain_check(
    receipt: dict[str, Any],
    scope: dict[str, dict],
    notes: list[str],
) -> str | None:
    """Profile 8 chain checks, reported one condition at a time.

    A missing ancestor is a property of the export, not of the receipt: it is
    noted as `incomplete_chain` and the receipt still verifies. A branch, a
    cycle, or a target naming a different candidate or authorization is a
    broken chain and fails.
    """
    replaces = receipt.get("context", {}).get("replaces_receipt")
    if replaces is None:
        return None
    target = scope.get(replaces)
    if target is None:
        notes.append("incomplete_chain")
        return None
    if target.get("resource") != receipt.get("resource"):
        return "chain_resource_mismatch"
    if target.get("authorization_id") != receipt.get("authorization_id"):
        return "chain_authorization_mismatch"
    cycle_error = _cycle_check(receipt, scope, replaces)
    if cycle_error is not None:
        return cycle_error
    # At most one direct successor. Every contender is in a branch, but only
    # one of them can be the chain head, so the earliest by (issued_at,
    # receipt_id) keeps the chain and the later ones are the contested
    # successors this reports on.
    successors = sorted(
        (
            candidate
            for candidate in scope.values()
            if candidate.get("context", {}).get("replaces_receipt") == replaces
        ),
        key=lambda candidate: (candidate.get("issued_at", ""), candidate["receipt_id"]),
    )
    if len(successors) > 1 and receipt["receipt_id"] != successors[0]["receipt_id"]:
        return "chain_branch"
    return None


def _cycle_check(
    receipt: dict[str, Any],
    scope: dict[str, dict],
    replaces: str,
) -> str | None:
    seen = {receipt["receipt_id"]}
    cursor: Any = replaces
    while cursor is not None:
        if cursor in seen:
            return "chain_cycle"
        seen.add(cursor)
        cursor = scope.get(cursor, {}).get("context", {}).get("replaces_receipt")
    return None


def _walk_dicts(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_dicts(child)


def _is_knockout_denial(receipt: dict[str, Any]) -> bool:
    """Profile 6: a knockout denial is a `candidate.screen` receipt deciding
    `deny`. Agreement between the decision and `context.tier` is a separate
    check, so a denial carrying the wrong tier is rejected there rather than
    silently losing its knockout exemption here."""
    action = receipt.get("action") or receipt.get("event")
    return action == "candidate.screen" and receipt.get("decision") == "deny"


def _candidate_value_check(receipt: dict[str, Any]) -> str | None:
    """Profile 7 minimization: one candidate value, in one place.

    `context.knockout.field_value` is the compared scalar behind a knockout
    denial, and is the only candidate value permitted anywhere in `context` —
    and only on a receipt that is a knockout denial. On every other receipt
    `context.knockout` is an ordinary container with no exemption, so a name,
    an address or a salary parked there is caught like any other stray value.
    The top-level `policy_eval.field_value` is outside `context` and outside
    this check by design: it records the issuer's routing value, not a
    candidate's data.
    """
    context = receipt["context"]
    permitted = context.get("knockout") if _is_knockout_denial(receipt) else None
    for holder in _walk_dicts(context):
        if "field_value" in holder and holder is not permitted:
            return "candidate_value_outside_knockout"
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
    parser.add_argument(
        "--keys",
        help="issuer keys.json (dashboard download, or the public "
        "GET /v1/workspaces/{workspace_id}/keys endpoint)",
    )
    parser.add_argument(
        "--workspace-id",
        help="caller-trusted workspace ID; must match keys.json and the receipt",
    )
    parser.add_argument(
        "--trusted-key-fingerprint",
        action="append",
        default=[],
        help="caller-trusted sha256 fingerprint; repeat for trusted rotation keys",
    )
    parser.add_argument(
        "--scope",
        help="optional JSON export containing receipts for profile §8 chain checks",
    )
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
    if not args.workspace_id:
        parser.error("--workspace-id is required outside --vectors mode")
    if not args.trusted_key_fingerprint:
        parser.error("at least one --trusted-key-fingerprint is required outside --vectors mode")
    if any(
        TRUSTED_KEY_FINGERPRINT_RE.fullmatch(value) is None
        for value in args.trusted_key_fingerprint
    ):
        parser.error(
            "--trusted-key-fingerprint must be sha256: followed by 64 lowercase hex characters"
        )
    doc = json.loads(path.read_text(encoding="utf-8"))
    receipt = doc.get("receipt", doc)
    keys = doc.get("keys")
    if args.keys:
        keys = json.loads(Path(args.keys).read_text(encoding="utf-8"))
    notes: list[str] = []
    scope = _load_scope(Path(args.scope)) if args.scope else None
    reason = validate_receipt(
        receipt,
        scope,
        keys=keys,
        expected_workspace_id=args.workspace_id,
        trusted_key_fingerprints=set(args.trusted_key_fingerprint),
        notes=notes,
    )
    if reason is not None:
        print(reason)
        return 1
    if scope is None and receipt.get("context", {}).get("replaces_receipt") is not None:
        notes.append("incomplete_chain")
    print("profile receipt passed")
    for note in notes:
        print(f"note:{note}")
    return 0


def _load_scope(path: Path) -> dict[str, dict[str, Any]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(doc, list):
        receipts = doc
    elif "receipts" in doc:
        receipts = doc["receipts"]
    elif "valid" in doc:
        receipts = [item["receipt"] for item in doc.get("valid", [])]
        receipts.extend(item["receipt"] for item in doc.get("invalid", []))
    else:
        receipts = [doc.get("receipt", doc)]
    return {
        receipt["receipt_id"]: receipt
        for receipt in receipts
        if isinstance(receipt, dict) and isinstance(receipt.get("receipt_id"), str)
    }


if __name__ == "__main__":
    raise SystemExit(main())
