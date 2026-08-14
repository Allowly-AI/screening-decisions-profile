# Changelog

## Unreleased
- Validator: tightened profile-only checks for `sha256:` digest prefixes, criteria and `decision_refs` list shapes, issuer deny `policy_eval`, review-decision/top-level decision agreement, policy identity shape, `full_name` PII keys, and unprefixed extension context keys (standard optional keys remain allowed). The single-receipt CLI now accepts `--scope` for §8 chain checks and reports `note:incomplete_chain` when a standalone receipt names an out-of-scope predecessor.

## v0.6.0 (2026-08-13) — Checkable decision, provenance, and chain rules
- Spec: `candidate.screen` maps decision to tier explicitly (allow→advance, deny→deny, confirm→confirm, escalate→escalate); §7 is the single normative source for per-action context presence; `context.subject` is required on screens and its uuid MUST equal the one in `resource`; `context.fields_supplied_by` is mandatory on knockout denials; the one permitted candidate value in `context` is `context.knockout.field_value`; replacements target the current chain head and MUST share its candidate `resource` and `authorization_id`. Policy-supersession lineage pointers drop from MUST to SHOULD — revoking the predecessor and creating the successor is what preserves history.
- Validator: knockout denials now fail without the provenance map (`missing_fields_supplied_by`), and a `fields_supplied_by` that is not `{"customer": [...], "cv": [...]}` with list values is `invalid_fields_supplied_by` — the shape carries the gate, and a bare string under `customer` would make the gate a substring test; the knockout attestation must be exactly `{field, op, value, field_value}` (`invalid_knockout_shape`); a `field_value` anywhere else in `context` is `candidate_value_outside_knockout`; a screen whose subject and resource name different candidates is `subject_resource_mismatch`, and one whose `context.subject` is not `{uuid, payload_digest}` (optionally `file_digest`) is `invalid_subject_shape`. The `context.knockout` exemption applies only where §7 grants it — on a knockout denial — so on any other receipt a `knockout` container is checked like any other part of `context`.
- Validator: the single `broken_replaces_chain` code splits into `chain_branch`, `chain_cycle`, `chain_resource_mismatch`, and `chain_authorization_mismatch`, plus a non-failing `incomplete_chain` note for an ancestor that lies outside a partial export.
- Vectors: 14 valid (adding a correction screen and the partial-export review) and 20 invalid (adding one per new failure class), all re-signed with the deterministic signer. Valid vectors may declare expected non-failing notes. The parse-warning escalation carries its detail only in `detail_code`, matching §7.
- No wire change: still base wire version `"4"`, unchanged canonicalization and signature bytes.

## v0.5.1 (2026-08-11) — Editorial: neutral example identities
- Corrected the editor of record to Allowly (Druim Pacific LLC) in the spec masthead and GOVERNANCE.
- Replaced the sample producer identity in the §12 examples (`workspace_id`, `engine_version`) and the vectors' `engine_version` with the fictional Acme Staffing (`acme-ats`); vectors re-signed with the deterministic signer. All identities in examples and vectors are fictional and name no real implementation.
- Rewrote `vectors/SOURCES.md`: vectors are self-contained deterministic fixtures whose sole normative source is the spec, enforced by the validator.
- No normative changes; wire version unchanged (`"4"`).

## v0.5.0 (2026-08-01) — Base wire version 4
- Realigned the profile, verifier pin, examples, and all 19 deterministic vectors to receipt wire version 4.
- Regenerated every canonicalizable signature with the profile's deterministic signer and added the signing-key fingerprint to the bundled key document.
- Required caller-trusted workspace and signing-key fingerprints for single-receipt CLI validation; values copied from the receipt bundle are not trust anchors.

## v0.4.1 (2026-07-23) — §12 examples aligned to v0.3 reason vocabulary
- §12 examples predated the v0.3 issuer-owned `reason` correction and were rejected by the repo's own validator. Example A: `knockout_failed` → `deny_condition_matched`, `policy_eval` now the issuer's tier-routing condition (§6), context gains `tier`, `knockout` (4-key shape), `fields_supplied_by`. Example B: `review_experience_below_min` → `deny_condition_matched`, context gains `review_decision: "reject"`; prose `confirm_threshold` → `confirm_condition_matched`, `criteria_met` → `authorization_granted_action_active`. Both examples now pass `_profile_check`.

## v0.4.0 (2026-07-23) — Base wire version 3
- Realigned to the base specification at wire version 3 (`schema_version: "3"`): the wire field renamed from `version`, and `alg`/`key_id` moved from the `signature` object to top level with `signature` now a flat base64url string (both are inside the signed payload; only `signature` itself is excluded from canonicalization). Timestamps are UTC millisecond precision.
- Spec masthead, §11, §12 examples, and README updated from wire `"1.0"` / base 1.0.0 to wire `"3"`; fixed stale masthead version (said v0.2 while changelog was at v0.3.3).
- All 19 vectors migrated to the wire-3 envelope and re-signed (`vectors/resign.py` updated for the flat signature and ms-precision key `active_from`); `validators/check_profile.py` unchanged and green against verifier 3.0.0 (`--vectors` passes 12 valid / 7 invalid as expected).
- `requirements.txt` verifier pin moved from the base v1.0.5 tag to v3.0.0.

## v0.3.3 (2026-07-15) — Operator attribution
- §7: `on_behalf_of {client, workspace}` + `operator` adopted as profile-standard OPTIONAL context keys on all actions (who the decision was made for / who operated the system). No `x_` prefix; minimization rule unaffected. Producer support live-verified in a signed staging receipt.
- (Bookkeeping: v0.3.2 was the deny_when reason-vocabulary alignment — entry was missing here.)

## 0.3.0 (2026-07-15) — Vectors + validator
- Added profile vectors covering valid screening, review, adverse-action, audit-export, and authorization lifecycle receipts.
- Added invalid vectors for vocabulary mismatches, required context omissions, floats, PII, broken replacement chains, and provenance-gate violations.
- Added `validators/check_profile.py`, a thin profile validator that performs a base precheck before profile vocabulary, context, privacy, provenance, and chain checks.
- Added CI workflow to run the validator over all bundled vectors.

## 0.2.0 (2026-07-15) — Aligned to base 1.0.0 Stable
- Rewritten as a strict context-profile: **zero new top-level fields** (base §3.1 unknown-field rule); verifies with stock base verifiers on wire `"1.0"`.
- Policy lifecycle remapped to base authorization lifecycle: publish = `authorization.create` with `context.policy {id, version, digest}`; supersession via the base lineage convention (`replaces` / `revoked_by: "superseded"` / `superseded_by`). `authorization_id` pins the policy in force on every screening receipt.
- Vocabulary collapsed to two profile actions — `candidate.screen` and `candidate.review` — plus `adverse_action.issue` and `audit.export`; outcomes distinguished by `decision` + `reason` codes and `policy_eval`.
- Decision chains via `context.replaces_receipt` (profile-MUST; base philosophy: legibility, not chain integrity).
- Privacy: base §10.6 identifier guidance elevated to MUST (opaque uuid; salted derivation only); §10.7 minimization extended (criterion ids only in context; the sole snapshotted value is `policy_eval.field_value`).
- Digests (`payload_digest`, policy `digest`) computed over base-§4 canonical form; payload values restricted to integers/strings/booleans/null.
- Licenses matched to base repo: CC BY 4.0 (spec) / Apache 2.0 (code).

## 0.1.0 (2026-07-15) — Initial draft
- First public draft; superseded same-day by 0.2.0 after alignment against the published base specification.

## v0.3.1
- §4 issuer-vocabulary alignment; deterministic vector re-signer.
