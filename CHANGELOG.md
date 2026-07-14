# Changelog

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
