# Screening Decisions Profile — v0.7.0 (Draft)
**A profile of the Allowly Receipt Format (wire version "4") for employment screening decisions.**

Status: **Draft.** Aligned to the published base specification at https://github.com/Allowly-AI/allowly-receipt-format (spec/receipt-format.md, wire version 4, Stable). License: profile text **CC BY 4.0**; schemas and validators **Apache 2.0** (matching the base repo). Editor: Allowly (Druim Pacific LLC). Contributions by pull request. "Allowly" is a trademark; see §11.

## 1 · Purpose & design constraint
This profile maps employment-screening decisions — automated knockouts, tier assignments, human reviews and overrides, corrections, adverse-action issuance, audit exports — onto unmodified base-format receipts. The base format's §3.1 rule is absolute: **verifiers reject unknown top-level fields**, so this profile adds none. Everything profile-specific lives in the fields the base format designates as issuer/customer-defined: the `action` and `reason` vocabularies, `resource`, `agent_id`/`user_id` semantics, and the `context` object. A profile receipt is therefore verifiable by any stock base-format verifier today; profile conformance is an additional, layered check (§9).

## 2 · Conformance
RFC 2119 keywords. A **Producer** is the party requesting receipts from an issuer (e.g., a screening system calling the issuer's `/check` and lifecycle endpoints) such that emitted receipts satisfy §§4–8. A **Profile Verifier** performs base verification first, then §9 checks. Base-format conformance is a precondition, not part of this profile.

## 3 · Policy lifecycle = authorization lifecycle
A published, employer-approved **policy version** is represented as one immutable base-format **authorization**:
- Publishing policy `{id, version}` MUST produce an `authorization.create` event receipt whose `context` carries `policy: {"id", "version", "digest"}`, where `digest` is `sha256:` over the policy document canonicalized by the **base §4 rules** (UTF-16 key sort; integers only — fractional policy values MUST be scaled integers or strings). The policy `id` MUST be 1–128 ASCII characters matching `[A-Za-z0-9][A-Za-z0-9._:-]*(/[A-Za-z0-9][A-Za-z0-9._:-]*)*`; no colon- or slash-delimited component may begin with the FunnelOps API credential prefix `fops_`. The policy `version` MUST be 5–32 ASCII characters matching `(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)`, so it is exactly numeric `x.y.z` with no leading zeros except the value `0`.
- Superseding a policy version MUST revoke the predecessor and create the successor. The receipts SHOULD carry the base convention's bidirectional lineage fields: the revocation's `context.revoked_by: "superseded"` and `context.superseded_by: <successor authorization_id>`, and the creation's `context.replaces: <predecessor authorization_id>`. Revocation and creation preserve immutable policy history; the pointers make that history easier to walk but are audit conveniences, not chain-integrity proofs.
- Every screening action receipt pins the policy in force via its top-level `authorization_id` — no profile machinery needed; this is the base format working as designed.

### 3.1 · Policy approval binding

A Producer MAY bind an immutable `policy_approval.v1` artifact to the authorization without changing the base wire format. When it does, the `authorization.create` context MUST carry `approval_schema_version`, `approval_id`, `approval_digest`, `approving_user_id`, `organization_id`, `identity_assurance`, `authentication_credential_id`, `funnelops_workspace_id`, and `operator`, in addition to the exact `policy` object. `approval_digest` MUST be `sha256:` plus 64 lowercase hexadecimal characters over the canonical approval artifact. The `approval_id`, `approving_user_id`, `organization_id`, and `authentication_credential_id` values MUST be source-tagged opaque identifiers, not names, email addresses, or credential secrets, and no colon- or slash-delimited component may begin with the FunnelOps API credential prefix `fops_`. The `funnelops_workspace_id` and matching `organization.workspace_id` values MUST each be 1-128 ASCII characters matching `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` and MUST likewise contain no such component. This shape check rejects that known credential form; it cannot prove that every other name-like string is semantically opaque, so the Producer remains responsible for supplying non-PII lookup identifiers. `identity_assurance` MUST be `authenticated_user` or `organization_asserted`; the latter supports only the claim that the authenticated organization reported the named opaque user. When approval fields are present, all are required, `organization.id` MUST equal `organization_id`, `organization.workspace_id` MUST equal `funnelops_workspace_id`, and the FunnelOps artifact's `operator` MUST be exactly `FunnelOps`.

The authorization's top-level `user_id` MUST equal `approving_user_id`. Its `agent_id` remains the screening engine. Later action receipts under that authorization therefore retain the approving principal and engine identity while `authorization_id` binds them to the approved policy.

## 4 · Action vocabulary (normative)
All screening receipts are **action receipts** (base §3.3), `decision ∈ {allow, deny, confirm, escalate}`.

**v0.3 correction (aligned to the live issuer):** `reason` belongs to the ISSUER — it is the issuer's machine code for how the decision was reached (base §3.1), not a producer-defined field. The producer's screening semantics are **context conventions**: for `candidate.screen`, `tier` MUST match the decision by the explicit mapping `allow → advance`, `deny → deny`, `confirm → confirm`, `escalate → escalate`; `detail_code` carries escalation detail (`criteria_below_confirm` · `parse_warning:*` · `accommodation_requested` · `context_field_missing`); `knockout` is defined in §6; and `review_decision` applies to `candidate.review`. The explicit mapping avoids treating `allow` and `advance` as equal strings. The verbs are routed by the issuer's per-action conditions evaluated against `context.tier`.

| action | decision | issuer reason (observed) | Producer context summary (§7 is normative) | Meaning |
|---|---|---|---|---|
| `candidate.screen` | allow | `authorization_granted_action_active` | `tier: "advance"`, criteria_passed/failed[] | Automated tier: Advance |
| `candidate.screen` | deny | `deny_condition_matched` | `tier: "deny"`, `knockout` (§6), citation | Objective knockout; `policy_eval` REQUIRED (§6) |
| `candidate.screen` | confirm | `confirm_condition_matched` · `context_field_missing` | `tier: "confirm"`, criteria_passed/failed[] | Middle tier; awaits human review |
| `candidate.screen` | escalate | `escalate_condition_matched` · `context_field_missing` | `tier: "escalate"`, `detail_code`, criteria_passed/failed[] | Routed to human judgment |
| `candidate.review` | allow \| deny | `authorization_granted_action_active` \| `deny_condition_matched` | `review_decision: "advance"\|"reject"`, optional `review_basis`, `replaces_receipt` (§8) | Human resolution of a confirm, or override |
| `adverse_action.issue` | allow | `authorization_granted_action_active` | `decision_refs[]` | Adverse-action communication generated |
| `audit.export` | allow | `authorization_granted_action_active` | `manifest_digest`, `filter` | Audit pack produced |

Human-readable text (e.g., a policy citation) goes in `context`. Producers MUST NOT reuse these action names with different semantics; additional actions use a producer prefix (§10). (Deny routing via `deny_when` is live in the issuer as of Jul 14, 2026; the deny rows above are observed behavior, not aspiration.)

## 5 · Subject, resource, and actor semantics
- `resource` MUST be `candidate:<uuid>` for `candidate.screen`, `candidate.review`, and `adverse_action.issue`; it is the canonical link between the receipt and the candidate. For `audit.export`, `resource` SHOULD be `requisition:<id>` or `null`.
- `<uuid>` is the client-scoped candidate identifier. The name denotes an opaque profile identifier and does not require RFC 4122 syntax. The base §10.6 guidance is **elevated to MUST** here: the uuid MUST be opaque (no PII), stable per candidate-requisition, and if derived from an identifier, derived only via salted keyed transformation — `sha256(email)` without salt is non-conformant.
- For `candidate.screen`, `context.subject` MUST be `{"uuid", "payload_digest"}` with optional `"file_digest"`, and `context.subject.uuid` MUST equal the `<uuid>` in `resource`. The uuid links all receipts for the candidate; `payload_digest` distinguishes input versions and is `sha256:` over the candidate field payload canonicalized by base §4 rules (therefore: integer/string/boolean/null values only — no floats, per base rule 6). Reviews and adverse-action receipts are already linked through `resource` and their receipt references, so `context.subject` is optional on those actions.
- `agent_id` identifies the acting principal per base §3.1: the screening engine identity for `candidate.screen` (e.g., `screening_engine`), the human actor's **role** for `candidate.review` (e.g., `recruiter`). `user_id` is the opaque employer-side principal on whose behalf the authorization or action runs. A Producer using §3.1 policy approval keeps the authorization's `approving_user_id` on automated action receipts; actor-specific review identity remains in PII-free review context. Neither field may contain PII (base §10.6).

## 6 · policy_eval usage
For knockout denials (`decision: deny`, `context.tier: "deny"`), `policy_eval` MUST be present in the base §3.6.1 shape and carries the ISSUER's evaluated routing condition (observed: `{"field": "tier", "op": "eq", "value": "deny"}`) — never a bare rule name; base verifiers reject a string there on shape alone. The PRODUCER's knockout condition MUST be attested as `context.knockout = {"field", "op", "value", "field_value"}` (§10.7 minimization: the compared value, never source text); the knockout rule id SHOULD be carried as `context.knockout_id`. The producer-evaluated split is deliberate: the issuer routes on `tier` so it never re-evaluates raw fields the producer already escaped (accommodation hatch); the full rule set remains recoverable via `authorization_id`. For advance receipts, Producers SHOULD emit `policy_eval: {"matched_condition": null, "field_value": null}` — the base's "evaluated, nothing fired" attestation. The fail-closed convention (base §3.6.3, `reason: "context_field_missing"` → `confirm`) applies unchanged when a policy references an absent payload field.

**Provenance gate (normative).** A knockout denial MUST derive only from customer-asserted field values — fields the Producer's customer supplied directly (application-form answers, ATS export columns, payload fields), never values machine-extracted from application materials. A knockout field that is absent, or available only by machine extraction, MUST route to `escalate` with reason `context_field_missing` — never `deny`. `context.fields_supplied_by` (§7) MUST be present on every knockout-denial receipt, and Profile Verifiers MUST check that `context.knockout.field` appears under `"customer"`; a knockout field listed only under `"cv"` is non-conformant. Requiring the provenance map makes the producer obligation verifiable from the receipt. Rationale: the only fully automated rejection path in this profile must rest on asserted facts, not extracted ones.

## 7 · Context schema per action (normative for profile conformance)
The §4 table summarizes the vocabulary; this section is the single normative source for profile context presence. `context` MUST/SHOULD carry:
- `candidate.screen`: `subject` (§5) and `requisition_id` MUST; `criteria_passed[]` and `criteria_failed[]` (criterion **ids only**, never values) MUST for allow/confirm/escalate, including empty arrays; `citation` (policy text, verbatim from the policy document) MUST for deny; `knockout_id` SHOULD for deny (§6); when an escalation is caused by a parse warning, `detail_code` MUST be `parse_warning:<code>` (there is no separate producer-owned `reason` or `parse_warning` field); `fields_supplied_by` MUST list field **names** by provenance for deny and SHOULD do so otherwise: `{"customer": [...], "cv": [...]}`.
- `candidate.review`: `replaces_receipt: <receipt_id>` MUST (§8); `requisition_id` MUST; `review_basis` SHOULD carry a PII-free reason code or criterion ids considered.
- `adverse_action.issue`: `decision_refs: [<receipt_id>…]` MUST.
- `audit.export`: `manifest_digest` MUST; `filter` (the query, PII-free) MUST.
**Operator attribution (all actions, OPTIONAL).** `context` MAY carry `organization: {"id": <source-tagged opaque organization id>, "workspace_id": <opaque Producer workspace id>}` and `operator: <name of the system operator>`, naming which customer account the Producer acted for and who operated the system. When `organization` is present, its two keys and `operator` are required; values MUST contain no PII. `organization.workspace_id` MUST be 1-128 ASCII characters matching `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`, and no colon- or slash-delimited component may begin with the FunnelOps API credential prefix `fops_`. This is the preferred minimized shape. The older `on_behalf_of: {"client": <customer-of-record legal name>, "workspace": <opaque workspace id>}` remains profile-standard but exposes a name and SHOULD NOT be used when an opaque organization identifier is sufficient. These keys need no `x_` prefix. A human-readable legal-entity mapping belongs in a controlled audit package, not routine receipts.

FunnelOps receipts using §3.1 approval MUST carry `organization` and `operator: "FunnelOps"` on `authorization.create` and every action receipt. The organization and workspace values MUST match the approval binding and MUST be derived from the authenticated workspace rather than caller input.

Minimization rule (base §10.7 extended): candidate field **values** MUST NOT appear anywhere in a receipt except as the single compared scalar at `context.knockout.field_value` on a knockout denial; that value is decision evidence, never identity or source text. `policy_eval.field_value` records the issuer-evaluated routing value (for the observed denial route, `"deny"`), not the Producer's candidate value. Elsewhere, candidate evidence is limited to opaque ids, digests, counts, criterion ids, and provenance field names. Nothing anywhere in a receipt may contain names, emails, phone numbers, or free text from application materials.

## 8 · Decision chains via `replaces_receipt`
The base format validates lineage pointers nowhere — they are "audit conveniences… the value is in making an honest issuer's intent legible" (base §3.3). This profile adopts the same philosophy at the decision level and makes the pointer **profile-mandatory**:
- A `candidate.review` receipt MUST carry `context.replaces_receipt` naming the current chain head: the `confirm` receipt it resolves, or the decided receipt it overrides. The target MUST have the same candidate `resource` and `authorization_id`.
- A **correction** (customer resubmits corrected fields under the same uuid) MUST produce a new `candidate.screen` receipt whose `context.replaces_receipt` names the current chain head for that uuid and `authorization_id`, with the new `payload_digest`. Keeping the authorization fixed makes the changed input, rather than a changed policy, the reason for a different result. History is superseded, never edited.
- Profile Verifiers MUST check: every in-scope receipt has at most one direct successor; every present `replaces_receipt` target has the same candidate `resource` and `authorization_id`; and chains are acyclic. A missing target in a partial export is reported as `incomplete_chain` and does not invalidate an otherwise conformant signed receipt. A branch, cycle, or identity mismatch is a broken chain. Verifiers report these conditions and never repair them.

## 9 · Verification & the independence note
Profile verification = (1) base §7 verification (signature over base §4 canonical bytes, caller-trusted workspace identity and signing-key fingerprint); (2) vocabulary and pairing checks per §§4–7; (3) chain checks per §8. The trusted workspace ID and fingerprints MUST come from verifier configuration, not from the receipt or key document being checked. **Format conformance is not attestation independence.** These receipts derive their evidentiary weight from the issuer being operationally independent of the screening system and its customer: an issuer that is the decider signing its own homework produces conformant receipts that prove only self-consistency. Profile Verifiers SHOULD surface the issuer identity (`workspace_id` → authenticated key ownership) and its relationship to the Producer.

## 10 · Extensions
Additional actions MUST be prefixed `x_<vendor>.` ; additional context keys MUST be prefixed `x_`. Extensions MUST NOT weaken any MUST above and MUST respect base canonicalization (no floats, I-JSON integer bounds).

## 11 · Versioning, IP, marks
Profile versions follow semver, independent of the base wire version; this profile requires only wire `"4"` (`schema_version: "4"`) — **no profile-specific top-level fields are needed to implement it today.** Profile text CC BY 4.0. Conformance claims ("implements the Screening Decisions Profile v0.x") are free for conformant implementations; use of the Allowly name beyond factual reference follows the Allowly trademark policy.

## 12 · Examples (fixture-aligned; envelope fields per base §3)
**A — knockout (fixture c008):**
```json
{
  "schema_version": "4",
  "receipt_id": "rcp_01K2SCRN00000000000000C008",
  "workspace_id": "ws_01HXACMESTAFF0000000000000",
  "issued_at": "2026-09-14T17:03:22.481Z",
  "decision": "deny",
  "reason": "deny_condition_matched",
  "user_id": "req_owner_114",
  "agent_id": "screening_engine",
  "action": "candidate.screen",
  "resource": "candidate:c008",
  "context": {
    "subject": { "uuid": "c008", "payload_digest": "sha256:6b0c…" },
    "requisition_id": "req_114",
    "tier": "deny",
    "knockout": { "field": "work_authorization", "op": "eq", "value": true, "field_value": false },
    "knockout_id": "ko_work_auth",
    "citation": "Role requires authorization to work in the United States (self-attested).",
    "fields_supplied_by": { "customer": ["work_authorization"], "cv": [] }
  },
  "authorization_id": "auth_01K2POLHOURLYOPS10000000000",
  "engine_version": "acme-ats-2026.09.1",
  "policy_eval": { "matched_condition": { "field": "tier", "op": "eq", "value": "deny" }, "field_value": "deny" },
  "alg": "Ed25519",
  "key_id": "…",
  "signature": "…"
}
```
**B — confirm and human resolution (fixture c004):** first a `candidate.screen` receipt with `decision: "confirm"`, `reason: "confirm_condition_matched"`, `context.tier: "confirm"`, `context.criteria_failed: ["cr_experience"]`; then:
```json
{
  "schema_version": "4",
  "receipt_id": "rcp_01K2REVW00000000000000C004",
  "workspace_id": "ws_01HXACMESTAFF0000000000000",
  "issued_at": "2026-09-15T09:41:02.007Z",
  "decision": "deny",
  "reason": "deny_condition_matched",
  "user_id": "rev_usr_7",
  "agent_id": "recruiter",
  "action": "candidate.review",
  "resource": "candidate:c004",
  "context": {
    "subject": { "uuid": "c004", "payload_digest": "sha256:9d41…" },
    "requisition_id": "req_114",
    "review_decision": "reject",
    "replaces_receipt": "rcp_01K2SCRN00000000000000C004",
    "review_basis": ["cr_experience"]
  },
  "authorization_id": "auth_01K2POLHOURLYOPS10000000000",
  "engine_version": "acme-ats-2026.09.1",
  "alg": "Ed25519",
  "key_id": "…",
  "signature": "…"
}
```
**C — correction chain:** the customer resubmits c004 with corrected `warehouse_years: 3` under the same uuid; the resulting `candidate.screen` receipt (`decision: "allow"`, `reason: "authorization_granted_action_active"`) carries the new `payload_digest` and `context.replaces_receipt` naming the review receipt above. The record shows the wrong value, who decided on it, the correction, and the new outcome — nothing erased.

*Where this profile and the base specification conflict, the base specification governs.*
