# Screening Decisions Profile

A **profile** of the [Allowly Receipt Format](https://github.com/Allowly-AI/allowly-receipt-format) (v1.0.0, wire version `"1.0"`) for employment screening decisions: automated knockouts, tier assignments, human reviews and overrides, corrections, adverse-action issuance, and audit exports.

**Status: Draft (v0.2).** The profile adds **no top-level fields** — everything lives in the base format's designated surfaces (`action`/`reason` vocabularies, `resource`, `context`). Profile receipts therefore verify with the stock base-format verifiers today, unchanged.

- Spec text: [`spec/screening-decisions-profile.md`](./spec/screening-decisions-profile.md) (CC BY 4.0)
- Code (future validators, vectors generator): Apache 2.0
- Where this profile and the base specification conflict, the base specification governs.

## Relationship to the base repo
Three layers, and this repository defines no receipt structure at all:
1. **Base format** ([allowly-receipt-format](https://github.com/Allowly-AI/allowly-receipt-format)) — what a receipt *is*: envelope, canonicalization, signature, verification. It leaves `action`, `reason`, `resource`, and `context` customer-defined.
2. **This profile** — a *dialect*: it assigns domain meaning to those customer-defined fields for employment screening. Profile receipts remain ordinary base-format receipts and verify with stock base verifiers.
3. **Implementations** (e.g., FunnelOps) — Allowly customers that speak the dialect when requesting receipts. The issuer signs; the profile tells implementers what to say; the base format defines how it's sealed.

Why public: a third party holding one receipt — an auditor, a regulator, opposing counsel — verifies the signature with layer 1 and interprets the fields with layer 2, **without the implementer's cooperation**. A private vocabulary would defeat the purpose of a signed record.

Kept deliberately separate from the base repo: the base format is Stable and changes rarely; this profile iterates at draft speed. Nothing here requires or requests base-format changes.

## Roadmap to v1.0
1. `vectors/` — profile test vectors (valid + invalid receipts per §§4–8), generated against the base test-vector conventions.
2. `validators/` — a thin profile-check layered on the base Python verifier: run base verification first, then §9 profile checks. Single file, CLI: exit 0/1.
3. Reference implementation in production (FunnelOps) + one external implementer → Stable.

## Validator
Requires Python 3.10+ for the stock base verifier.

Run the profile validator against the bundled vectors:

```sh
python3 -m pip install -r requirements.txt
python3 validators/check_profile.py vectors/vectors.json --vectors
```

Run it against one receipt JSON:

```sh
python3 validators/check_profile.py receipt.json
```

The validator performs a minimal base-format precheck first, then the profile checks for vocabulary pairings, required context by action, PII-free context, provenance gating, and `replaces_receipt` chains.

## Reporting issues
Spec ambiguities and vector disagreements: GitHub issues, following the base repo's conventions. Security: security@allowly.ai.
