# Screening Decisions Profile

A **profile** of the [Allowly Receipt Format](https://github.com/Allowly-AI/allowly-receipt-format) (wire version `"4"`) for employment screening decisions: automated knockouts, tier assignments, human reviews and overrides, corrections, adverse-action issuance, and audit exports.

**Status: Draft (v0.6.0).** The profile adds **no top-level fields** — everything lives in the base format's designated surfaces (`action`/`reason` vocabularies, `resource`, `context`). Profile receipts therefore verify with the stock base-format verifiers today, unchanged.

- Spec text: [`spec/screening-decisions-profile.md`](./spec/screening-decisions-profile.md) (CC BY 4.0)
- Code (future validators, vectors generator): Apache 2.0
- Where this profile and the base specification conflict, the base specification governs.

## Relationship to the base repo
Three layers, and this repository defines no receipt structure at all:
1. **Base format** ([allowly-receipt-format](https://github.com/Allowly-AI/allowly-receipt-format)) — what a receipt *is*: envelope, canonicalization, signature, verification. It leaves `action`, `reason`, `resource`, and `context` customer-defined.
2. **This profile** — a *dialect*: it assigns domain meaning to those customer-defined fields for employment screening. Profile receipts remain ordinary base-format receipts and verify with stock base verifiers.
3. **Implementations** (e.g., an ATS connector or a screening system) — Allowly customers that speak the dialect when requesting receipts. The issuer signs; the profile tells implementers what to say; the base format defines how it's sealed.

Why public: a third party holding one receipt — an auditor, a regulator, opposing counsel — verifies the signature with layer 1 and interprets the fields with layer 2, **without the implementer's cooperation**. A private vocabulary would defeat the purpose of a signed record.

Kept deliberately separate from the base repo: the base format is Stable and changes rarely; this profile iterates at draft speed. Nothing here requires or requests base-format changes.

## Roadmap to v1.0
1. `vectors/` — profile test vectors (valid + invalid receipts per §§4–8), generated against the base test-vector conventions.
2. `validators/` — a thin profile-check layered on the base Python verifier: run base verification first, then §9 profile checks. Single file, CLI: exit 0/1.
3. A reference implementation in production + one external implementer → Stable.

## Validator

### Python validator
Requires Python 3.10+ for the stock base verifier.

Run the profile validator against the bundled vectors:

```sh
python3 -m pip install -r requirements.txt
python3 validators/check_profile.py vectors/vectors.json --vectors
```

Run it against one receipt JSON:

```sh
python3 validators/check_profile.py receipt.json \
  --keys keys.json \
  --workspace-id "$ALLOWLY_WORKSPACE_ID" \
  --trusted-key-fingerprint "$ALLOWLY_TRUSTED_KEY_FINGERPRINT" \
  --scope audit-export.json
```

The workspace ID and key fingerprint must come from caller-trusted
configuration, not from the receipt or key document being checked. Repeat the
fingerprint flag for every trusted rotation key that may have signed a receipt.
`--scope` is optional, but chain checks need it; validating a standalone
receipt with `context.replaces_receipt` reports `note:incomplete_chain`.

### JavaScript validator

`validators/check_profile.mjs` is the same two layers in a single dependency-free
ES module that runs unmodified in a modern browser and in Node 20+. It uses
WebCrypto (`crypto.subtle`) for Ed25519, so it needs a runtime that offers that
curve.

```js
import { verifyReceipt } from "./validators/check_profile.mjs";

const { base, profile } = await verifyReceipt(receipt, {
  keys,                       // the workspace key document
  scope,                      // optional: other receipts, for §8 chain checks
  workspaceId,                // caller-trusted workspace ID
  trustedKeyFingerprints,     // caller-trusted sha256: fingerprints
});
// base.ok / profile.ok, plus profile.notes for non-failing conditions
```

In Node, read the same files the Python CLI takes:

```sh
node --input-type=module -e '
  import { readFileSync } from "node:fs";
  import { verifyReceipt } from "./validators/check_profile.mjs";
  const doc = JSON.parse(readFileSync("receipt.json", "utf-8"));
  const keys = JSON.parse(readFileSync("keys.json", "utf-8"));
  console.log(await verifyReceipt(doc.receipt ?? doc, {
    keys,
    workspaceId: process.env.ALLOWLY_WORKSPACE_ID,
    trustedKeyFingerprints: [process.env.ALLOWLY_TRUSTED_KEY_FINGERPRINT],
  }));
'
```

In a browser, import the module and pass the key document your application
already trusts. The trust rules are unchanged: the workspace ID and the key
fingerprints come from caller-trusted configuration, never from the receipt or
from a key document that travelled with it. Omitting `workspaceId` or
`trustedKeyFingerprints` falls back to the supplied key document, which is a
trust anchor only because the caller chose to supply it.

Error codes are the same strings the Python validator returns, and each layer
reports the first failing check. `validators/parity.test.mjs` enforces that:
it runs every bundled vector through both implementations and fails on any
difference in classification, error code, or notes.

```sh
node validators/parity.test.mjs
```

### Checks

Both validators perform a minimal base-format precheck first, then the profile checks for vocabulary pairings, required context by action, PII-free context, provenance gating, and `replaces_receipt` chains. Chain conditions are reported one at a time and distinctly: a branch, a cycle, or a target naming a different candidate or authorization fails the receipt, while an ancestor missing from a partial export is reported as `incomplete_chain` and leaves an otherwise conformant receipt valid.

## Reporting issues
Spec ambiguities and vector disagreements: GitHub issues, following the base repo's conventions. Security: security@allowly.ai.
