# Vector Sources

The vectors are self-contained deterministic fixtures: receipt bodies authored
to exercise §§4–8 of the profile, wrapped in deterministic envelopes and signed
by `resign.py` (fixed-seed Ed25519 key, `test-key-v03`). They are generated
artifacts, not captures from any production system; every identity in them —
workspaces, engines, requisitions, candidates — is fictional.

Provenance and trust:

- The spec (`spec/screening-decisions-profile.md`) is the sole normative
  source; `validators/check_profile.py` enforces it. If a vector and the spec
  disagree, the spec governs and the vector is a bug.
- Valid vectors cover every profile action/decision pairing in §4: the four
  screening tiers, each escalation reason, review replacement and override,
  a correction that replaces an earlier screen for the same candidate,
  adverse-action issuance, audit export, and the authorization lifecycle pair.
  A valid vector may carry a `notes` list naming the conditions the validator
  is expected to report without failing the receipt — `incomplete_chain`, for
  the review whose target lies outside a partial export (§8).
- Invalid vectors cover the documented failure classes: vocabulary mispairing,
  missing knockout `policy_eval`, missing review `replaces_receipt`, float in
  context, PII in context, each broken-chain condition of §8 (a second direct
  successor, a cycle, and a target naming a different candidate or a different
  authorization), a screen whose `tier`
  repeats the decision verb instead of the mapped tier (§4), a screen whose
  `context.subject.uuid` names a different candidate than its `resource` and
  one whose subject omits `payload_digest` (§5),
  a knockout attestation that is not exactly the four keys of §6 (one key short
  and one key long), a second candidate value carried elsewhere in `context`
  (§7), a candidate value inside a `knockout` container on a receipt that is
  not a knockout denial — an advancing screen and a review, neither of which
  earns the §7 exemption — and the three §6 provenance failures — a knockout
  denial with no `fields_supplied_by` map at all, one whose knockout field is
  listed only under `cv`, and one whose `customer` entry is a bare string
  instead of the list of field names §7 defines.
- Signatures: run `python3 vectors/resign.py` after editing receipt bodies.
  Deliberately non-canonicalizable vectors keep their prior signature by
  design — they fail base verification before the signature is checked.
