# BLOCKED

## R1 base verifier dependency
Question: Which stock Allowly base Python verifier should `validators/check_profile.py` call before profile checks?

Context: R1 requires "stdlib + the base Python verifier as its only dep" and base verification first. The seed repo does not include the base verifier, and no local copy of `allowly-receipt-format` is present under `/Users/yoda/Documents/FunnelOps`.

Options:
- Vendor or submodule the published base verifier when the public base repo is available.
- Keep the current minimal base precheck in the seed repo until the base verifier is supplied.

Recommendation: Keep the minimal precheck for local seed validation; replace it with the stock base verifier before publishing the public repo.

## R1 valid vectors vs FunnelOps G1 snapshots
Question: Should vectors follow the current profile spec or current FunnelOps G1 request snapshots when they disagree?

Context: R1 requires valid vectors sourced from FunnelOps G1 request snapshots, but current app event bodies drift from the profile in a few places. Examples: `candidate_screen_body` places `policy_eval` under `context`, while the profile specifies top-level `policy_eval`; `letter_body` uses resource `adverse_action`, while the profile requires `candidate:<uuid>` for `adverse_action.issue`.

Options:
- Keep vectors profile-conformant and document the implementation drift.
- Change the profile vectors to mirror current implementation snapshots, making the profile validator reject its own spec.
- Update FunnelOps event serializers to match the public profile, then regenerate vectors from those snapshots.

Recommendation: Keep vectors profile-conformant in R1 and open a follow-up to align FunnelOps serializers before claiming snapshot-sourced public vectors.
