# REVIEW - slice R1 (screening profile vectors + validator)

Builder: Codex. Local mode: branch `slice/R1`; no remote configured. This repo was initialized from `screening-profile-repo-seed/` with `main` as the seed baseline.

## Requirements Covered
- R1.1 valid vectors: screening outcomes, review replacement, adverse-action issuance, audit export, and authorization lifecycle receipts.
- R1.2 invalid vectors: vocabulary mismatch, missing knockout `policy_eval`, missing review `replaces_receipt`, float context value, PII context key/value, broken replacement chain, and provenance-gate violation.
- R1.3 `validators/check_profile.py`: stock base verifier first, then profile vocabulary, context, PII, provenance, and chain checks; CLI supports single receipt or `--vectors`.
- R1.4 GitHub Action validates bundled vectors; changelog bumped to v0.3.

## Files Touched
- `vectors/vectors.json`
- `validators/check_profile.py`
- `.github/workflows/vectors.yml`
- `requirements.txt`
- `README.md`
- `CHANGELOG.md`
- `BLOCKED.md`

## Commits
- `test(vectors): R1.1 valid profile vectors`
- `test(vectors): R1.2 invalid profile vectors`
- `feat(validator): R1.3 profile checks`
- `ci: R1.4 validate profile vectors`
- `docs: R1 review script`
- `docs: R1 blockers`
- `docs: clarify R1 base verifier blocker`
- `fix(validator): use base verifier for R1 vectors`

## Verify
```sh
# with Python 3.10+; CI uses Python 3.12
python3 -m pip install -r requirements.txt
python3 validators/check_profile.py vectors/vectors.json --vectors
python3 -m json.tool vectors/vectors.json >/tmp/r1_vectors_pretty.json
```

Observed:
- Python 3.12 Docker dependency install -> clean.
- Validator -> `profile vectors passed`.
- JSON parse -> clean.

## Demo
```sh
python3 validators/check_profile.py vectors/vectors.json --vectors
```

Observed:
```text
profile vectors passed
```

## Cuts
- None hidden. See `BLOCKED.md`.

## New Dependencies
- `allowly-receipt-format` from `Allowly-AI/allowly-receipt-format` verifier package.

## BLOCKED
- R1 valid vectors vs FunnelOps G1 snapshots: current app event snapshots drift from the profile, so vectors remain profile-conformant rather than snapshot-sourced.
