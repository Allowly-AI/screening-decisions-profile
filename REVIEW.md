# REVIEW - slice R1 (screening profile vectors + validator)

Builder: Codex. Local mode: branch `slice/R1`; no remote configured. This repo was initialized from `screening-profile-repo-seed/` with `main` as the seed baseline.

## Requirements Covered
- R1.1 valid vectors: screening outcomes, review replacement, adverse-action issuance, audit export, and authorization lifecycle receipts.
- R1.2 invalid vectors: vocabulary mismatch, missing knockout `policy_eval`, missing review `replaces_receipt`, float context value, PII context key/value, broken replacement chain, and provenance-gate violation.
- R1.3 `validators/check_profile.py`: stock base verifier first, then profile vocabulary, context, PII, provenance, and chain checks; CLI supports single receipt or `--vectors`.
- R1.4 GitHub Action validates bundled vectors; changelog bumped to v0.3.

## Files Touched
- `vectors/vectors.json`
- `vectors/SOURCES.md`
- `validators/check_profile.py`
- `.github/workflows/vectors.yml`
- `requirements.txt`
- `README.md`
- `CHANGELOG.md`
- `BLOCKED.md`

## Commits
Run `git log --oneline main..slice/R1` for the branch history.

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
- None.
