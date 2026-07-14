# BLOCKED

## R1 valid vectors vs FunnelOps G1 snapshots
Question: What artifact proves these valid vectors were sourced from FunnelOps G1 request snapshots?

Context: R1 requires valid vectors sourced from FunnelOps G1 request snapshots. FunnelOps serializers now align with the public profile (`policy_eval` top-level; `adverse_action.issue` uses `candidate:<uuid>`), but this seed repo still lacks a checked-in export or regeneration artifact proving the signed vector bodies came from a named FunnelOps snapshot run.

Options:
- Keep the current signed, profile-conformant vectors and document the missing provenance artifact.
- Add a small FunnelOps snapshot export/regeneration step and replace the valid vector bodies from that output.

Recommendation: Keep the current vectors for R1 validation; add the snapshot export/regeneration artifact before claiming snapshot-sourced public vectors.
