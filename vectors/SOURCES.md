# Vector Sources

Valid vector body fields are traced to FunnelOps G1 event-map serializers at:

- Repo: `projects/funnelops`
- Branch: `slice/G5`
- Commit: `9bf6f11` (`fix(allowly): align event bodies with profile`)

The profile repo adds deterministic receipt envelopes and signatures so stock base
verification can run without the FunnelOps app.

| Vector | FunnelOps source |
|---|---|
| `candidate_screen_advance` | `app/allowly/events.py::candidate_screen_body`; covered by `tests/test_allowly.py::test_candidate_screen_advance_body_snapshot` |
| `candidate_screen_knockout` | `app/allowly/events.py::candidate_screen_body`; covered by `tests/test_allowly.py::test_candidate_screen_knockout_maps_rule_id_to_condition_object` and `tests/test_g2_e2e.py::test_golden_payload_and_csv_batches_match_expected_tiers` |
| `candidate_screen_confirm` | `app/allowly/events.py::candidate_screen_body`; covered by `tests/test_allowly.py::test_candidate_screen_confirm_and_escalate_bodies` |
| `candidate_screen_escalate_criteria` | `app/allowly/events.py::candidate_screen_body`; covered by `tests/test_allowly.py::test_candidate_screen_confirm_and_escalate_bodies` |
| `candidate_screen_escalate_parse_warning` | `app/allowly/events.py::candidate_screen_body`; covered by `tests/test_allowly.py::test_candidate_screen_confirm_and_escalate_bodies` |
| `candidate_screen_escalate_accommodation` | `app/allowly/events.py::candidate_screen_body`; same serializer branch as profile escalation reasons |
| `candidate_screen_escalate_context_missing` | `app/allowly/events.py::candidate_screen_body`; same serializer branch as profile escalation reasons |
| `candidate_review_replaces_confirm` | `app/allowly/events.py::review_body`; covered by review API tests in FunnelOps |
| `adverse_action_issue` | `app/allowly/events.py::letter_body`; covered by `tests/test_g4_letters.py::test_adverse_action_send_marks_sent_and_mints_letter_receipt` |
| `audit_export` | `app/allowly/events.py::audit_body`; covered by audit export tests in FunnelOps |
| `authorization_create` | `app/allowly/client.py::publish_policy` / `app/allowly/mint.py`; covered by policy publish tests in FunnelOps |
| `authorization_revoke` | `app/allowly/client.py::publish_policy`; covered by Allowly client tests in FunnelOps |
