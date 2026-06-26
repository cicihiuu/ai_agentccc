# Followup Routing

## Goal

Define how producer modules expose scope and how consumer modules inherit it without losing provenance.

This bundle is a support skill. It should be loaded when the target and task match the skill description in `skill.yaml`, and it should stay within the explicit scope of the current module implementation.

## Use Signals

- A runnable skill emits followup_context.
- A downstream skill expands scope based on producer data.
- The report needs to explain why later modules saw extra routes or artifacts.

## Inputs and Expected Artifacts

- Inputs: module_context
- Expected artifacts: followup_route_summary, consumer_scope_note
- Trigger words: followup, routing, context chain
- Support modules: backup_audit_extended, config_audit, permission_bypass, sql_scan, js_audit, xss_triage, ssrf_triage, poc_verify
- Risk level: low

## Recommended Workflow

1. Treat followup_context as producer-owned data.
2. Expose only consumer-relevant keys to downstream modules.
3. Keep a route summary in runtime state so later reporting can explain scope expansion.
4. Preserve producer names in logs or evidence whenever follow-up scope materially changed execution.

## Evidence Rules

- If follow-up data changed scope, record the producer and the consumed keys.
- Avoid merging unrelated producer payloads into one anonymous blob.

Also apply these structural rules:

- Keep findings compact and reproducible.
- Prefer concrete URLs, parameters, script locations, config paths, or page states over vague summaries.
- If this skill consumes upstream routing or artifact hints, preserve the producer name in logs or evidence when that scope change matters.

## Boundaries and Non-Goals

- Support guidance must not mutate upstream findings in place.
- It should help explain scope, not hide it.

## Reference Files

Read these files when the task needs more detail than the core workflow above:

- [Producer Consumer Contract](references/producer-consumer-contract.md)
- [Routing Audit Trail](references/routing-audit-trail.md)

## Output Contract

- Emit findings that fit the shared `Finding` schema.
- Keep module output aligned with the expected artifacts declared in `skill.yaml`.
- If the skill is support-only, use it to shape runtime context and reporting rather than to create standalone findings.
