# Result Reporting

## Goal

Keep final report structure aligned with skill coverage, expected artifacts, and module-level provenance.

This bundle is a support skill. It should be loaded when the target and task match the skill description in `skill.yaml`, and it should stay within the explicit scope of the current module implementation.

## Use Signals

- Multiple runnable skills feed one final report.
- The operator needs a skill coverage table, stable sections, and traceable findings.

## Inputs and Expected Artifacts

- Inputs: scan_run
- Expected artifacts: coverage_table, report_sections, verification_ready_summary
- Trigger words: report, coverage, result aggregation
- Support modules: recon, backup_audit_extended, config_audit, permission_bypass, sql_scan, js_audit, xss_triage, ssrf_triage, weak_password, cors_audit, jwt_audit, poc_verify
- Risk level: low

## Recommended Workflow

1. Render summary sections first, then preserve per-module findings and logs.
2. Show how runnable skills map to modules and which support skills were attached.
3. Use expected_artifacts to explain what each skill was supposed to contribute.
4. Keep final counts traceable back to concrete module output.

## Evidence Rules

- Coverage tables should be derived from runtime state, not handwritten summaries.
- Do not claim complete coverage when a module did not run or returned no evidence.

Also apply these structural rules:

- Keep findings compact and reproducible.
- Prefer concrete URLs, parameters, script locations, config paths, or page states over vague summaries.
- If this skill consumes upstream routing or artifact hints, preserve the producer name in logs or evidence when that scope change matters.

## Boundaries and Non-Goals

- Reporting should not invent findings.
- It should summarize, not overwrite, module provenance.

## Reference Files

Read these files when the task needs more detail than the core workflow above:

- [Coverage Rules](references/coverage-rules.md)
- [Aggregation Rules](references/aggregation-rules.md)

## Output Contract

- Emit findings that fit the shared `Finding` schema.
- Keep module output aligned with the expected artifacts declared in `skill.yaml`.
- If the skill is support-only, use it to shape runtime context and reporting rather than to create standalone findings.
