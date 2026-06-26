# Evidence Normalization

## Goal

Keep finding titles, locations, evidence text, and recommendations consistent across runnable skills.

This bundle is a support skill. It should be loaded when the target and task match the skill description in `skill.yaml`, and it should stay within the explicit scope of the current module implementation.

## Use Signals

- A module emitted noisy whitespace, missing locations, or weak recommendation text.
- Several modules need to land in one report without style drift.

## Inputs and Expected Artifacts

- Inputs: module_result
- Expected artifacts: normalized_findings
- Trigger words: evidence, normalize, finding style
- Support modules: recon, backup_audit_extended, config_audit, permission_bypass, sql_scan, js_audit, xss_triage, ssrf_triage, weak_password, cors_audit, jwt_audit, poc_verify
- Risk level: low

## Recommended Workflow

1. Compress noisy whitespace and keep titles concise.
2. Fill missing location values with the target when necessary.
3. Ensure evidence says what was observed rather than only naming a category.
4. Preserve module-specific meaning while enforcing a minimum quality bar.

## Evidence Rules

- The support skill should improve readability without erasing provenance.
- Recommendations should remain actionable and compact.

Also apply these structural rules:

- Keep findings compact and reproducible.
- Prefer concrete URLs, parameters, script locations, config paths, or page states over vague summaries.
- If this skill consumes upstream routing or artifact hints, preserve the producer name in logs or evidence when that scope change matters.

## Boundaries and Non-Goals

- Do not silently change severity.
- Do not replace concrete evidence with empty generic phrases.

## Reference Files

Read these files when the task needs more detail than the core workflow above:

- [Finding Style](references/finding-style.md)
- [Evidence Quality Bar](references/evidence-quality-bar.md)

## Output Contract

- Emit findings that fit the shared `Finding` schema.
- Keep module output aligned with the expected artifacts declared in `skill.yaml`.
- If the skill is support-only, use it to shape runtime context and reporting rather than to create standalone findings.
