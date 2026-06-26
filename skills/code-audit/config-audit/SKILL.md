# Configuration Exposure Audit

## Goal

Review recovered configuration entrypoints for secret exposure, debug behavior, and risky deployment defaults.

This bundle is a runnable skill. It should be loaded when the target and task match the skill description in `skill.yaml`, and it should stay within the explicit scope of the current module implementation.

## Use Signals

- Backup or source artifacts expose .env, settings, bootstrap, or include paths.
- Framework names or DB hosts were recovered upstream.
- The operator wants concrete config risk rather than broad source review.

## Inputs and Expected Artifacts

- Inputs: followup_context
- Expected artifacts: config_risk_findings, secret_path_hints, framework_entrypoints
- Trigger words: config, env, settings, debug, secret
- Support modules: none
- Risk level: low

## Recommended Workflow

1. Consume followup_context first and prefer config-specific paths over blind guesses.
2. Look for secret-bearing files, debug toggles, risky file handling settings, and deployment defaults that widen the attack surface.
3. Separate confirmed exposure from simple configuration presence.
4. Emit findings only when the path, marker, or setting meaning is understandable from the recovered context.

## Evidence Rules

- Record the exact config path or environment marker.
- State why the observed marker matters operationally.
- If a clue came from backup follow-up data, keep that provenance visible.

Also apply these structural rules:

- Keep findings compact and reproducible.
- Prefer concrete URLs, parameters, script locations, config paths, or page states over vague summaries.
- If this skill consumes upstream routing or artifact hints, preserve the producer name in logs or evidence when that scope change matters.

## Boundaries and Non-Goals

- Do not rotate, change, or validate secrets during this step.
- Do not label every config file as a vulnerability.
- Prefer explicit risk descriptions over generic hardening advice.

## Reference Files

Read these files when the task needs more detail than the core workflow above:

- [Framework Config Patterns](references/framework-config-patterns.md)
- [Secret And Debug Rules](references/secret-and-debug-rules.md)

## Output Contract

- Emit findings that fit the shared `Finding` schema.
- Keep module output aligned with the expected artifacts declared in `skill.yaml`.
- If the skill is support-only, use it to shape runtime context and reporting rather than to create standalone findings.
