# Frontend JavaScript Audit

## Goal

Review scripts for exposed routes, hard-coded secrets, dangerous sinks, and browser-side risk signals.

This bundle is a runnable skill. It should be loaded when the target and task match the skill description in `skill.yaml`, and it should stay within the explicit scope of the current module implementation.

## Use Signals

- The page serves inline or external JavaScript.
- Backup artifacts exposed front-end bundles or API route hints.
- The operator wants front-end evidence that can inform XSS or auth review.

## Inputs and Expected Artifacts

- Inputs: target_url, followup_context
- Expected artifacts: script_inventory, secret_candidates, api_path_hints, dangerous_sink_candidates
- Trigger words: javascript, frontend, dom, script, bundle
- Support modules: none
- Risk level: low

## Recommended Workflow

1. Fetch the landing page and enumerate external plus inline scripts.
2. Inspect script content for secret-like patterns, dangerous sinks, and hard-coded API paths.
3. Treat sink matches as review signals unless a source-to-sink chain is also clear.
4. Emit script-local findings with stable locations such as the script URL or inline block index.

## Evidence Rules

- Use the script URL or inline script tag index as location.
- Preserve the matched sink, path, or credential-style token category.
- Keep excerpts short and factual.

Also apply these structural rules:

- Keep findings compact and reproducible.
- Prefer concrete URLs, parameters, script locations, config paths, or page states over vague summaries.
- If this skill consumes upstream routing or artifact hints, preserve the producer name in logs or evidence when that scope change matters.

## Boundaries and Non-Goals

- Do not merge all front-end risk into XSS.
- Do not claim stored or reflected behavior unless the source path is known.
- This skill should leave exploit replay to later stages.

## Reference Files

Read these files when the task needs more detail than the core workflow above:

- [Source Sink Overview](references/source-sink-overview.md)
- [Frontend Evidence Rules](references/frontend-evidence-rules.md)

## Output Contract

- Emit findings that fit the shared `Finding` schema.
- Keep module output aligned with the expected artifacts declared in `skill.yaml`.
- If the skill is support-only, use it to shape runtime context and reporting rather than to create standalone findings.
