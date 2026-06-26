# Browser Workflow Support

## Goal

Provide consistent browser-observation rules to any module that inspects page structure or UI-visible evidence.

This bundle is a support skill. It should be loaded when the target and task match the skill description in `skill.yaml`, and it should stay within the explicit scope of the current module implementation.

## Use Signals

- A runnable skill is browser-facing.
- The reviewer may need screenshots or DOM-visible confirmation later.
- Page titles, forms, redirects, or rendered scripts are part of the evidence chain.

## Inputs and Expected Artifacts

- Inputs: module_context
- Expected artifacts: page_observation_notes, screenshot_targets
- Trigger words: browser, screenshot, dom, page review
- Support modules: recon, js_audit, xss_triage, weak_password, poc_verify
- Risk level: low

## Recommended Workflow

1. Load the page and note visible title, redirect behavior, and basic layout clues.
2. Inventory forms, buttons, inputs, and script tags before drilling into one issue.
3. Preserve a screenshot target list whenever a later verifier should capture visual proof.
4. Keep browser notes scoped to what the runnable skill actually observed.

## Evidence Rules

- Reference the visible page or route where the clue appeared.
- If screenshots are recommended, describe the exact state to capture.

Also apply these structural rules:

- Keep findings compact and reproducible.
- Prefer concrete URLs, parameters, script locations, config paths, or page states over vague summaries.
- If this skill consumes upstream routing or artifact hints, preserve the producer name in logs or evidence when that scope change matters.

## Boundaries and Non-Goals

- This is support guidance, not an executable module.
- It should not replace protocol or source evidence when those are stronger.

## Reference Files

Read these files when the task needs more detail than the core workflow above:

- [Inspection Order](references/inspection-order.md)
- [Screenshot Guidance](references/screenshot-guidance.md)

## Output Contract

- Emit findings that fit the shared `Finding` schema.
- Keep module output aligned with the expected artifacts declared in `skill.yaml`.
- If the skill is support-only, use it to shape runtime context and reporting rather than to create standalone findings.
