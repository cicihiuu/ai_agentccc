# JWT Audit

## Goal

Review JWT-like material for algorithm, claim, and disclosure risks that matter operationally.

This bundle is a runnable skill. It should be loaded when the target and task match the skill description in `skill.yaml`, and it should stay within the explicit scope of the current module implementation.

## Use Signals

- API responses or front-end assets contain bearer tokens or JWT-like strings.
- The operator wants to know whether none-alg, weak claims, or sensitive payload data are present.
- A quick decode can improve triage without mutating state.

## Inputs and Expected Artifacts

- Inputs: target_url
- Expected artifacts: jwt_findings, token_payload_note, crypto_risk_note
- Trigger words: jwt, token, bearer, alg, claims
- Support modules: none
- Risk level: medium

## Recommended Workflow

1. Locate JWT-like strings in responses.
2. Decode header and payload when possible, then inspect algorithm, claims, and sensitive content patterns.
3. Emit separate findings for signature risk, claim risk, and disclosure risk when they are materially different.
4. Avoid leaking full token bodies in logs or evidence.

## Evidence Rules

- Identify whether the issue is in the header, payload, or transport context.
- Use concise decoded clues rather than the full token.
- Keep any sensitive value excerpts minimal.

Also apply these structural rules:

- Keep findings compact and reproducible.
- Prefer concrete URLs, parameters, script locations, config paths, or page states over vague summaries.
- If this skill consumes upstream routing or artifact hints, preserve the producer name in logs or evidence when that scope change matters.

## Boundaries and Non-Goals

- This skill does not forge or replay tokens.
- It should not overstate demo tokens as production compromise without context.
- It focuses on review-quality evidence rather than authentication bypass.

## Reference Files

Read these files when the task needs more detail than the core workflow above:

- [Jwt Risk Patterns](references/jwt-risk-patterns.md)
- [Token Redaction Rules](references/token-redaction-rules.md)

## Output Contract

- Emit findings that fit the shared `Finding` schema.
- Keep module output aligned with the expected artifacts declared in `skill.yaml`.
- If the skill is support-only, use it to shape runtime context and reporting rather than to create standalone findings.
