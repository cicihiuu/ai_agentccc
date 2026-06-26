# State Bootstrap

## Goal

Build reusable request state before vulnerability modules run.

This skill handles common stateful web behavior without naming a specific lab: login forms, hidden anti-CSRF fields, cookies, authenticated navigation, and post-login state preparation.

## Workflow

1. Fetch the target entry page.
2. Detect password-bearing login forms and login links.
3. Preserve hidden fields, including CSRF-style tokens.
4. Try only configured credential candidates from the active Profile.
5. If login succeeds, visit configured state/setup pages and submit matched state forms while preserving hidden fields.
6. Collect cookies and authenticated same-origin links.
7. Emit `request_headers`, `authenticated_urls`, and `state_actions` for downstream modules.

## Boundaries

- Do not brute force credentials.
- Do not dump or expose passwords.
- If no login form is found, skip cleanly and let stateless scans continue.
- If no state/setup form is found, continue with the authenticated session unchanged.
- Treat authentication state as context, not as a standalone vulnerability.
