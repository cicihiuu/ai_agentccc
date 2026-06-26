from __future__ import annotations

import base64
import json
import re

from ai_security_agent.schemas import Finding, ModuleResult

from .common import is_local_or_lab_target, now_iso, safe_fetch_text, target_scope_label


JWT_RE = re.compile(r"(eyJ[a-zA-Z0-9_-]+)\.(eyJ[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]*)")
SENSITIVE_KEYS = {"password", "pwd", "secret", "token", "ssn", "creditcard", "private_key", "apikey", "api_key"}


def run(target: str, context: dict | None = None) -> ModuleResult:
    started = now_iso()
    if not is_local_or_lab_target(target):
        return ModuleResult(
            module="jwt_audit",
            target=target,
            status="skipped",
            findings=[],
            logs=["Target is outside the local/course-lab allowlist; JWT audit skipped."],
            started_at=started,
            finished_at=now_iso(),
            error="only localhost or course lab targets are allowed",
        )

    logs = [f"Target scope: {target_scope_label(target)}"]
    response = safe_fetch_text(target, timeout_seconds=1.5, max_bytes=120_000)
    if not response.ok:
        return ModuleResult(
            module="jwt_audit",
            target=target,
            status="failed",
            findings=[],
            logs=logs + [f"JWT page fetch failed: {response.error or response.status_code}"],
            started_at=started,
            finished_at=now_iso(),
            error=response.error or f"HTTP {response.status_code}",
        )

    findings: list[Finding] = []
    seen_tokens: set[str] = set()
    for header_b64, payload_b64, signature in JWT_RE.findall(response.text):
        token = f"{header_b64}.{payload_b64}.{signature}"
        if token in seen_tokens:
            continue
        seen_tokens.add(token)
        token_findings, token_logs = _analyze_token(target, token, header_b64, payload_b64, signature)
        findings.extend(token_findings)
        logs.extend(token_logs)

    if not seen_tokens:
        logs.append("No JWT-like token was found in the fetched response body.")
    elif not findings:
        logs.append(f"Parsed {len(seen_tokens)} JWT-like token(s) with no risky header or payload issue confirmed.")

    return ModuleResult(
        module="jwt_audit",
        target=target,
        status="ok",
        findings=findings[:8],
        logs=logs,
        followup_context={
            "producer": "jwt_audit",
            "consumers": {
                "poc_verify": {
                    "high_risk_findings": [item.to_dict() for item in findings if item.verification_status == "confirmed"],
                    "jwt_findings": [item.to_dict() for item in findings],
                }
            },
            "high_risk_findings": [item.to_dict() for item in findings if item.verification_status == "confirmed"],
        },
        started_at=started,
        finished_at=now_iso(),
    )


def _analyze_token(
    target: str,
    token: str,
    header_b64: str,
    payload_b64: str,
    signature: str,
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    logs = [f"Analyzing JWT-like token: {token[:24]}..."]
    try:
        header = json.loads(_decode_b64url_json(header_b64))
        payload = json.loads(_decode_b64url_json(payload_b64))
    except (ValueError, json.JSONDecodeError) as exc:
        logs.append(f"JWT decode failed: {exc}")
        return findings, logs

    alg = str(header.get("alg", "")).strip().lower()
    if alg == "none":
        context = _jwt_context(target, header, payload, issue="alg=none", signature_present=bool(signature))
        findings.append(
            Finding(
                title="JWT none-algorithm token accepted in response",
                severity="critical",
                location=target,
                evidence=_jwt_evidence(token, header, payload, "alg=none"),
                kind="vulnerability",
                verification_status="confirmed",
                verified=True,
                recommendation="Reject alg=none and enforce a strict server-side JWT algorithm allowlist.",
                metadata={"jwt_context": context, "verification_source": "jwt_audit"},
            )
        )
    if not signature:
        context = _jwt_context(target, header, payload, issue="empty_signature", signature_present=False)
        findings.append(
            Finding(
                title="JWT with empty signature exposed in response",
                severity="high" if alg != "none" else "critical",
                location=target,
                evidence=_jwt_evidence(token, header, payload, "signature segment is empty"),
                kind="vulnerability",
                verification_status="confirmed",
                verified=True,
                recommendation="Reject unsigned JWTs and verify the expected signature algorithm on every token.",
                metadata={"jwt_context": context, "verification_source": "jwt_audit"},
            )
        )

    sensitive_hits = sorted(_find_sensitive_keys(payload))
    if sensitive_hits:
        context = _jwt_context(target, header, payload, issue=f"sensitive_claims:{','.join(sensitive_hits[:6])}", signature_present=bool(signature))
        findings.append(
            Finding(
                title="Sensitive plaintext data in JWT payload",
                severity="high",
                location=target,
                evidence=_jwt_evidence(token, header, payload, f"sensitive keys: {', '.join(sensitive_hits)}"),
                kind="vulnerability",
                verification_status="confirmed",
                verified=True,
                recommendation="Do not place secrets or sensitive plaintext data in JWT payloads; move them server-side.",
                metadata={"jwt_context": context, "verification_source": "jwt_audit"},
            )
        )
    return findings, logs


def _decode_b64url_json(data: str) -> str:
    padding = "=" * ((4 - len(data) % 4) % 4)
    decoded = base64.urlsafe_b64decode(data + padding)
    return decoded.decode("utf-8", errors="replace")


def _find_sensitive_keys(value: object, prefix: str = "") -> set[str]:
    hits: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            label = f"{prefix}.{key}" if prefix else str(key)
            lowered = str(key).lower()
            if lowered in SENSITIVE_KEYS:
                hits.add(label)
            hits.update(_find_sensitive_keys(nested, label))
        return hits
    if isinstance(value, list):
        for index, nested in enumerate(value):
            hits.update(_find_sensitive_keys(nested, f"{prefix}[{index}]"))
        return hits
    if prefix and isinstance(value, str):
        lowered = value.lower()
        if any(marker in lowered for marker in ("secret", "password", "apikey", "api_key", "private")):
            hits.add(prefix)
    return hits


def _jwt_evidence(token: str, header: dict[str, object], payload: dict[str, object], issue: str) -> str:
    return "\n".join(
        [
            f"Issue: {issue}",
            f"Token prefix: {token[:48]}...",
            f"Header: {json.dumps(header, ensure_ascii=True, sort_keys=True)}",
            f"Payload: {json.dumps(payload, ensure_ascii=True, sort_keys=True)}",
        ]
    )


def _jwt_context(
    target: str,
    header: dict[str, object],
    payload: dict[str, object],
    *,
    issue: str,
    signature_present: bool,
) -> dict[str, object]:
    return {
        "url": target,
        "issue": issue,
        "alg": str(header.get("alg", "")).strip(),
        "typ": str(header.get("typ", "")).strip(),
        "signature_present": bool(signature_present),
        "payload_keys": sorted(str(key) for key in payload.keys())[:16] if isinstance(payload, dict) else [],
    }
