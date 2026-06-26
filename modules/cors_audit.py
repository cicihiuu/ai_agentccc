from __future__ import annotations

from urllib.request import Request, urlopen

from ai_security_agent.schemas import Finding, ModuleResult

from .common import is_local_or_lab_target, now_iso, target_scope_label


MALICIOUS_ORIGIN = "https://evil-origin.invalid"


def run(target: str, context: dict | None = None) -> ModuleResult:
    started = now_iso()
    if not is_local_or_lab_target(target):
        return ModuleResult(
            module="cors_audit",
            target=target,
            status="skipped",
            findings=[],
            logs=["Target is outside the local/course-lab allowlist; CORS audit skipped."],
            started_at=started,
            finished_at=now_iso(),
            error="only localhost or course lab targets are allowed",
        )

    logs = [f"Target scope: {target_scope_label(target)}", f"Sending CORS probe with Origin: {MALICIOUS_ORIGIN}"]
    findings: list[Finding] = []
    headers, error = _fetch_headers_with_origin(target, MALICIOUS_ORIGIN)
    if error:
        return ModuleResult(
            module="cors_audit",
            target=target,
            status="failed",
            findings=[],
            logs=logs + [f"CORS probe failed: {error}"],
            started_at=started,
            finished_at=now_iso(),
            error=error,
        )

    allow_origin = (headers.get("access-control-allow-origin") or "").strip()
    allow_credentials = (headers.get("access-control-allow-credentials") or "").strip().lower()
    vary = (headers.get("vary") or "").strip()
    logs.append(f"Access-Control-Allow-Origin: {allow_origin or 'not set'}")
    logs.append(f"Access-Control-Allow-Credentials: {allow_credentials or 'not set'}")

    if allow_origin == MALICIOUS_ORIGIN and allow_credentials == "true":
        context_payload = _cors_context(target, allow_origin, allow_credentials, vary, probe_origin=MALICIOUS_ORIGIN, risk="origin_reflection_credentials")
        findings.append(
            Finding(
                title="High-risk CORS origin reflection with credentials",
                severity="high",
                location=target,
                evidence=_cors_evidence(allow_origin, allow_credentials, vary),
                kind="vulnerability",
                verification_status="confirmed",
                verified=True,
                recommendation=(
                    "Replace arbitrary origin reflection with a strict allowlist and do not enable "
                    "Access-Control-Allow-Credentials for untrusted origins."
                ),
                metadata={"cors_context": context_payload, "verification_source": "cors_audit"},
            )
        )
    elif allow_origin == MALICIOUS_ORIGIN:
        context_payload = _cors_context(target, allow_origin, allow_credentials, vary, probe_origin=MALICIOUS_ORIGIN, risk="origin_reflection")
        findings.append(
            Finding(
                title="CORS origin reflection without credentials",
                severity="low",
                location=target,
                evidence=_cors_evidence(allow_origin, allow_credentials, vary),
                kind="candidate",
                verification_status="unconfirmed",
                verified=False,
                recommendation="Allow only trusted origins and confirm reflected origins are intentional.",
                metadata={"cors_context": context_payload, "verification_source": "cors_audit"},
            )
        )
    elif allow_origin == "*" and allow_credentials == "true":
        context_payload = _cors_context(target, allow_origin, allow_credentials, vary, probe_origin=MALICIOUS_ORIGIN, risk="wildcard_credentials")
        findings.append(
            Finding(
                title="Invalid wildcard CORS with credentials",
                severity="medium",
                location=target,
                evidence=_cors_evidence(allow_origin, allow_credentials, vary),
                kind="vulnerability",
                verification_status="confirmed",
                verified=True,
                recommendation="Do not combine wildcard CORS with credentials; use an explicit trusted origin allowlist.",
                metadata={"cors_context": context_payload, "verification_source": "cors_audit"},
            )
        )
    elif allow_origin == "null" and allow_credentials == "true":
        context_payload = _cors_context(target, allow_origin, allow_credentials, vary, probe_origin=MALICIOUS_ORIGIN, risk="null_origin_credentials")
        findings.append(
            Finding(
                title="CORS trust of null origin with credentials",
                severity="medium",
                location=target,
                evidence=_cors_evidence(allow_origin, allow_credentials, vary),
                kind="vulnerability",
                verification_status="confirmed",
                verified=True,
                recommendation="Reject null origins unless a narrowly scoped sandbox use case explicitly requires them.",
                metadata={"cors_context": context_payload, "verification_source": "cors_audit"},
            )
        )

    if not findings:
        logs.append("No obvious CORS misconfiguration was confirmed from the reflected Origin probe.")

    return ModuleResult(
        module="cors_audit",
        target=target,
        status="ok",
        findings=findings,
        logs=logs,
        followup_context={
            "producer": "cors_audit",
            "consumers": {
                "poc_verify": {
                    "high_risk_findings": [item.to_dict() for item in findings if item.verification_status == "confirmed"],
                    "cors_findings": [item.to_dict() for item in findings],
                }
            },
            "high_risk_findings": [item.to_dict() for item in findings if item.verification_status == "confirmed"],
        },
        started_at=started,
        finished_at=now_iso(),
    )


def _fetch_headers_with_origin(target: str, origin: str) -> tuple[dict[str, str], str]:
    request = Request(target, headers={"Origin": origin, "Accept": "*/*"})
    try:
        with urlopen(request, timeout=2.0) as response:
            headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
            return headers, ""
    except Exception as exc:
        return {}, str(exc)


def _cors_evidence(allow_origin: str, allow_credentials: str, vary: str) -> str:
    return "\n".join(
        [
            f"Probe Origin: {MALICIOUS_ORIGIN}",
            f"Access-Control-Allow-Origin: {allow_origin or 'not set'}",
            f"Access-Control-Allow-Credentials: {allow_credentials or 'not set'}",
            f"Vary: {vary or 'not set'}",
        ]
    )


def _cors_context(
    target: str,
    allow_origin: str,
    allow_credentials: str,
    vary: str,
    *,
    probe_origin: str,
    risk: str,
) -> dict[str, str]:
    return {
        "url": target,
        "probe_origin": probe_origin,
        "allow_origin": allow_origin or "",
        "allow_credentials": allow_credentials or "",
        "vary": vary or "",
        "risk": risk,
    }
