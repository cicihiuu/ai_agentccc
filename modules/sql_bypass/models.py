from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse


@dataclass(frozen=True, slots=True)
class SQLBypassCandidate:
    page_url: str
    parameter: str
    method: str = "GET"
    baseline_url: str = ""
    baseline_body: str = ""
    confirmed_strategies: list[str] = field(default_factory=list)
    strategy_lengths: dict[str, int] = field(default_factory=dict)
    basis: str = ""
    source_title: str = ""
    source_location: str = ""
    source_verified: bool = False

    @property
    def has_request_context(self) -> bool:
        return bool(self.page_url and self.parameter)

    def to_dict(self) -> dict[str, Any]:
        return {
            "page_url": _redact_url(self.page_url, self.parameter),
            "parameter": self.parameter,
            "method": self.method,
            "baseline_url": _redact_url(self.baseline_url, self.parameter),
            "baseline_body": _redact_body(self.baseline_body, self.parameter),
            "confirmed_strategies": list(self.confirmed_strategies),
            "strategy_lengths": dict(self.strategy_lengths),
            "basis": self.basis,
            "source_title": self.source_title,
            "source_location": self.source_location,
            "source_verified": self.source_verified,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SQLBypassCandidate":
        lengths: dict[str, int] = {}
        raw_lengths = data.get("strategy_lengths", {})
        if isinstance(raw_lengths, dict):
            for key, value in raw_lengths.items():
                try:
                    lengths[str(key)] = int(value)
                except (TypeError, ValueError):
                    continue
        return cls(
            page_url=str(data.get("page_url", "") or data.get("page", "")).strip(),
            parameter=str(data.get("parameter", "") or data.get("param_name", "")).strip(),
            method=str(data.get("method", "GET") or "GET").strip().upper(),
            baseline_url=str(data.get("baseline_url", "")).strip(),
            baseline_body=str(data.get("baseline_body", "")).strip(),
            confirmed_strategies=[str(item).strip() for item in data.get("confirmed_strategies", []) if str(item).strip()]
            if isinstance(data.get("confirmed_strategies", []), list)
            else [],
            strategy_lengths=lengths,
            basis=str(data.get("basis", "")).strip(),
            source_title=str(data.get("source_title", "") or data.get("title", "")).strip(),
            source_location=str(data.get("source_location", "") or data.get("location", "")).strip(),
            source_verified=bool(data.get("source_verified", data.get("verified", False))),
        )


@dataclass(frozen=True, slots=True)
class WAFProfile:
    waf_type: str
    confidence: float
    detected: bool
    vendor: str = ""
    matched_by: list[str] = field(default_factory=list)
    recommendation_basis: str = ""
    signatures: list[str] = field(default_factory=list)
    blocked_indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "waf_type": self.waf_type,
            "confidence": self.confidence,
            "detected": self.detected,
            "vendor": self.vendor,
            "matched_by": list(self.matched_by),
            "recommendation_basis": self.recommendation_basis,
            "signatures": list(self.signatures),
            "blocked_indicators": list(self.blocked_indicators),
        }


@dataclass(frozen=True, slots=True)
class TamperRecommendation:
    name: str
    source: str
    reason: str
    dbms_scope: str = ""
    rank: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source,
            "reason": self.reason,
            "dbms_scope": self.dbms_scope,
            "rank": self.rank,
        }


@dataclass(frozen=True, slots=True)
class PayloadStrategy:
    name: str
    payload: str
    true_payload: str
    false_payload: str
    family: str
    note: str
    tamper_hint: str = ""

    def to_dict(self, *, redacted: bool = True) -> dict[str, Any]:
        payload_hash = _hash_text(self.payload)
        if redacted:
            return {
                "name": self.name,
                "payload_hash": payload_hash,
                "family": self.family,
                "note": self.note,
                "tamper_hint": self.tamper_hint,
            }
        return {
            "name": self.name,
            "payload": self.payload,
            "true_payload": self.true_payload,
            "false_payload": self.false_payload,
            "payload_hash": payload_hash,
            "family": self.family,
            "note": self.note,
            "tamper_hint": self.tamper_hint,
        }


@dataclass(frozen=True, slots=True)
class ProbeRequest:
    method: str
    url: str
    body: str = ""

    def to_dict(self, *, parameter: str = "", redacted: bool = True) -> dict[str, Any]:
        if not redacted:
            return {"method": self.method, "url": self.url, "body": self.body}
        return {
            "method": self.method,
            "url": _redact_url(self.url, parameter),
            "body": _redact_body(self.body, parameter),
        }


@dataclass(frozen=True, slots=True)
class ControlProbeStep:
    name: str
    request: ProbeRequest
    status_code: int
    response_length: int
    blocked: bool
    sql_error_marker: bool
    error: str = ""

    def to_dict(self, *, parameter: str = "", redacted: bool = True) -> dict[str, Any]:
        return {
            "name": self.name,
            "request": self.request.to_dict(parameter=parameter, redacted=redacted),
            "status_code": self.status_code,
            "response_length": self.response_length,
            "blocked": self.blocked,
            "sql_error_marker": self.sql_error_marker,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class AttackControlProbe:
    normal_baseline: ControlProbeStep
    basic_attack: ControlProbeStep
    bypass_attack: ControlProbeStep

    @property
    def blocked_to_allowed(self) -> bool:
        return self.normal_baseline.status_code in range(200, 400) and self.basic_attack.blocked and not self.bypass_attack.blocked and self.bypass_attack.status_code in range(200, 400)

    def to_dict(self, *, parameter: str = "", redacted: bool = True) -> dict[str, Any]:
        return {
            "normal_baseline": self.normal_baseline.to_dict(parameter=parameter, redacted=redacted),
            "basic_attack": self.basic_attack.to_dict(parameter=parameter, redacted=redacted),
            "bypass_attack": self.bypass_attack.to_dict(parameter=parameter, redacted=redacted),
            "blocked_to_allowed": self.blocked_to_allowed,
        }


@dataclass(frozen=True, slots=True)
class ProbeObservation:
    strategy: PayloadStrategy
    request: ProbeRequest
    control_probe: AttackControlProbe
    status_code: int
    response_length: int
    blocked: bool
    delta_from_baseline: int
    true_false_delta: int
    true_status_code: int
    false_status_code: int
    sql_error_marker: bool
    assessment_signal: bool
    signal_type: str
    basis: str
    error: str = ""

    def to_dict(self, *, parameter: str = "", redacted: bool = True) -> dict[str, Any]:
        return {
            "strategy": self.strategy.to_dict(redacted=redacted),
            "request": self.request.to_dict(parameter=parameter, redacted=redacted),
            "control_probe": self.control_probe.to_dict(parameter=parameter, redacted=redacted),
            "status_code": self.status_code,
            "response_length": self.response_length,
            "blocked": self.blocked,
            "delta_from_baseline": self.delta_from_baseline,
            "true_false_delta": self.true_false_delta,
            "true_status_code": self.true_status_code,
            "false_status_code": self.false_status_code,
            "sql_error_marker": self.sql_error_marker,
            "assessment_signal": self.assessment_signal,
            "signal_type": self.signal_type,
            "basis": self.basis,
            "error": self.error,
        }

    @property
    def signal_rank(self) -> int:
        signal_type = str(self.signal_type or "").strip().lower()
        if signal_type == "sql_error":
            return 40
        if signal_type == "blocked_to_allowed":
            return 35
        if signal_type == "true_false_pair":
            return 25
        if self.delta_from_baseline > 120:
            return 10
        return 0


@dataclass(frozen=True, slots=True)
class BypassAssessmentRecord:
    candidate: SQLBypassCandidate
    waf_profile: WAFProfile
    tamper_recommendations: list[TamperRecommendation]
    observations: list[ProbeObservation]
    sqlmap_command: dict[str, Any]
    conclusion: str
    dbms_hint: str = ""

    @property
    def has_assessment_signal(self) -> bool:
        return any(item.assessment_signal for item in self.observations)

    @property
    def signal_count(self) -> int:
        return sum(1 for item in self.observations if item.assessment_signal)

    @property
    def signal_types(self) -> list[str]:
        return sorted({str(item.signal_type).strip() for item in self.observations if item.assessment_signal and str(item.signal_type).strip()})

    @property
    def attempted_strategy_names(self) -> list[str]:
        names: list[str] = []
        for item in self.observations:
            name = str(item.strategy.name).strip()
            if name and name not in names:
                names.append(name)
        return names

    @property
    def best_observation(self) -> ProbeObservation | None:
        if not self.observations:
            return None
        return max(
            self.observations,
            key=lambda item: (
                int(item.assessment_signal),
                item.signal_rank,
                int(item.true_false_delta),
                int(item.delta_from_baseline),
                -int(item.blocked),
            ),
        )

    def to_dict(self, *, redacted: bool = True) -> dict[str, Any]:
        tamper_items = [item.to_dict() for item in self.tamper_recommendations]
        best_observation = self.best_observation
        return {
            "candidate": self.candidate.to_dict(),
            "waf_profile": self.waf_profile.to_dict(),
            "tamper_recommendations": tamper_items if redacted else tamper_items,
            "observations": [item.to_dict(parameter=self.candidate.parameter, redacted=redacted) for item in self.observations],
            "sqlmap_command": _redact_sqlmap_command(self.sqlmap_command) if redacted else dict(self.sqlmap_command),
            "assessment_conclusion": self.conclusion,
            "assessment_signal": self.has_assessment_signal,
            "dbms_hint": self.dbms_hint,
            "signal_summary": {
                "signal_count": self.signal_count,
                "signal_types": list(self.signal_types),
                "attempted_strategy_names": list(self.attempted_strategy_names),
                "blocked_observation_count": sum(1 for item in self.observations if item.blocked or item.control_probe.basic_attack.blocked),
                "best_strategy": best_observation.strategy.name if best_observation else "",
                "best_signal_type": best_observation.signal_type if best_observation else "",
                "has_assessment_signal": self.has_assessment_signal,
            },
            "best_observation": best_observation.to_dict(parameter=self.candidate.parameter, redacted=redacted) if best_observation else {},
        }


def _hash_text(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()[:16]


def _redact_url(url: str, parameter: str = "") -> str:
    if not url:
        return ""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return url
    query = parse_qs(parsed.query)
    param_keys = sorted(query.keys())
    path = parsed.path or "/"
    if parameter and parameter in query:
        return f"{parsed.scheme}://{parsed.netloc}{path}?{parameter}=[redacted]"
    if param_keys:
        return f"{parsed.scheme}://{parsed.netloc}{path}?params=[redacted:{','.join(param_keys[:6])}]"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _redact_body(body: str, parameter: str = "") -> str:
    if not body:
        return ""
    keys = sorted(parse_qs(body).keys())
    if parameter and parameter in keys:
        return f"{parameter}=[redacted]"
    return f"params=[redacted:{','.join(keys[:6])}]" if keys else "[redacted]"


def _redact_sqlmap_command(command_info: dict[str, Any]) -> dict[str, Any]:
    primary = command_info.get("primary_command", [])
    variants = command_info.get("variant_commands", [])
    return {
        "execution_mode": str(command_info.get("execution_mode", "generated_only")),
        "waf_type": str(command_info.get("waf_type", "generic")),
        "primary_display": _redact_command_list(primary),
        "variant_displays": [_redact_command_list(item) for item in variants if isinstance(item, list)],
        "blocked_options": list(command_info.get("blocked_options", [])) if isinstance(command_info.get("blocked_options", []), list) else [],
    }


def _redact_command_list(command: Any) -> str:
    raw = [str(item) for item in command] if isinstance(command, list) else []
    redacted: list[str] = []
    skip_next = False
    for index, part in enumerate(raw):
        if skip_next:
            skip_next = False
            continue
        if part in {"-u", "--url"} and index + 1 < len(raw):
            redacted.extend([part, "[redacted-url]"])
            skip_next = True
            continue
        if part == "--data" and index + 1 < len(raw):
            redacted.extend([part, "[redacted-body]"])
            skip_next = True
            continue
        redacted.append(part)
    return " ".join(redacted)
