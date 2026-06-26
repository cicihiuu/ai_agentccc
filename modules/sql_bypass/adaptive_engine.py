from __future__ import annotations

from typing import Any

from .evasion_engine import EvasionEngine
from .models import BypassAssessmentRecord, SQLBypassCandidate, WAFProfile
from .probe_runner import ProbeRunner, is_blocked_response
from .sqlmap_adapter import build_safe_sqlmap_command


class SQLBypassAdaptiveEngine:
    def __init__(self, *, evasion_engine: EvasionEngine | None = None, probe_runner: ProbeRunner | None = None) -> None:
        self.evasion_engine = evasion_engine or EvasionEngine()
        self.probe_runner = probe_runner or ProbeRunner()

    def extract_sql_scan_candidates(self, context: dict[str, Any] | None) -> list[SQLBypassCandidate]:
        upstream = (context or {}).get("upstream_followup_context")
        if not isinstance(upstream, dict):
            return []
        sql_context = upstream.get("sql_scan")
        if not isinstance(sql_context, dict) or sql_context.get("producer") != "sql_scan":
            return []
        consumers = sql_context.get("consumers")
        payload = consumers.get("sql_bypass") if isinstance(consumers, dict) and isinstance(consumers.get("sql_bypass"), dict) else {}
        raw_items = payload.get("sql_findings") or sql_context.get("sql_bypass_findings") or payload.get("candidate_findings") or []
        if not isinstance(raw_items, list):
            return []
        candidates: list[SQLBypassCandidate] = []
        seen: set[tuple[str, str, str, str, str]] = set()
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            candidate = SQLBypassCandidate.from_dict(item)
            if not candidate.has_request_context:
                continue
            key = (candidate.page_url, candidate.parameter, candidate.method, candidate.baseline_url, candidate.baseline_body)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(candidate)
        candidates.sort(
            key=lambda item: (
                not item.source_verified,
                -len(item.confirmed_strategies),
                item.method != "GET",
                item.page_url,
                item.parameter,
            )
        )
        return candidates

    def run(self, candidates: list[SQLBypassCandidate], *, max_candidates: int = 6, strategies_per_candidate: int = 8) -> list[BypassAssessmentRecord]:
        records: list[BypassAssessmentRecord] = []
        for candidate in candidates[:max_candidates]:
            baseline_request, baseline = self.probe_runner.send_baseline(candidate)
            _basic_request, basic_attack = self.probe_runner.send_basic_attack(candidate)
            waf_profile = self.evasion_engine.analyze_response(
                basic_attack.headers or baseline.headers,
                f"{basic_attack.text or ''}\n{basic_attack.error or ''}",
                status_code=basic_attack.status_code,
            )
            if not waf_profile.detected:
                combined_headers = {**(baseline.headers or {}), **(basic_attack.headers or {})}
                combined_body = f"{baseline.text or ''}\n{basic_attack.text or ''}\n{basic_attack.error or ''}"
                waf_profile = self.evasion_engine.analyze_response(
                    combined_headers,
                    combined_body,
                    status_code=basic_attack.status_code or baseline.status_code,
                )
            if baseline.error and not waf_profile.detected:
                waf_profile = WAFProfile(
                    waf_type="generic",
                    confidence=0.1,
                    detected=False,
                    vendor="generic",
                    matched_by=[],
                    recommendation_basis="Baseline fetch failed before a specific WAF fingerprint could be established.",
                    signatures=[],
                    blocked_indicators=[baseline.error],
                )
            baseline_blocked = is_blocked_response(baseline)
            strategies = self.evasion_engine.generate_strategies(candidate, waf_profile, limit=strategies_per_candidate)
            observations = [
                self.probe_runner.send_strategy(candidate, strategy, baseline_request=baseline_request, baseline=baseline)
                for strategy in strategies
            ]
            dbms_hint = self._infer_dbms_hint(candidate)
            tamper_recommendations = self.evasion_engine.tamper_recommendations(waf_profile, dbms_hint=dbms_hint)
            records.append(
                BypassAssessmentRecord(
                    candidate=candidate,
                    waf_profile=waf_profile,
                    tamper_recommendations=tamper_recommendations,
                    observations=observations,
                    sqlmap_command=build_safe_sqlmap_command(candidate, waf_profile, tamper_recommendations),
                    conclusion=self._conclusion(waf_profile, baseline_blocked, observations),
                    dbms_hint=dbms_hint,
                )
            )
        return records

    def _infer_dbms_hint(self, candidate: SQLBypassCandidate) -> str:
        basis = (candidate.basis or "").lower()
        joined = " ".join(candidate.confirmed_strategies).lower()
        combined = f"{basis} {joined}"
        if "mysql" in combined or "mysqli" in combined or "pdoexception" in combined:
            return "mysql"
        if "mssql" in combined or "sql server" in combined or "sppassword" in combined:
            return "mssql"
        if "postgres" in combined or "postgresql" in combined:
            return "postgresql"
        if "sqlite" in combined:
            return "sqlite"
        return ""

    def _conclusion(self, waf_profile, baseline_blocked: bool, observations) -> str:
        signal_count = sum(1 for item in observations if item.assessment_signal)
        blocked_count = sum(1 for item in observations if item.blocked or item.control_probe.basic_attack.blocked)
        if signal_count:
            signal_types = sorted({item.signal_type for item in observations if item.assessment_signal})
            return (
                "assessment only; not a standalone confirmed vulnerability. "
                f"Observed {signal_count} stable signal(s) ({', '.join(signal_types)}) against waf={waf_profile.waf_type}."
            )
        if baseline_blocked or blocked_count:
            return (
                "assessment only; not a standalone confirmed vulnerability. "
                f"WAF/blocking behavior was observed, but tested bypass variants did not produce a stable signal."
            )
        return "assessment only; not a standalone confirmed vulnerability. No WAF bypass signal was observed in bounded probes."
