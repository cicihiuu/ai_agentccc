from __future__ import annotations

from dataclasses import dataclass, field

from .schemas import Finding


TRUTH_STATUS_LABELS = {
    "confirmed": "已确认",
    "unconfirmed": "未确认",
    "manual_required": "待人工确认",
    "not_run": "未执行",
    "informational": "信息项",
}

TRUTH_KIND_LABELS = {
    "vulnerability": "漏洞",
    "candidate": "候选",
    "evidence": "证据",
    "scope": "范围",
    "verification_record": "验证记录",
}


@dataclass(slots=True)
class TruthSummary:
    total_findings: int
    confirmed_vulnerabilities: int
    candidate_vulnerabilities: int
    manual_review_items: int
    supporting_items: int
    severity_counts: dict[str, int] = field(default_factory=dict)


def summarize_findings(findings: list[Finding]) -> TruthSummary:
    severity_counts: dict[str, int] = {}
    total_findings = 0
    confirmed_vulnerabilities = 0
    candidate_vulnerabilities = 0
    manual_review_items = 0
    supporting_items = 0
    seen: set[tuple[str, str, str, str, str, str]] = set()

    for finding in findings:
        dedupe_key = (
            finding.title,
            finding.location,
            finding.evidence,
            finding.kind,
            finding.verification_status,
            finding.severity,
        )
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        total_findings += 1
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        if finding.kind == "vulnerability" and finding.verification_status == "confirmed":
            confirmed_vulnerabilities += 1
        elif finding.kind == "candidate":
            candidate_vulnerabilities += 1

        if finding.verification_status in {"manual_required", "not_run"}:
            manual_review_items += 1

        if finding.kind in {"evidence", "scope", "verification_record"}:
            supporting_items += 1

    return TruthSummary(
        total_findings=total_findings,
        confirmed_vulnerabilities=confirmed_vulnerabilities,
        candidate_vulnerabilities=candidate_vulnerabilities,
        manual_review_items=manual_review_items,
        supporting_items=supporting_items,
        severity_counts=severity_counts,
    )


def is_confirmed_vulnerability(finding: Finding) -> bool:
    return finding.kind == "vulnerability" and finding.verification_status == "confirmed"


def is_candidate_vulnerability(finding: Finding) -> bool:
    return finding.kind == "candidate"


def is_manual_review_item(finding: Finding) -> bool:
    return finding.verification_status in {"manual_required", "not_run"}


def is_supporting_item(finding: Finding) -> bool:
    return finding.kind in {"evidence", "scope", "verification_record"}


def kind_label(kind: str) -> str:
    return TRUTH_KIND_LABELS.get(kind, kind)


def verification_status_label(status: str) -> str:
    return TRUTH_STATUS_LABELS.get(status, status)
