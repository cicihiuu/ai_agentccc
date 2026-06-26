from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar, Literal


ModuleName = Literal[
    "state_bootstrap",
    "recon",
    "backup_audit_extended",
    "sql_scan",
    "sql_bypass",
    "js_audit",
    "xss_triage",
    "ssrf_triage",
    "poc_verify",
    "config_audit",
    "permission_bypass",
    "weak_password",
    "cors_audit",
    "jwt_audit",
]
ModuleStatus = Literal["ok", "failed", "skipped"]
Severity = Literal["critical", "high", "medium", "low", "info"]
FindingKind = Literal["vulnerability", "candidate", "evidence", "scope", "verification_record"]
VerificationStatus = Literal["confirmed", "unconfirmed", "manual_required", "not_run", "informational"]


@dataclass(slots=True)
class Finding:
    title: str
    severity: Severity
    location: str = ""
    evidence: str = ""
    kind: FindingKind = "candidate"
    verification_status: VerificationStatus = "unconfirmed"
    verified: bool = False
    recommendation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    VALID_SEVERITIES: ClassVar[set[str]] = {"critical", "high", "medium", "low", "info"}
    VALID_KINDS: ClassVar[set[str]] = {"vulnerability", "candidate", "evidence", "scope", "verification_record"}
    VALID_VERIFICATION_STATUSES: ClassVar[set[str]] = {
        "confirmed",
        "unconfirmed",
        "manual_required",
        "not_run",
        "informational",
    }

    def __post_init__(self) -> None:
        if self.kind == "candidate" and self.verification_status == "unconfirmed":
            inferred_kind, inferred_status = self._resolve_truth_fields(
                {
                    "title": self.title,
                    "severity": self.severity,
                    "location": self.location,
                    "evidence": self.evidence,
                    "verified": self.verified,
                    "recommendation": self.recommendation,
                },
                severity=self.severity,
            )
            self.kind = inferred_kind
            self.verification_status = inferred_status
            self.verified = inferred_status == "confirmed"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        severity = data.get("severity", "info")
        if severity not in cls.VALID_SEVERITIES:
            raise ValueError(f"invalid severity: {severity}")
        kind, verification_status = cls._resolve_truth_fields(data, severity=str(severity))
        return cls(
            title=str(data.get("title", "")).strip(),
            severity=severity,
            location=str(data.get("location", "")).strip(),
            evidence=str(data.get("evidence", "")).strip(),
            kind=kind,
            verification_status=verification_status,
            verified=bool(data.get("verified", verification_status == "confirmed")),
            recommendation=str(data.get("recommendation", "")).strip(),
            metadata=dict(data.get("metadata", {})) if isinstance(data.get("metadata", {}), dict) else {},
        )

    def validate(self) -> None:
        if not self.title:
            raise ValueError("finding title is required")
        if self.severity not in self.VALID_SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity}")
        if self.kind not in self.VALID_KINDS:
            raise ValueError(f"invalid finding kind: {self.kind}")
        if self.verification_status not in self.VALID_VERIFICATION_STATUSES:
            raise ValueError(f"invalid verification_status: {self.verification_status}")
        if self.verified != (self.verification_status == "confirmed"):
            raise ValueError("verified must be true only when verification_status is confirmed")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a dictionary")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "title": self.title,
            "severity": self.severity,
            "location": self.location,
            "evidence": self.evidence,
            "kind": self.kind,
            "verification_status": self.verification_status,
            "verified": self.verified,
            "recommendation": self.recommendation,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def _resolve_truth_fields(cls, data: dict[str, Any], *, severity: str) -> tuple[FindingKind, VerificationStatus]:
        raw_kind = str(data.get("kind", "")).strip()
        raw_status = str(data.get("verification_status", "")).strip()
        if raw_kind and raw_kind not in cls.VALID_KINDS:
            raise ValueError(f"invalid finding kind: {raw_kind}")
        if raw_status and raw_status not in cls.VALID_VERIFICATION_STATUSES:
            raise ValueError(f"invalid verification_status: {raw_status}")
        if raw_kind and raw_status:
            return raw_kind, raw_status

        title = str(data.get("title", "")).strip().lower()
        evidence = str(data.get("evidence", "")).strip().lower()
        recommendation = str(data.get("recommendation", "")).strip().lower()
        location = str(data.get("location", "")).strip().lower()
        verified = bool(data.get("verified", False))
        combined = "\n".join([title, evidence, recommendation, location])

        if raw_kind:
            inferred_kind = raw_kind
        elif "verification record" in combined or "replay result:" in combined:
            inferred_kind = "verification_record"
        elif any(marker in combined for marker in ("follow-up scope", "followup scope", "checklist", "baseline metadata")):
            inferred_kind = "scope"
        elif severity == "info" and any(marker in combined for marker in ("hint", "scope", "inventory", "metadata", "route")):
            inferred_kind = "evidence"
        elif verified and severity in {"critical", "high", "medium", "low"}:
            inferred_kind = "vulnerability"
        else:
            inferred_kind = "candidate"

        if raw_status:
            inferred_status = raw_status
        elif inferred_kind in {"scope", "evidence"}:
            inferred_status = "informational"
        elif inferred_kind == "verification_record":
            inferred_status = "manual_required" if "manual" in combined or "needs human confirmation" in combined else "unconfirmed"
        elif verified:
            inferred_status = "confirmed"
        else:
            inferred_status = "unconfirmed"

        return inferred_kind, inferred_status


@dataclass(slots=True)
class ModuleResult:
    module: ModuleName
    target: str
    status: ModuleStatus
    findings: list[Finding] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    followup_context: dict[str, Any] = field(default_factory=dict)
    started_at: str = ""
    finished_at: str = ""
    error: str = ""

    VALID_MODULES: ClassVar[set[str]] = {
        "state_bootstrap",
        "recon",
        "backup_audit_extended",
        "sql_scan",
        "sql_bypass",
        "js_audit",
        "xss_triage",
        "ssrf_triage",
        "poc_verify",
        "config_audit",
        "permission_bypass",
        "weak_password",
        "cors_audit",
        "jwt_audit",
    }
    VALID_STATUSES: ClassVar[set[str]] = {"ok", "failed", "skipped"}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ModuleResult":
        module = data.get("module", "")
        status = data.get("status", "")
        if module not in cls.VALID_MODULES:
            raise ValueError(f"invalid module: {module}")
        if status not in cls.VALID_STATUSES:
            raise ValueError(f"invalid status: {status}")
        findings = [Finding.from_dict(item) for item in data.get("findings", [])]
        result = cls(
            module=module,
            target=str(data.get("target", "")).strip(),
            status=status,
            findings=findings,
            logs=[str(item) for item in data.get("logs", [])],
            followup_context=dict(data.get("followup_context", {})),
            started_at=str(data.get("started_at", "")).strip(),
            finished_at=str(data.get("finished_at", "")).strip(),
            error=str(data.get("error", "")).strip(),
        )
        result.validate()
        return result

    def validate(self) -> None:
        if self.module not in self.VALID_MODULES:
            raise ValueError(f"invalid module: {self.module}")
        if self.status not in self.VALID_STATUSES:
            raise ValueError(f"invalid status: {self.status}")
        if not self.target:
            raise ValueError("target is required")
        if self.status in {"failed", "skipped"} and not self.error:
            raise ValueError("failed or skipped modules must include error")
        if not isinstance(self.followup_context, dict):
            raise ValueError("followup_context must be a dictionary")
        for finding in self.findings:
            finding.validate()

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "module": self.module,
            "target": self.target,
            "status": self.status,
            "findings": [finding.to_dict() for finding in self.findings],
            "logs": list(self.logs),
            "followup_context": dict(self.followup_context),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
        }


@dataclass(slots=True)
class ScanRun:
    target: str
    modules: list[ModuleResult]
    generated_at: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanRun":
        target = str(data.get("target", "")).strip()
        modules = [ModuleResult.from_dict(item) for item in data.get("modules", [])]
        run = cls(
            target=target,
            modules=modules,
            generated_at=str(data.get("generated_at", "")).strip(),
        )
        run.validate()
        return run

    def validate(self) -> None:
        if not self.target:
            raise ValueError("scan target is required")
        if not self.modules:
            raise ValueError("at least one module result is required")
        for module in self.modules:
            module.validate()

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "target": self.target,
            "modules": [module.to_dict() for module in self.modules],
            "generated_at": self.generated_at,
        }
