from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TaskModeSpec:
    key: str
    label: str
    module_bundle: str
    skill_names: tuple[str, ...] | None
    max_parallel_steps: int | None = 1


MODULE_BUNDLE_LABELS: dict[str, str] = {
    "full": "黑盒 Web 渗透",
    "recon": "资产与入口探测",
    "sql": "SQL 注入检测",
    "sql_bypass": "WAF 绕过检测",
    "xss": "XSS 漏洞检测",
    "ssrf": "SSRF 漏洞检测",
    "backup": "备份文件审计",
    "config": "配置泄露审计",
    "cors": "CORS 配置检测",
    "jwt": "JWT 安全检测",
    "js": "JS 敏感信息检测",
    "permission": "权限绕过 / IDOR 检测",
    "weak": "弱口令检测",
}

MODULE_BUNDLE_SKILLS: dict[str, tuple[str, ...] | None] = {
    "full": None,
    "recon": ("state-bootstrap", "recon"),
    "sql": ("state-bootstrap", "sql-scan", "sql-bypass", "poc-verify"),
    "sql_bypass": ("state-bootstrap", "sql-scan", "sql-bypass", "poc-verify"),
    "xss": ("state-bootstrap", "js-audit", "xss-triage", "poc-verify"),
    "ssrf": ("state-bootstrap", "js-audit", "ssrf-triage", "poc-verify"),
    "backup": ("state-bootstrap", "backup-audit-extended", "poc-verify"),
    "config": ("state-bootstrap", "backup-audit-extended", "config-audit", "poc-verify"),
    "cors": ("state-bootstrap", "cors-audit", "poc-verify"),
    "jwt": ("state-bootstrap", "jwt-audit", "poc-verify"),
    "js": ("state-bootstrap", "js-audit", "poc-verify"),
    "permission": ("state-bootstrap", "js-audit", "permission-bypass", "poc-verify"),
    "weak": ("state-bootstrap", "weak-password", "poc-verify"),
}

TASK_MODE_SPECS: dict[str, TaskModeSpec] = {
    "blackbox_pentest": TaskModeSpec(
        key="blackbox_pentest",
        label="黑盒 Web 渗透",
        module_bundle="full",
        skill_names=None,
        max_parallel_steps=None,
    ),
    "frontend_audit": TaskModeSpec(
        key="frontend_audit",
        label="前端 JS 审计",
        module_bundle="js",
        skill_names=("state-bootstrap", "js-audit", "xss-triage", "permission-bypass", "poc-verify"),
    ),
    "sql_focus": TaskModeSpec(
        key="sql_focus",
        label="SQL 注入专项",
        module_bundle="sql",
        skill_names=("state-bootstrap", "sql-scan", "sql-bypass", "poc-verify"),
    ),
    "exposure_audit": TaskModeSpec(
        key="exposure_audit",
        label="暴露面 / 备份配置审计",
        module_bundle="config",
        skill_names=("state-bootstrap", "recon", "backup-audit-extended", "config-audit", "js-audit", "poc-verify"),
    ),
    "auth_audit": TaskModeSpec(
        key="auth_audit",
        label="认证与权限审计",
        module_bundle="permission",
        skill_names=("state-bootstrap", "js-audit", "permission-bypass", "weak-password", "jwt-audit", "cors-audit", "poc-verify"),
    ),
}


def normalize_module_bundle(module_bundle: str) -> str:
    value = str(module_bundle or "full").strip().lower().replace("-", "_")
    if value not in MODULE_BUNDLE_SKILLS:
        raise ValueError(f"unsupported module_bundle: {module_bundle}")
    return value


def normalize_task_mode(task_mode: str) -> str:
    value = str(task_mode or "").strip().lower().replace("-", "_")
    if not value:
        return ""
    if value not in TASK_MODE_SPECS:
        raise ValueError(f"unsupported task_mode: {task_mode}")
    return value


def task_mode_spec(task_mode: str) -> TaskModeSpec:
    return TASK_MODE_SPECS[normalize_task_mode(task_mode)]


def module_bundle_label(module_bundle: str) -> str:
    return MODULE_BUNDLE_LABELS.get(normalize_module_bundle(module_bundle), str(module_bundle or "full"))


def module_bundle_skills(module_bundle: str) -> tuple[str, ...] | None:
    return MODULE_BUNDLE_SKILLS[normalize_module_bundle(module_bundle)]
