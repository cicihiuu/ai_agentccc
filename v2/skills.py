from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import ChildTaskPolicy, SkillCard


BASELINE_SKILLS = [
    "state-bootstrap",
    "recon",
    "backup-audit-extended",
    "config-audit",
    "sql-scan",
    "sql-bypass",
    "js-audit",
    "xss-triage",
    "ssrf-triage",
    "permission-bypass",
    "cors-audit",
    "poc-verify",
    "weak-password",
    "jwt-audit",
]


DEFAULT_TOOL_MAP = {
    "state_bootstrap": ["state_bootstrap_bridge", "http_request", "extract_forms_from_html", "extract_links_from_html", "session_store"],
    "recon": ["http_request", "extract_links_from_html", "extract_forms_from_html", "extract_parameters_from_response", "recon_bridge", "artifact_capture", "response_diff"],
    "backup_audit_extended": ["backup_audit_bridge", "fetch_candidate_file", "extract_archive", "grep_sensitive_patterns", "spawn_subagent"],
    "config_audit": ["fetch_candidate_file", "parse_config", "grep_sensitive_patterns"],
    "sql_scan": ["run_skill_deep_scan", "discover_sql_candidates", "probe_sql_boolean", "run_waf_bypass_strategy"],
    "sql_bypass": ["generate_sql_bypass_plan", "run_sql_bypass_probe", "run_waf_bypass_strategy", "run_sqlmap_safe", "artifact_capture"],
    "js_audit": ["js_audit_bridge", "http_request", "parse_js_ast", "extract_js_endpoints", "extract_fetch_calls", "extract_dom_sinks", "grep_sensitive_patterns", "artifact_capture"],
    "xss_triage": ["run_skill_deep_scan", "http_request", "replay_request_with_mutation", "response_diff", "browser_action", "xss_triage_bridge"],
    "ssrf_triage": ["run_skill_deep_scan", "http_request", "create_callback_endpoint", "poll_callback_events", "build_ssrf_probe_set", "replay_with_redirect_chain", "parser_confusion_probe", "ssrf_triage_bridge"],
    "permission_bypass": ["run_skill_deep_scan", "browser_action", "session_store", "save_session", "load_session", "switch_session", "clone_session", "same_request_different_session_replay", "response_diff", "compare_http_responses", "permission_bypass_bridge"],
    "cors_audit": ["cors_audit_bridge", "run_skill_deep_scan", "http_request", "browser_action", "artifact_capture"],
    "poc_verify": ["generate_poc_verification_case", "run_poc_in_docker", "capture_request_response", "artifact_capture"],
    "weak_password": ["weak_password_bridge", "run_skill_deep_scan", "browser_action", "session_store"],
    "jwt_audit": ["jwt_audit_bridge", "http_request", "artifact_capture"],
}


STRATEGY_DEFAULTS: dict[str, dict[str, Any]] = {
    "sql_scan": {
        "success_criteria": ["发现候选参数", "完成差分或时间/错误型验证", "产生可追踪 verification record"],
        "stop_conditions": ["无候选参数", "连续重复探测无新信号", "已完成至少一种稳定验证"],
        "false_positive_rules": ["不能仅凭 SQL 错误字符串报告", "必须有受控差分、时间信号或 POC 证据"],
    },
    "sql_bypass": {
        "success_criteria": ["生成绕过策略", "至少执行一个绕过 probe", "输出结构化 assessment signal"],
        "stop_conditions": ["上游无 SQL candidate", "绕过策略均无差异信号", "已形成 POC 验证候选"],
        "false_positive_rules": ["不能把 WAF 识别结果当漏洞", "绕过成功必须关联到注入候选"],
    },
    "xss_triage": {
        "success_criteria": ["识别反射或 DOM sink", "固化浏览器/DOM 证据", "输出执行上下文判断"],
        "stop_conditions": ["无输入点或 sink", "反射不可进入可执行上下文", "已完成 browser proof"],
        "false_positive_rules": ["不能仅凭响应包含 payload 报告", "需要 browser、DOM 或上下文证据"],
    },
    "ssrf_triage": {
        "success_criteria": ["识别 URL-bearing 参数", "部署 callback", "确认回连或可信侧信道"],
        "stop_conditions": ["无 URL 参数", "callback 多轮未命中且无 redirect/parser 信号", "已命中 callback"],
        "false_positive_rules": ["不能仅凭参数名像 url 报告", "必须有 callback 或可信响应差异"],
    },
    "permission_bypass": {
        "success_criteria": ["构造至少两个身份", "同请求不同身份回放", "证明差异与权限边界相关"],
        "stop_conditions": ["无法建立身份上下文", "无可比较 endpoint", "已固化差分证据"],
        "false_positive_rules": ["不能仅凭 body 不同报告", "必须说明身份、对象或角色边界"],
    },
    "js_audit": {
        "success_criteria": ["提取 JS endpoint/source/sink", "定位 API 或危险 DOM 操作", "回流可测试入口"],
        "stop_conditions": ["无 JS 资源或 endpoint", "已派生 child follow-up", "无新 sink/endpoint"],
        "false_positive_rules": ["静态 sink 不能直接报告", "敏感信息必须脱敏且证明可利用性"],
    },
    "backup_audit_extended": {
        "success_criteria": ["发现可访问备份/配置", "完成解压或配置解析", "输出 route/secret/source follow-up"],
        "stop_conditions": ["候选文件均不可访问", "已完成基础静态审计", "无新敏感模式"],
        "false_positive_rules": ["不能泄露原始 secret", "备份存在需证明可访问和有风险内容"],
    },
    "poc_verify": {
        "success_criteria": ["选择 verified candidate", "生成 POC case", "Docker 或 manual proof 归档"],
        "stop_conditions": ["无候选 finding", "POC 模板不可安全执行", "已得到 sandbox proof"],
        "false_positive_rules": ["manual-only 不得提升为 sandbox verified", "POC 输出必须可复现"],
    },
}


FOLLOWUP_ROUTE_MAP = {
    "state_bootstrap": ["recon", "sql_scan", "xss_triage", "ssrf_triage", "permission_bypass", "js_audit", "poc_verify"],
    "recon": ["backup_audit_extended", "js_audit", "sql_scan"],
    "backup_audit_extended": ["config_audit", "permission_bypass"],
    "config_audit": ["poc_verify"],
    "sql_scan": ["sql_bypass", "poc_verify"],
    "sql_bypass": ["poc_verify"],
    "js_audit": ["xss_triage", "permission_bypass", "poc_verify"],
    "xss_triage": ["poc_verify"],
    "ssrf_triage": ["poc_verify"],
    "permission_bypass": ["poc_verify"],
    "cors_audit": ["poc_verify"],
    "poc_verify": [],
    "weak_password": ["poc_verify"],
    "jwt_audit": [],
}


CHILD_TASK_POLICY_MAP: dict[str, list[ChildTaskPolicy]] = {
    "backup_audit_extended": [
        ChildTaskPolicy(
            source_module="backup_audit_extended",
            task_name="backup-source-audit-child",
            goal="审计备份暴露线索，提取源码、配置与敏感信息证据。",
            planned_tools=["grep_sensitive_patterns", "parse_config", "artifact_capture"],
            spawn_condition="has_leads",
            max_iterations=4,
            success_criteria=["提取备份/配置风险线索", "输出可回流 endpoint/route/secret 上下文"],
            stop_conditions=["基础配置审计完成", "无新敏感模式"],
            output_contract=["leads", "verification_records", "route_candidates", "recommended_next_tests"],
        )
    ],
    "js_audit": [
        ChildTaskPolicy(
            source_module="js_audit",
            task_name="js-derived-api-child",
            goal="根据 JS/HTML 派生接口候选，独立验证可访问的后端入口。",
            planned_tools=["http_request", "artifact_capture"],
            spawn_condition="endpoint_candidates_or_js_heuristics",
            max_iterations=6,
            success_criteria=["验证 JS 派生 API 可访问", "固化响应证据"],
            stop_conditions=["候选 endpoint 已检查", "无可访问入口"],
            output_contract=["endpoint_seeds", "leads", "verified_findings"],
        )
    ],
    "xss_triage": [
        ChildTaskPolicy(
            source_module="xss_triage",
            task_name="xss-multi-entry-child",
            goal="独立复测 XSS 反射入口，固化浏览器与响应证据。",
            planned_tools=["http_request", "browser_action", "artifact_capture"],
            spawn_condition="xss_probe_urls",
            max_iterations=6,
            success_criteria=["复测反射入口", "固化浏览器证据"],
            stop_conditions=["候选 URL 已检查", "无反射或 browser proof"],
            output_contract=["xss_probe_urls", "verification_records", "verified_findings"],
        )
    ],
    "permission_bypass": [
        ChildTaskPolicy(
            source_module="permission_bypass",
            task_name="auth-differential-child",
            goal="独立复测高低权限访问差异，固化越权证据。",
            planned_tools=["create_identity", "session_store", "http_request", "compare_http_responses", "artifact_capture"],
            spawn_condition="suspicious_differential",
            max_iterations=8,
            success_criteria=["构建双身份", "完成同请求差分回放", "固化权限边界证据"],
            stop_conditions=["无法建立身份", "无 suspicious differential"],
            output_contract=["session_seeds", "differential_signals", "verified_findings"],
        )
    ],
}


def _read_markdown_list(path: Path, fallback: list[str]) -> list[str]:
    if not path.exists():
        return list(fallback)
    items: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(("- ", "* ")):
            items.append(stripped[2:].strip())
    return items or list(fallback)


class SkillCatalog:
    def __init__(self, root: Path):
        self.root = root
        self._cards = self._load()

    def _load(self) -> dict[str, SkillCard]:
        cards: dict[str, SkillCard] = {}
        for skill_yaml in self.root.glob("*/*/skill.yaml"):
            payload = yaml.safe_load(skill_yaml.read_text(encoding="utf-8")) or {}
            name = str(payload.get("name", "")).strip()
            if not name:
                continue
            module = str(payload.get("module", "")).strip() or name.replace("-", "_")
            guide = skill_yaml.parent / "SKILL.md"
            checklist = _read_markdown_list(
                guide,
                fallback=[
                    f"确认 {name} 相关输入面。",
                    f"使用结构化工具验证 {name} 线索。",
                    "仅将已验证结果提升为正式漏洞。",
                ],
            )
            evidence_requirements = payload.get("evidence_requirements", {}).get("required_fields", [])
            if not isinstance(evidence_requirements, list):
                evidence_requirements = []
            support_tools = DEFAULT_TOOL_MAP.get(module, ["http_request", "artifact_capture"])
            cards[name] = SkillCard(
                name=name,
                module=module,
                category=str(payload.get("group", "generic")).strip() or "generic",
                description=str(payload.get("description", "")).strip(),
                checklist=checklist[:8],
                recommended_tools=support_tools,
                verification_requirements=[str(item) for item in evidence_requirements if str(item).strip()],
                followup_routes=list(FOLLOWUP_ROUTE_MAP.get(module, [])),
                triggers=[str(item).strip() for item in payload.get("triggers", []) if str(item).strip()],
                when_to_use=str(payload.get("when_to_use", "")).strip(),
                skip_conditions=[str(item).strip() for item in payload.get("not_for", []) if str(item).strip()],
                decision_prompt=str(payload.get("decision_prompt", "")).strip()
                or f"围绕 {name} 的目标、证据要求和误报规则选择下一步最小有效工具动作。",
                tool_schema_subset=[str(item).strip() for item in payload.get("tool_schema_subset", []) if str(item).strip()]
                or list(support_tools),
                success_criteria=[str(item).strip() for item in payload.get("success_criteria", []) if str(item).strip()]
                or list(STRATEGY_DEFAULTS.get(module, {}).get("success_criteria", ["产生可验证安全信号"])),
                stop_conditions=[str(item).strip() for item in payload.get("stop_conditions", []) if str(item).strip()]
                or list(STRATEGY_DEFAULTS.get(module, {}).get("stop_conditions", ["达到 step budget 或无新进展"])),
                false_positive_rules=[str(item).strip() for item in payload.get("false_positive_rules", []) if str(item).strip()]
                or list(STRATEGY_DEFAULTS.get(module, {}).get("false_positive_rules", ["未验证线索不得进入正式报告"])),
            )
        return cards

    def get(self, name: str) -> SkillCard:
        return self._cards[name]

    def list_baseline(self) -> list[SkillCard]:
        return [self._cards[name] for name in BASELINE_SKILLS if name in self._cards]

    def list_all(self) -> list[SkillCard]:
        return list(self._cards.values())

    def child_policies_for_module(self, module: str) -> list[ChildTaskPolicy]:
        return [item for item in CHILD_TASK_POLICY_MAP.get(module, [])]
