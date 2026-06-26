from __future__ import annotations

import json
import re
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer

from ai_security_agent.i18n import to_user_title


def _short_text(value: Any, limit: int = 1600) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n..."


SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
    "informational": "提示",
}

CATEGORY_LABELS = {
    "sql_injection": "SQL 注入",
    "sql injection": "SQL 注入",
    "xss": "跨站脚本（XSS）",
    "cross-site scripting": "跨站脚本（XSS）",
    "ssrf": "SSRF",
    "authorization": "权限绕过 / IDOR",
    "backup_source_audit": "备份 / 源码 / 元数据泄露",
    "backup_exposure": "备份文件泄露",
    "config_exposure": "配置泄露",
    "cors": "CORS 配置风险",
    "jwt": "JWT 安全风险",
    "frontend_secret_exposure": "前端敏感信息泄露",
    "frontend secret exposure": "前端敏感信息泄露",
    "js_derived_api": "JS 派生接口",
    "js_auxiliary": "JS 辅助评估",
    "xss_auxiliary": "XSS 辅助评估",
    "backup_auxiliary": "备份文件辅助评估",
}

STATUS_LABELS = {
    "verified": "已验证",
    "manual_required": "需人工确认",
    "manual review": "需人工确认",
    "failed": "失败",
    "pending": "待执行",
    "ok": "成功",
    "completed": "已完成",
    "running": "执行中",
    "blocked": "已阻塞",
}

METHOD_LABELS = {
    "browser_dom_execution_context": "浏览器 DOM 执行上下文",
    "boolean_differential": "布尔差异验证",
    "response_diff": "响应差异验证",
    "docker_poc": "沙箱 POC 验证",
    "static_js_secret_exposure": "静态 JS 敏感信息验证",
}

PROOF_TYPE_LABELS = {
    "browser_capture": "浏览器取证",
    "response_diff": "响应差异",
    "manual_case": "人工验证用例",
    "static_analysis": "静态分析",
}

FIELD_LABELS = {
    "Artifact": "产物数量",
    "Artifact Count": "产物数量",
    "Artifact Type": "产物类型",
    "Baseline URL": "基线 URL",
    "Baseline Value": "基线值",
    "Benchmark": "基准",
    "Completeness": "完整度",
    "Created At": "创建时间",
    "Evidence Kind": "证据类型",
    "Generated At": "生成时间",
    "Group": "分组",
    "Issue": "问题",
    "JS Category": "JS 类别",
    "Lead ID": "线索 ID",
    "Line": "行号",
    "Location": "位置",
    "Masked Sample": "脱敏样本",
    "Method": "方法",
    "Mutated Value": "变更值",
    "Needs Improvement": "待改进",
    "Page": "页面",
    "Parameter": "参数",
    "Passed": "已通过",
    "Passed Categories": "通过类别",
    "Path": "路径",
    "Probe Type": "探测类型",
    "Probe URL": "探测 URL",
    "Proof Type": "证据类型",
    "Report Version": "报告版本",
    "Request URL": "请求 URL",
    "Rule": "规则",
    "Scan ID": "扫描 ID",
    "Script": "脚本",
    "Signature Present": "存在签名",
    "Sink": "Sink",
    "Source": "来源",
    "Status Code": "状态码",
    "Target": "目标地址",
    "Type": "类型",
    "URL": "URL",
    "Verification ID": "验证 ID",
    "Verification Method": "验证方式",
    "Verification Summary": "验证摘要",
}

TITLE_PATTERNS = (
    (r"^SQL injection evidence candidate:\s*(.+)$", r"SQL 注入证据候选参数：\1"),
    (r"^XSS evidence candidate:\s*(.+)$", r"XSS 证据候选参数：\1"),
    (r"^Reflected XSS evidence candidate:\s*(.+)$", r"反射型 XSS 证据候选参数：\1"),
    (r"^SQL bypass assessment$", "SQL 绕过评估"),
    (r"^SQL bypass assessment:\s*(.+)$", r"SQL 绕过评估：\1"),
    (r"^SQL bypass assessment for parameter:\s*(.+)$", r"SQL 绕过评估参数：\1"),
    (r"^Manual POC case(?: for)?\s*(.*)$", r"人工 POC 验证用例：\1"),
    (r"^Sandbox verified:\s*(.+)$", r"沙箱验证通过：\1"),
    (r"^JavaScript auxiliary assessment$", "JavaScript 辅助评估"),
    (r"^Verified finding$", "已验证漏洞"),
)


def _label(value: Any, mapping: dict[str, str]) -> str:
    text = str(value or "").strip()
    return mapping.get(text.lower(), text or "-")


def _field_label(label: str) -> str:
    return FIELD_LABELS.get(label, label)


def _method_label(value: Any) -> str:
    return _label(value, METHOD_LABELS)


def _proof_type_label(value: Any) -> str:
    return _label(value, PROOF_TYPE_LABELS)


def _translate_title(value: Any, fallback: str = "-") -> str:
    title = str(value or fallback).strip() or fallback
    for pattern, replacement in TITLE_PATTERNS:
        updated = re.sub(pattern, replacement, title, flags=re.IGNORECASE)
        if updated != title:
            return updated.rstrip("：")
    translated = to_user_title(title)
    return translated or title


def _translate_list_item(value: Any) -> str:
    return _translate_title(str(value or "").strip())


def _badge(value: Any, *, css: str = "") -> str:
    text = str(value or "-").strip() or "-"
    return f'<span class="badge {escape(css)}">{escape(text)}</span>'


def _kv_block(rows: list[tuple[str, Any]]) -> str:
    visible = [(label, value) for label, value in rows if str(value or "").strip()]
    if not visible:
        return ""
    cells = "".join(f"<div>{escape(_field_label(label))}</div><div>{escape(str(value))}</div>" for label, value in visible)
    return f'<div class="kv">{cells}</div>'


def _list_block(items: Any, *, empty: str = "暂无记录") -> str:
    if not isinstance(items, list):
        return f'<p class="muted">{escape(empty)}</p>'
    rows = [_translate_list_item(item) for item in items if str(item).strip()]
    if not rows:
        return f'<p class="muted">{escape(empty)}</p>'
    return "<ol>" + "".join(f"<li>{escape(item)}</li>" for item in rows) + "</ol>"


def _details_json(title: str, value: Any) -> str:
    if value in ({}, [], None, ""):
        return ""
    return (
        '<details class="detail-block">'
        f"<summary>{escape(title)}</summary>"
        f"<pre>{escape(_short_text(json.dumps(value, ensure_ascii=False, indent=2), 6000))}</pre>"
        "</details>"
    )


def _source_label(source: Any) -> str:
    if not isinstance(source, dict):
        return str(source or "-")
    kind = str(source.get("kind", "")).strip()
    name = str(source.get("name") or source.get("id") or "").strip()
    kind = {"step": "步骤", "agent": "Agent", "module": "模块"}.get(kind.lower(), kind)
    return f"{kind}:{name}" if kind and name else kind or name or "-"


def _artifact_list(artifacts: Any) -> str:
    if not isinstance(artifacts, list) or not artifacts:
        return '<p class="muted">暂无相关产物。</p>'
    rows = []
    for item in artifacts:
        if not isinstance(item, dict):
            continue
        rows.append(
            "<li>"
            f"<strong>{escape(str(item.get('name', '-') or '-'))}</strong>"
            f" / {escape(str(item.get('kind', '-') or '-'))}"
            f"<br><span class=\"mono\">{escape(str(item.get('path', '-') or '-'))}</span>"
            f"<br><span class=\"muted\">{escape(_short_text(_translate_title(item.get('summary', '')), 240))}</span>"
            "</li>"
        )
    return "<ul>" + "".join(rows) + "</ul>" if rows else '<p class="muted">暂无相关产物。</p>'


def _proof_excerpt(record: dict[str, Any]) -> str:
    bundle = record.get("evidence_bundle", {}) if isinstance(record.get("evidence_bundle", {}), dict) else {}
    proof = bundle.get("proof_excerpt") or record.get("summary") or record.get("proof") or ""
    return _short_text(_translate_title(proof), 700)


def _display_title(value: Any, fallback: str = "-") -> str:
    return _translate_title(value, fallback)


def _sql_context_block(item: dict[str, Any]) -> str:
    context = item.get("sql_context", {}) if isinstance(item.get("sql_context", {}), dict) else {}
    if not context:
        return ""
    strategies = context.get("confirmed_strategies", [])
    strategy_items = "".join(f"<li>{escape(str(strategy))}</li>" for strategy in strategies) if isinstance(strategies, list) else ""
    return (
        "<div class=\"kv\">"
        f"<div>Page</div><div>{escape(str(context.get('page', '-') or '-'))}</div>"
        f"<div>Method</div><div>{escape(str(context.get('method', '-') or '-'))}</div>"
        f"<div>Parameter</div><div>{escape(str(context.get('parameter', '-') or '-'))}</div>"
        f"<div>Baseline URL</div><div>{escape(str(context.get('baseline_url', '-') or '-'))}</div>"
        "</div>"
        "<p><strong>已确认策略：</strong></p>"
        f"<ul>{strategy_items or '<li>暂无记录</li>'}</ul>"
    )


def _xss_context_block(item: dict[str, Any]) -> str:
    context = item.get("xss_context", {}) if isinstance(item.get("xss_context", {}), dict) else {}
    if not context:
        return ""
    strategies = context.get("confirmed_strategies", [])
    strategy_items = "".join(f"<li>{escape(str(strategy))}</li>" for strategy in strategies) if isinstance(strategies, list) else ""
    return (
        "<div class=\"kv\">"
        f"<div>Page</div><div>{escape(str(context.get('page', '-') or '-'))}</div>"
        f"<div>Method</div><div>{escape(str(context.get('method', '-') or '-'))}</div>"
        f"<div>Parameter</div><div>{escape(str(context.get('parameter', '-') or '-'))}</div>"
        f"<div>Context</div><div>{escape(str(context.get('context', '-') or '-'))}</div>"
        f"<div>Request URL</div><div>{escape(str(context.get('request_url', '-') or '-'))}</div>"
        "</div>"
        "<p><strong>已确认策略：</strong></p>"
        f"<ul>{strategy_items or '<li>暂无记录</li>'}</ul>"
    )


def _ssrf_context_block(item: dict[str, Any]) -> str:
    context = item.get("ssrf_context", {}) if isinstance(item.get("ssrf_context", {}), dict) else {}
    if not context:
        return ""
    markers = context.get("matched_markers", [])
    marker_items = "".join(f"<li>{escape(str(marker))}</li>" for marker in markers) if isinstance(markers, list) else ""
    return (
        "<div class=\"kv\">"
        f"<div>Page</div><div>{escape(str(context.get('page', '-') or '-'))}</div>"
        f"<div>Method</div><div>{escape(str(context.get('method', '-') or '-'))}</div>"
        f"<div>Parameter</div><div>{escape(str(context.get('parameter', '-') or '-'))}</div>"
        f"<div>Request URL</div><div>{escape(str(context.get('request_url', '-') or '-'))}</div>"
        f"<div>Probe URL</div><div>{escape(str(context.get('probe_url', '-') or '-'))}</div>"
        f"<div>Probe Type</div><div>{escape(str(context.get('probe_type', '-') or '-'))}</div>"
        "</div>"
        "<p><strong>匹配标记：</strong></p>"
        f"<ul>{marker_items or '<li>暂无记录</li>'}</ul>"
    )


def _backup_context_block(item: dict[str, Any]) -> str:
    context = item.get("backup_context", {}) if isinstance(item.get("backup_context", {}), dict) else {}
    if not context:
        return ""
    members = context.get("members", [])
    member_items = "".join(f"<li>{escape(str(member))}</li>" for member in members) if isinstance(members, list) else ""
    return (
        "<div class=\"kv\">"
        f"<div>Path</div><div>{escape(str(context.get('path', '-') or '-'))}</div>"
        f"<div>Status Code</div><div>{escape(str(context.get('status_code', '-') or '-'))}</div>"
        f"<div>Artifact Type</div><div>{escape(str(context.get('artifact_type', '-') or '-'))}</div>"
        f"<div>Evidence Kind</div><div>{escape(str(context.get('evidence_kind', '-') or '-'))}</div>"
        f"<div>Group</div><div>{escape(str(context.get('group_key', '-') or '-'))}</div>"
        "</div>"
        "<p><strong>分组成员：</strong></p>"
        f"<ul>{member_items or '<li>暂无记录</li>'}</ul>"
    )


def _js_context_block(item: dict[str, Any]) -> str:
    context = item.get("js_context", {}) if isinstance(item.get("js_context", {}), dict) else {}
    if not context:
        return ""
    return (
        "<div class=\"kv\">"
        f"<div>Script</div><div>{escape(str(context.get('script', '-') or '-'))}</div>"
        f"<div>Origin</div><div>{escape(str(context.get('origin', '-') or '-'))}</div>"
        f"<div>JS Category</div><div>{escape(str(context.get('category', '-') or '-'))}</div>"
        f"<div>Line</div><div>{escape(str(context.get('line', '-') or '-'))}</div>"
        f"<div>Source</div><div>{escape(str(context.get('source', '-') or '-'))}</div>"
        f"<div>Sink</div><div>{escape(str(context.get('sink', '-') or '-'))}</div>"
        f"<div>API Path</div><div>{escape(str(context.get('api_path', '-') or '-'))}</div>"
        f"<div>Rule</div><div>{escape(str(context.get('rule_id', '-') or '-'))}</div>"
        f"<div>Masked Sample</div><div>{escape(str(context.get('masked_sample', '-') or '-'))}</div>"
        "</div>"
    )


def _permission_context_block(item: dict[str, Any]) -> str:
    context = item.get("permission_context", {}) if isinstance(item.get("permission_context", {}), dict) else {}
    if not context:
        return ""

    def status_line(key: str) -> str:
        probe = context.get(key, {}) if isinstance(context.get(key, {}), dict) else {}
        if not probe:
            return ""
        markers = probe.get("sensitive_markers", []) if isinstance(probe.get("sensitive_markers", []), list) else []
        return f"{key}: HTTP {probe.get('status_code', '-')}, len={probe.get('length', '-')}, markers={','.join(str(item) for item in markers) or 'none'}"

    probe_items = "".join(
        f"<li>{escape(line)}</li>"
        for line in [status_line(key) for key in ("anonymous", "high", "low", "baseline", "mutated")]
        if line
    )
    return (
        "<div class=\"kv\">"
        f"<div>URL</div><div>{escape(str(context.get('url', '-') or '-'))}</div>"
        f"<div>Type</div><div>{escape(str(context.get('type', '-') or '-'))}</div>"
        f"<div>Method</div><div>{escape(str(context.get('method', '-') or '-'))}</div>"
        f"<div>Parameter</div><div>{escape(str(context.get('parameter', '-') or '-'))}</div>"
        f"<div>Baseline Value</div><div>{escape(str(context.get('baseline_value', '-') or '-'))}</div>"
        f"<div>Mutated Value</div><div>{escape(str(context.get('mutated_value', '-') or '-'))}</div>"
        f"<div>Source</div><div>{escape(str(context.get('source', '-') or '-'))}</div>"
        "</div>"
        "<p><strong>差异探测：</strong></p>"
        f"<ul>{probe_items or '<li>暂无记录</li>'}</ul>"
    )


def _jwt_context_block(item: dict[str, Any]) -> str:
    context = item.get("jwt_context", {}) if isinstance(item.get("jwt_context", {}), dict) else {}
    if not context:
        return ""
    payload_keys = context.get("payload_keys", [])
    key_items = "".join(f"<li>{escape(str(key))}</li>" for key in payload_keys) if isinstance(payload_keys, list) else ""
    return (
        "<div class=\"kv\">"
        f"<div>URL</div><div>{escape(str(context.get('url', '-') or '-'))}</div>"
        f"<div>Issue</div><div>{escape(str(context.get('issue', '-') or '-'))}</div>"
        f"<div>Alg</div><div>{escape(str(context.get('alg', '-') or '-'))}</div>"
        f"<div>Type</div><div>{escape(str(context.get('typ', '-') or '-'))}</div>"
        f"<div>Signature Present</div><div>{escape(str(context.get('signature_present', '-')))}</div>"
        "</div>"
        "<p><strong>Payload 字段：</strong></p>"
        f"<ul>{key_items or '<li>暂无记录</li>'}</ul>"
    )


def _render_finding_card(item: dict[str, Any], index: int) -> str:
    evidence_bundle = item.get("evidence_bundle", {}) if isinstance(item.get("evidence_bundle", {}), dict) else {}
    verification = evidence_bundle.get("verification", {}) if isinstance(evidence_bundle.get("verification", {}), dict) else {}
    artifacts = evidence_bundle.get("artifacts", []) if isinstance(evidence_bundle.get("artifacts", []), list) else []
    severity = str(item.get("severity", "info") or "info").lower()
    proof_type = _proof_type_label(item.get("proof_type", ""))
    method = _method_label(verification.get("method", ""))
    evidence = _short_text(item.get("evidence", "-"), 320)
    return f"""
      <section class="item-card">
        <div class="item-head">
          <div>
            <div class="item-index">已验证漏洞 #{index}</div>
            <h3>{escape(_display_title(item.get("title", "-")))}</h3>
          </div>
          <div class="badges">
            {_badge(_label(severity, SEVERITY_LABELS), css=f"severity-{severity}")}
            {_badge(_label(item.get("category"), CATEGORY_LABELS))}
            {_badge(_label(item.get("verification_status", "verified"), STATUS_LABELS), css="status-ok")}
          </div>
        </div>
        {_kv_block([
            ("Location", item.get("location", "")),
            ("Verification Method", method),
            ("Proof Type", proof_type),
            ("Completeness", item.get("completeness_score", "")),
            ("Source", _source_label(item.get("source", {}))),
        ])}
        <div class="summary-line"><strong>关键证据：</strong>{escape(evidence)}</div>
        <details class="detail-block">
          <summary>展开详细证据</summary>
          {_sql_context_block(item)}
          {_xss_context_block(item)}
          {_ssrf_context_block(item)}
          {_backup_context_block(item)}
          {_js_context_block(item)}
          {_permission_context_block(item)}
          {_jwt_context_block(item)}
          <h4>影响</h4>
          <p>{escape(_short_text(item.get("impact", "-"), 900))}</p>
          <h4>关键证据</h4>
          <pre>{escape(_short_text(item.get("evidence", "-"), 1200))}</pre>
          <h4>复现步骤</h4>
          {_list_block(item.get("reproduction_steps", []))}
          <h4>修复建议</h4>
          <p>{escape(_short_text(item.get("recommendation", "-"), 900))}</p>
          <h4>验证与产物</h4>
          {_kv_block([
              ("Verification ID", verification.get("verification_id", "")),
              ("Lead ID", verification.get("lead_id", "")),
              ("Verification Summary", _translate_title(verification.get("summary", ""))),
          ])}
          <h5>产物</h5>
          {_artifact_list(artifacts)}
          {_details_json("完整证据包", evidence_bundle)}
        </details>
      </section>
    """


def _render_verification_card(item: dict[str, Any], index: int, *, title: str = "验证记录") -> str:
    bundle = item.get("evidence_bundle", {}) if isinstance(item.get("evidence_bundle", {}), dict) else {}
    artifacts = bundle.get("artifacts", []) if isinstance(bundle.get("artifacts", []), list) else []
    proof_type = _proof_type_label(item.get("proof_type", ""))
    method = _method_label(item.get("method", ""))
    return f"""
      <section class="item-card compact">
        <div class="item-head">
          <div>
            <div class="item-index">{escape(title)} #{index}</div>
            <h3>{escape(str(item.get("verification_id", "-")))}</h3>
          </div>
          <div class="badges">
            {_badge(method)}
            {_badge(_label(item.get("status", "-"), STATUS_LABELS), css="status-ok" if str(item.get("status", "")).lower() == "verified" else "")}
            {_badge(proof_type)}
          </div>
        </div>
        {_kv_block([
            ("Source", _source_label(item.get("source", {}))),
            ("Lead ID", item.get("lead_id", "")),
            ("Artifact Count", bundle.get("artifact_count", "")),
            ("Completeness", item.get("completeness_score", "")),
        ])}
        <div class="summary-line"><strong>摘要：</strong>{escape(_short_text(_translate_title(item.get("summary", "-")), 320))}</div>
        <details class="detail-block">
          <summary>展开验证详情</summary>
          <h4>证据摘录</h4>
          <pre>{escape(_proof_excerpt(item))}</pre>
          <h4>产物</h4>
          {_artifact_list(artifacts)}
          {_details_json("完整验证记录", item)}
        </details>
      </section>
    """


def _render_lead_card(item: dict[str, Any], index: int) -> str:
    severity = str(item.get("severity", "info") or "info").lower()
    metadata = item.get("metadata", {}) if isinstance(item.get("metadata", {}), dict) else {}
    next_steps = item.get("next_steps", []) if isinstance(item.get("next_steps", []), list) else []
    return f"""
      <section class="item-card compact">
        <div class="item-head">
          <div>
            <div class="item-index">待验证线索 #{index}</div>
            <h3>{escape(_display_title(item.get("title", "-")))}</h3>
          </div>
          <div class="badges">
            {_badge(_label(severity, SEVERITY_LABELS), css=f"severity-{severity}")}
            {_badge(_label(item.get("category", "-"), CATEGORY_LABELS))}
          </div>
        </div>
        {_kv_block([
            ("Location", item.get("location", "")),
            ("Source", _source_label(item.get("source", {}))),
            ("Lead ID", item.get("lead_id", "")),
            ("Created At", item.get("created_at", "")),
        ])}
        <div class="summary-line"><strong>证据摘要：</strong>{escape(_short_text(item.get("evidence", "-"), 320))}</div>
        <details class="detail-block">
          <summary>展开线索详情</summary>
          <h4>判断依据</h4>
          <p>{escape(_short_text(item.get("rationale", "-"), 900))}</p>
          <h4>证据摘要</h4>
          <pre>{escape(_short_text(item.get("evidence", "-"), 1200))}</pre>
          <h4>后续建议</h4>
          {_list_block(next_steps, empty="暂无后续建议")}
          {_details_json("元数据", metadata)}
        </details>
      </section>
    """


def _summary_cards(execution_summary: dict[str, Any], finding_count: int, verification_count: int, unverified_count: int, auxiliary_count: int) -> str:
    rows = [
        ("已验证漏洞", finding_count),
        ("验证记录", verification_count),
        ("待验证线索", unverified_count),
        ("辅助评估", auxiliary_count),
        ("完成步骤", f"{execution_summary.get('completed_steps', 0)} / {execution_summary.get('total_steps', 0)}"),
        ("产物数量", execution_summary.get("artifact_count", 0)),
    ]
    return "".join(
        f'<div class="metric"><span>{escape(label)}</span><strong>{escape(str(value))}</strong></div>'
        for label, value in rows
    )


def _pdf_font_name() -> str:
    font_name = "MicrosoftYaHei"
    font_path = Path(r"C:\Windows\Fonts\msyh.ttc")
    if font_name in pdfmetrics.getRegisteredFontNames():
        return font_name
    if not font_path.exists():
        return "Helvetica"
    try:
        pdfmetrics.registerFont(TTFont(font_name, str(font_path), subfontIndex=0))
        return font_name
    except Exception:
        return "Helvetica"


def _pdf_styles() -> Any:
    styles = getSampleStyleSheet()
    font_name = _pdf_font_name()
    if font_name != "Helvetica":
        for style in styles.byName.values():
            style.fontName = font_name
    styles["Code"].fontSize = 8
    styles["Code"].leading = 10
    return styles


def _pdf_paragraph(text: Any, style: Any) -> Paragraph:
    safe_text = escape(str(text or "-")).replace("\n", "<br/>")
    return Paragraph(safe_text, style)


class ReportBuilder:
    def __init__(self, report_dir: Path, *, base_url: str):
        self.report_dir = report_dir
        self.base_url = base_url.rstrip("/")

    def build(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.report_dir.mkdir(parents=True, exist_ok=True)
        json_path = self.report_dir / "verified_report.json"
        html_path = self.report_dir / "verified_report.html"
        pdf_path = self.report_dir / "verified_report.pdf"

        json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        html_path.write_text(self._render_html(payload), encoding="utf-8")
        self._render_pdf(payload, pdf_path)

        return {
            "scan_id": payload.get("scan_id", ""),
            "generated_at": payload.get("generated_at", datetime.now().astimezone().isoformat(timespec="seconds")),
            "finding_count": int(payload.get("finding_count", 0) or 0),
            "json_path": str(json_path),
            "json_url": f"{self.base_url}/{json_path.name}",
            "html_path": str(html_path),
            "html_url": f"{self.base_url}/{html_path.name}",
            "pdf_path": str(pdf_path),
            "pdf_url": f"{self.base_url}/{pdf_path.name}",
        }

    def _render_html(self, payload: dict[str, Any]) -> str:
        findings = payload.get("verified_findings", [])
        verification_records = payload.get("verification_records", [])
        execution_summary = payload.get("execution_summary", {})
        benchmark_summary = payload.get("benchmark_summary", {})
        coverage_metrics = payload.get("coverage_metrics", {})
        attack_paths = payload.get("attack_paths", [])
        appendix = payload.get("appendix", {})
        unverified_leads = appendix.get("unverified_leads", []) if isinstance(appendix.get("unverified_leads", []), list) else []
        auxiliary_assessments = appendix.get("auxiliary_assessments", []) if isinstance(appendix.get("auxiliary_assessments", []), list) else []

        finding_blocks = "".join(_render_finding_card(item, index) for index, item in enumerate(findings, start=1))
        verification_blocks = "".join(_render_verification_card(item, index) for index, item in enumerate(verification_records, start=1))
        unverified_blocks = "".join(_render_lead_card(item, index) for index, item in enumerate(unverified_leads, start=1))
        auxiliary_blocks = "".join(_render_verification_card(item, index, title="辅助评估") for index, item in enumerate(auxiliary_assessments, start=1))
        attack_path_blocks = "".join(
            f"<li><strong>{escape(_display_title(item.get('name', '-')))}</strong><p>{escape(_short_text(_translate_title(item.get('summary', '-')), 700))}</p></li>"
            for item in attack_paths
            if isinstance(item, dict)
        )
        summary_cards = _summary_cards(
            execution_summary if isinstance(execution_summary, dict) else {},
            len(findings) if isinstance(findings, list) else 0,
            len(verification_records) if isinstance(verification_records, list) else 0,
            len(unverified_leads),
            len(auxiliary_assessments),
        )
        failed_categories = benchmark_summary.get("failed_categories", []) if isinstance(benchmark_summary, dict) else []
        passed_categories = benchmark_summary.get("passed_categories", []) if isinstance(benchmark_summary, dict) else []

        return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>已验证安全报告 - {escape(str(payload.get("scan_id", "")))}</title>
  <style>
    :root {{ --bg:#f4f7fb; --card:#fff; --line:#d8e2ef; --text:#182230; --muted:#667085; --code:#eef4fb; --blue:#175cd3; }}
    body {{ font-family: Arial, 'Microsoft YaHei', sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 28px; line-height: 1.55; }}
    .page {{ max-width: 1180px; margin: 0 auto; display: grid; gap: 18px; }}
    .card {{ background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 20px; box-shadow: 0 8px 24px rgba(16,24,40,.04); }}
    .item-card {{ border: 1px solid var(--line); border-radius: 12px; padding: 16px; margin: 14px 0; background: #fff; }}
    .item-card.compact {{ background: #fbfdff; }}
    .item-head {{ display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; border-bottom: 1px solid #edf2f7; padding-bottom: 10px; margin-bottom: 12px; }}
    .item-index {{ color: var(--blue); font-weight: 700; font-size: 13px; margin-bottom: 4px; }}
    .badges {{ display: flex; gap: 6px; flex-wrap: wrap; justify-content: flex-end; }}
    .badge {{ display: inline-block; border: 1px solid #cfd8e3; border-radius: 999px; padding: 2px 9px; font-size: 12px; background: #f8fafc; color: #344054; }}
    .severity-critical,.severity-high {{ background:#fef3f2; border-color:#fecdca; color:#b42318; }}
    .severity-medium {{ background:#fffaeb; border-color:#fedf89; color:#b54708; }}
    .severity-low,.severity-info {{ background:#eff8ff; border-color:#b2ddff; color:#175cd3; }}
    .status-ok {{ background:#ecfdf3; border-color:#abefc6; color:#067647; }}
    .metrics {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(150px,1fr)); gap: 10px; margin-top: 14px; }}
    .metric {{ background:#f8fafc; border:1px solid #e4e7ec; border-radius: 10px; padding: 12px; }}
    .metric span {{ display:block; color: var(--muted); font-size: 13px; }}
    .metric strong {{ font-size: 22px; }}
    .kv {{ display: grid; grid-template-columns: 150px minmax(0,1fr); gap: 7px 12px; margin: 10px 0; }}
    .kv div:nth-child(odd) {{ color: var(--muted); font-weight: 700; }}
    .kv div:nth-child(even), p, li, h3, .summary-line {{ overflow-wrap: anywhere; word-break: break-word; }}
    .mono {{ font-family: Consolas, 'Courier New', monospace; word-break: break-all; overflow-wrap: anywhere; }}
    .muted {{ color: var(--muted); }}
    .summary-line {{ margin: 10px 0 0; background:#f8fafc; border:1px solid #e4e7ec; border-radius: 10px; padding: 10px 12px; }}
    pre {{ white-space: pre-wrap; word-break: break-word; overflow-wrap: anywhere; background: var(--code); padding: 12px; border-radius: 8px; max-height: 340px; overflow: auto; }}
    details {{ margin-top: 10px; background:#f8fafc; border:1px solid #e4e7ec; border-radius: 10px; padding: 10px 12px; }}
    .detail-block > summary {{ list-style-position: inside; }}
    summary {{ cursor: pointer; font-weight: 700; color:#344054; }}
    h1, h2, h3, h4 {{ margin-top: 0; }}
    h2 {{ border-left: 4px solid var(--blue); padding-left: 10px; }}
    h4 {{ margin-bottom: 6px; margin-top: 14px; color:#344054; }}
  </style>
</head>
<body>
  <div class="page">
    <section class="card">
      <h1>已验证安全报告</h1>
      {_kv_block([
          ("Scan ID", payload.get("scan_id", "-")),
          ("Target", payload.get("target", "-")),
          ("Generated At", payload.get("generated_at", "-")),
          ("Report Version", payload.get("report_version", "-")),
      ])}
      <div class="metrics">{summary_cards}</div>
    </section>
    <section class="card">
      <h2>执行概览</h2>
      {_kv_block([
          ("Benchmark", benchmark_summary.get("manifest_name", "") if isinstance(benchmark_summary, dict) else ""),
          ("Passed", f"{benchmark_summary.get('passed_count', 0)} / {benchmark_summary.get('total_count', 0)}" if isinstance(benchmark_summary, dict) else ""),
          ("Passed Categories", ", ".join(str(item) for item in passed_categories) if isinstance(passed_categories, list) else ""),
          ("Needs Improvement", ", ".join(str(item) for item in failed_categories) if isinstance(failed_categories, list) else ""),
      ])}
      <details class="detail-block">
        <summary>展开完整执行指标</summary>
        <pre>{escape(json.dumps({"execution_summary": execution_summary, "benchmark_summary": benchmark_summary, "coverage_metrics": coverage_metrics}, ensure_ascii=False, indent=2))}</pre>
      </details>
    </section>
    <section class="card">
      <h2>攻击路径</h2>
      <ul>{attack_path_blocks or "<li>暂无记录到链式攻击路径。</li>"}</ul>
    </section>
    <section class="card">
      <h2>已验证漏洞</h2>
      {finding_blocks or "<p>暂无已验证漏洞。</p>"}
    </section>
    <section class="card">
      <h2>验证记录</h2>
      {verification_blocks or "<p>暂无验证记录。</p>"}
    </section>
    <section class="card">
      <h2>辅助评估</h2>
      <p class="muted">辅助评估用于说明策略输出、仅能人工确认的用例和后续跟进种子，不计入已验证漏洞。</p>
      {auxiliary_blocks or "<p>暂无辅助评估。</p>"}
    </section>
    <section class="card">
      <h2>待验证线索</h2>
      <p class="muted">这些项目已在扫描中收集，但尚未满足已验证报告的证据门槛。</p>
      {unverified_blocks or "<p>暂无待验证线索。</p>"}
    </section>
  </div>
</body>
</html>
"""

    def _render_pdf(self, payload: dict[str, Any], output_path: Path) -> None:
        styles = _pdf_styles()
        findings = payload.get("verified_findings", [])
        verification_records = payload.get("verification_records", [])
        execution_summary = payload.get("execution_summary", {})
        benchmark_summary = payload.get("benchmark_summary", {})
        coverage_metrics = payload.get("coverage_metrics", {})
        appendix = payload.get("appendix", {})
        unverified_leads = appendix.get("unverified_leads", []) if isinstance(appendix.get("unverified_leads", []), list) else []

        story = [
            _pdf_paragraph("已验证安全报告", styles["Title"]),
            Spacer(1, 12),
            _pdf_paragraph(f"扫描 ID：{payload.get('scan_id', '-')}", styles["Normal"]),
            _pdf_paragraph(f"目标地址：{payload.get('target', '-')}", styles["Normal"]),
            _pdf_paragraph(f"生成时间：{payload.get('generated_at', '-')}", styles["Normal"]),
            _pdf_paragraph(f"报告版本：{payload.get('report_version', '-')}", styles["Normal"]),
            Spacer(1, 12),
            _pdf_paragraph("执行摘要", styles["Heading2"]),
            _pdf_paragraph(
                f"已验证漏洞：{len(findings) if isinstance(findings, list) else 0}；"
                f"验证记录：{len(verification_records) if isinstance(verification_records, list) else 0}；"
                f"待验证线索：{len(unverified_leads)}；"
                f"完成步骤：{execution_summary.get('completed_steps', 0) if isinstance(execution_summary, dict) else 0} / "
                f"{execution_summary.get('total_steps', 0) if isinstance(execution_summary, dict) else 0}；"
                f"产物数量：{execution_summary.get('artifact_count', 0) if isinstance(execution_summary, dict) else 0}",
                styles["Normal"],
            ),
            Spacer(1, 12),
            _pdf_paragraph("已验证漏洞摘要", styles["Heading2"]),
        ]

        if not findings:
            story.append(_pdf_paragraph("暂无已验证漏洞。", styles["Normal"]))
        for index, finding in enumerate(findings if isinstance(findings, list) else [], start=1):
            severity = _label(finding.get("severity", "-"), SEVERITY_LABELS)
            category = _label(finding.get("category", "-"), CATEGORY_LABELS)
            story.extend(
                [
                    _pdf_paragraph(f"{index}. {_display_title(finding.get('title', '-'))}", styles["Heading3"]),
                    _pdf_paragraph(f"严重级别：{severity}；漏洞类型：{category}", styles["Normal"]),
                    _pdf_paragraph(f"位置：{finding.get('location', '-')}", styles["Normal"]),
                    _pdf_paragraph(f"关键证据：{_short_text(finding.get('evidence', '-'), 360)}", styles["Normal"]),
                    _pdf_paragraph(f"修复建议：{_short_text(finding.get('recommendation', '-'), 360)}", styles["Normal"]),
                    Spacer(1, 8),
                ]
            )

        story.extend([Spacer(1, 12), _pdf_paragraph("待验证线索摘要", styles["Heading2"])])
        if not unverified_leads:
            story.append(_pdf_paragraph("暂无待验证线索。", styles["Normal"]))
        for index, lead in enumerate(unverified_leads, start=1):
            story.extend(
                [
                    _pdf_paragraph(f"{index}. {_display_title(lead.get('title', '-'))}", styles["Heading3"]),
                    _pdf_paragraph(f"位置：{lead.get('location', '-')}", styles["Normal"]),
                    _pdf_paragraph(f"证据摘要：{_short_text(lead.get('evidence', '-'), 360)}", styles["Normal"]),
                    Spacer(1, 8),
                ]
            )

        story.extend([PageBreak(), _pdf_paragraph("附录 A：已验证漏洞详细证据", styles["Heading2"])])
        if not findings:
            story.append(_pdf_paragraph("暂无已验证漏洞详细证据。", styles["Normal"]))
        for index, finding in enumerate(findings if isinstance(findings, list) else [], start=1):
            story.extend(
                [
                    _pdf_paragraph(f"{index}. {_display_title(finding.get('title', '-'))}", styles["Heading3"]),
                    _pdf_paragraph(f"影响：{_short_text(finding.get('impact', '-'), 700)}", styles["Normal"]),
                    _pdf_paragraph(f"完整证据：{_short_text(finding.get('evidence', '-'), 1200)}", styles["Code"]),
                    _pdf_paragraph("复现步骤：", styles["Normal"]),
                    _pdf_paragraph("\n".join(f"- {_translate_list_item(item)}" for item in finding.get("reproduction_steps", []) if str(item).strip()) or "暂无记录", styles["Normal"]),
                    _pdf_paragraph(f"修复建议：{_short_text(finding.get('recommendation', '-'), 700)}", styles["Normal"]),
                    Spacer(1, 10),
                ]
            )

        story.extend([PageBreak(), _pdf_paragraph("附录 B：验证记录", styles["Heading2"])])
        if not verification_records:
            story.append(_pdf_paragraph("暂无验证记录。", styles["Normal"]))
        for index, record in enumerate(verification_records if isinstance(verification_records, list) else [], start=1):
            story.extend(
                [
                    _pdf_paragraph(f"{index}. {record.get('verification_id', '-')}", styles["Heading3"]),
                    _pdf_paragraph(f"验证方式：{_method_label(record.get('method', '-'))}", styles["Normal"]),
                    _pdf_paragraph(f"状态：{_label(record.get('status', '-'), STATUS_LABELS)}", styles["Normal"]),
                    _pdf_paragraph(f"证据摘录：{_proof_excerpt(record)}", styles["Code"]),
                    Spacer(1, 10),
                ]
            )

        story.extend([PageBreak(), _pdf_paragraph("附录 C：待验证线索", styles["Heading2"])])
        if not unverified_leads:
            story.append(_pdf_paragraph("暂无待验证线索。", styles["Normal"]))
        for index, lead in enumerate(unverified_leads, start=1):
            story.extend(
                [
                    _pdf_paragraph(f"{index}. {_display_title(lead.get('title', '-'))}", styles["Heading3"]),
                    _pdf_paragraph(f"判断依据：{_short_text(lead.get('rationale', '-'), 700)}", styles["Normal"]),
                    _pdf_paragraph(f"证据摘要：{_short_text(lead.get('evidence', '-'), 900)}", styles["Code"]),
                    _pdf_paragraph("后续建议：", styles["Normal"]),
                    _pdf_paragraph("\n".join(f"- {_translate_list_item(item)}" for item in lead.get("next_steps", []) if str(item).strip()) or "暂无后续建议", styles["Normal"]),
                    Spacer(1, 10),
                ]
            )

        story.extend(
            [
                PageBreak(),
                _pdf_paragraph("附录 D：原始执行指标", styles["Heading2"]),
                _pdf_paragraph(
                    json.dumps(
                        {
                            "execution_summary": execution_summary,
                            "benchmark_summary": benchmark_summary,
                            "coverage_metrics": coverage_metrics,
                        },
                        ensure_ascii=False,
                        indent=2,
                    ),
                    styles["Code"],
                ),
            ]
        )
        doc = SimpleDocTemplate(str(output_path), pagesize=A4)
        doc.build(story)
