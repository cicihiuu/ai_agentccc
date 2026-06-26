from __future__ import annotations

import re
from typing import Mapping


STAGE_LABELS = {
    "plan": "规划阶段",
    "step": "执行阶段",
    "step_replan": "重规划阶段",
    "final_answer": "最终总结阶段",
}

STATUS_LABELS = {
    "pending": "待执行",
    "running": "执行中",
    "ok": "成功",
    "failed": "失败",
    "skipped": "跳过",
    "awaiting": "等待中",
    "not-run": "未执行",
}

RISK_LABELS = {
    "low": "低风险",
    "medium": "中风险",
    "high": "高风险",
}

SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}

REASON_CODE_LABELS = {
    "manual_confirmation_required": "高风险步骤需要人工确认后才能继续执行。",
    "policy_denies_high_risk": "当前策略禁止执行高风险步骤。",
    "demo_only_skips_high_risk": "当前为演示模式，系统已自动跳过高风险步骤。",
    "human_denied": "该步骤已被人工拒绝。",
}

EVENT_TYPE_LABELS = {
    "run_created": "任务已创建",
    "intent_built": "任务意图已生成",
    "plan_created": "执行计划已生成",
    "planning_deferred": "已延后 LLM 规划",
    "llm_plan_enrichment_started": "LLM 规划增强开始",
    "llm_plan_enrichment_completed": "LLM 规划增强完成",
    "batch_start": "批量执行开始",
    "step_started": "步骤开始",
    "step_completed": "步骤完成",
    "step_failed": "步骤失败",
    "human_gate_waiting": "等待人工确认",
    "human_gate_approved": "人工已批准",
    "human_gate_denied": "人工已拒绝",
    "replan_completed": "重规划完成",
    "llm_warning": "LLM 警告",
    "llm_fallback_rule_based": "已回退到规则模式",
    "final_answer_created": "最终结果已生成",
    "graph_node": "图节点执行",
}

MODE_LABELS = {
    "rule_based": "规则模式",
    "llm_assisted": "LLM 辅助模式",
    "full_agent": "完整 Agent 模式",
}

PROVIDER_STATUS_LABELS = {
    "disabled": "未启用",
    "rule_based": "规则模式未使用",
    "ready": "可用",
    "missing_env": "缺少环境变量",
    "fallback": "已回退",
}

_KIND_MAP: dict[str, Mapping[str, str]] = {
    "stage": STAGE_LABELS,
    "status": STATUS_LABELS,
    "risk": RISK_LABELS,
    "severity": SEVERITY_LABELS,
    "reason_code": REASON_CODE_LABELS,
    "event_type": EVENT_TYPE_LABELS,
    "mode": MODE_LABELS,
    "provider_status": PROVIDER_STATUS_LABELS,
}

EXACT_MESSAGE_MAP = {
    "target is required": "缺少目标地址。",
    "scan target is required": "缺少目标地址。",
    "run not found": "未找到对应任务。",
    "plan must be created before step": "必须先完成规划阶段才能执行步骤。",
    "plan must be created before step_replan": "必须先完成规划阶段才能执行重规划。",
    "run is not complete": "当前任务尚未执行完成，暂时不能生成报告。",
    "agent state is not initialized": "任务状态尚未初始化。",
    "no ready step": "当前没有可执行步骤。",
    "llm provider is not configured": "未配置可用的 LLM Provider。",
    "manual confirmation denied": "人工已拒绝该步骤。",
    "manual confirmation required": "高风险步骤需要人工确认后才能继续执行。",
    "manual confirmation pending": "人工确认尚未完成。",
    "ollama returned an empty response": "Ollama 返回了空内容。",
    "only localhost or course lab targets are allowed": "仅允许针对 localhost 或课程实验目标运行。",
}

PHRASE_MAP = {
    "Target entrypoint and baseline metadata": "目标入口与基线元数据",
    "Backup filename risk checklist": "备份文件名风险检查清单",
    "Config audit review checklist": "配置审计检查清单",
    "Permission bypass review checklist": "权限绕过检查清单",
    "Detected suspicious sinks": "检测到可疑 sink",
    "Support Skills": "辅助 Skills",
    "Runnable Skills": "可执行 Skills",
    "Target": "目标",
    "Profile": "Agent Profile（引擎配置）",
    "Frontend JavaScript review checklist": "前端 JavaScript 审计检查清单",
    "Backup-derived JavaScript follow-up scope": "基于备份线索的 JavaScript 后续审计范围",
    "Backup-derived SQL follow-up scope": "基于备份线索的 SQL 后续审计范围",
    "Backup-derived SSRF follow-up scope": "基于备份线索的 SSRF 后续审计范围",
    "Backup-derived XSS follow-up scope": "基于备份线索的 XSS 后续审计范围",
    "Keep the screenshot trail": "保留截图轨迹",
    "Verification conclusion": "验证结论",
    "Needs manual follow-up": "需要人工跟进",
    "No high-confidence": "未发现高置信结果",
    "SQL injection candidate parameter review": "SQL 注入候选参数复核",
    "SQL injection candidate inventory": "SQL 注入候选参数清单",
    "SQL bypass assessment recorded": "SQL 绕过评估已记录",
    "Manual POC case": "人工 POC 验证用例",
    "Sandbox verified": "沙箱验证通过",
    "JavaScript auxiliary assessment": "JavaScript 辅助评估",
    "Verified finding": "已验证漏洞",
}

MOJIBAKE_MAP = {
    "浠诲姟宸插垱寤": "任务已创建",
    "浠诲姟鎰忓浘宸茬敓鎴": "任务意图已生成",
    "鎵ц璁″垝宸茬敓鎴": "执行计划已生成",
    "宸插欢鍚": "已延后",
    "瑙勫垝": "规划",
    "鎵ц": "执行",
    "閲嶈鍒": "重规划",
    "鏈€缁堢粨鏋": "最终结果",
    "绛夊緟浜哄伐纭": "等待人工确认",
    "浜哄伐宸叉壒鍑": "人工已批准",
    "浜哄伐宸叉嫆缁": "人工已拒绝",
    "宸插洖閫€鍒拌鍒欐ā寮": "已回退到规则模式",
    "鍙户缁墽琛": "可继续执行",
    "鏆傛棤鍙墽琛屾楠": "暂无可执行步骤",
    "浠诲姟宸插畬鎴": "任务已完成",
    "褰撳墠鏈": "当前有",
    "涓彲鎵ц姝ラ": "个可执行步骤",
    "鏈鎸佺画鎵ц宸叉殏鍋": "本次持续执行已暂停",
    "鏈宸叉墽琛": "本次已执行",
    "鏂板": "新增",
    "涓ā鍧楃粨鏋": "个模块结果",
    "浠诲姟鐘舵€佸凡鍒锋柊": "任务状态已刷新",
    "完整 Agent 模式依赖未就绪": "完整 Agent 模式依赖未就绪",
    "LLM Provider 鍒濆鍖栧け璐": "LLM Provider 初始化失败",
    "LLM 鏈惎鐢": "LLM 未启用",
    "请先在系统环境变量中设置": "请先在系统环境变量中设置",
    "PowerShell 示例": "PowerShell 示例",
    "你的 API Key": "你的 API Key",
    "不要在页面输入真实 API Key": "不要在页面输入真实 API Key",
    "链褰": "未记录",
    "鏈彁渚涘缓璁": "未提供建议",
    "鍙戠敓鏈鏈熼敊璇": "发生未预期错误",
}


def provider_env_help(env_var: str) -> str:
    env_name = (env_var or "API_KEY").strip()
    return (
        f"请先在系统环境变量中设置 {env_name}，然后重新打开终端并重启工作台。\n"
        "PowerShell 示例：\n"
        f'setx {env_name} "你的 API Key"\n'
        "不要在页面输入真实 API Key。"
    )


def to_user_label(kind: str, value: str) -> str:
    normalized = (value or "").strip()
    return _KIND_MAP.get(kind, {}).get(normalized, normalized)


def to_user_title(text: str) -> str:
    title = (text or "").strip()
    if not title:
        return title
    patterns = (
        (r"^SQL injection evidence candidate:\s*(.+)$", r"SQL 注入证据候选参数：\1"),
        (r"^SQL injection candidate parameter review$", "SQL 注入候选参数复核"),
        (r"^SQL injection candidate inventory$", "SQL 注入候选参数清单"),
        (r"^SQL bypass assessment:\s*(.+)$", r"SQL 绕过评估：\1"),
        (r"^SQL bypass assessment for parameter:\s*(.+)$", r"SQL 绕过评估参数：\1"),
        (r"^Manual POC case for\s*(.+)$", r"人工 POC 验证用例：\1"),
        (r"^Sandbox verified:\s*(.+)$", r"沙箱验证通过：\1"),
        (r"^JavaScript auxiliary assessment$", "JavaScript 辅助评估"),
        (r"^Verified finding$", "已验证漏洞"),
    )
    for pattern, replacement in patterns:
        updated = re.sub(pattern, replacement, title, flags=re.IGNORECASE)
        if updated != title:
            return updated
    return title


def to_user_message(text: str, *, fallback: str = "发生未预期错误，请查看详细日志。") -> str:
    if not text:
        return fallback

    message = text.strip()
    exact = EXACT_MESSAGE_MAP.get(message.lower())
    if exact:
        return exact

    if "DEEPSEEK_API_KEY" in message and ("missing" in message.lower() or "环境变量" in message):
        return provider_env_help("DEEPSEEK_API_KEY")
    if "TOKENHUB_API_KEY" in message and ("missing" in message.lower() or "环境变量" in message):
        return provider_env_help("TOKENHUB_API_KEY")

    translated = message
    for source, target in PHRASE_MAP.items():
        translated = translated.replace(source, target)
    for source, target in MOJIBAKE_MAP.items():
        translated = translated.replace(source, target)
    return translated
