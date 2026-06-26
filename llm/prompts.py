from __future__ import annotations

from typing import Any


def build_intent_prompt(target: str, task: str, profile: Any) -> str:
    task_text = task.strip() or f"对目标 {target} 执行 {profile.role} 场景下的安全分析。"
    return f"""你是一个网络安全 AI Agent 的任务理解器。请把输入任务整理成中文摘要，并输出严格 JSON：
{{
  "goal": "中文任务目标",
  "constraints": ["中文约束1"],
  "user_scope": "中文范围说明",
  "entry_mode": "url_only 或 task_plus_target"
}}

目标地址：{target}
任务配置：{profile.name}
角色：{profile.role}
原始任务：{task_text}

不要输出任何 JSON 之外的说明。
"""


def build_json_repair_prompt(raw_text: str, schema_hint: str) -> str:
    return f"""下面是一段本应为 JSON 的模型输出，但格式损坏了。请仅输出修复后的 JSON 对象，不要附加解释。

Schema 提示：
{schema_hint}

原始内容：
{raw_text}
"""


def build_planner_prompt(intent: Any, profile: Any, skills: list[Any]) -> str:
    skill_lines = "\n".join(
        f"- skill={skill.name}; module={skill.module}; risk={skill.risk_level}; when={skill.when_to_use}; not_for={', '.join(skill.not_for[:2]) or '无'}"
        for skill in skills
    )
    return f"""你是一个受控网络安全智能体规划器。请基于任务目标和可用技能，输出严格 JSON：
{{
  "steps": [
    {{"module": "recon", "reason": "中文原因"}}
  ],
  "planner_explanation": "中文解释"
}}

任务目标：{intent.goal}
目标地址：{intent.target}
范围约束：{"; ".join(intent.constraints) or "无额外约束"}
任务配置：{profile.name}
可用技能：
{skill_lines}

只能选择以上 module，说明必须是中文，不要输出 JSON 之外的文字。
"""


def build_step_prompt(intent: Any, step: Any, context: dict, profile: Any) -> str:
    context_keys = ", ".join(sorted(context.keys()))
    return f"""你正在执行一个受控网络安全智能体步骤。输出严格 JSON：
{{
  "thought": "中文思考摘要",
  "actions": [
    {{"tool": "run_module_action", "arguments": {{"module": "{step.module}"}}}}
  ],
  "decision": "中文阶段结论"
}}

任务：{intent.goal}
目标：{intent.target}
当前步骤：{step.module}
步骤原因：{step.reason}
任务配置：{profile.name}
上下文键：{context_keys or "无"}

所有面向用户的文字必须是中文。若无法给出更优动作，请保留默认的 run_module_action。
不要输出 JSON 之外的内容。
"""


def build_replan_prompt(intent: Any, completed_summary: list[str], pending_modules: list[str]) -> str:
    return f"""你是受控网络安全智能体的重规划器。请输出严格 JSON：
{{
  "should_replan": true,
  "reason": "中文原因",
  "deferred_items": ["中文待办"],
  "advice": "中文建议"
}}

任务：{intent.goal}
已完成摘要：
{chr(10).join('- ' + item for item in completed_summary) or '- 暂无'}
待执行模块：{", ".join(pending_modules) or "无"}

不要输出 JSON 之外的内容。
"""


def build_final_review_prompt(intent: Any, module_summaries: list[str]) -> str:
    return f"""你是 AI Report Reviewer。请检查当前任务是否存在明显遗漏，并输出严格 JSON：
{{
  "review_notes": [
    {{"level": "info", "message": "中文审阅意见", "resolved": true}}
  ],
  "final_summary": "中文最终总结"
}}

任务目标：{intent.goal}
模块摘要：
{chr(10).join('- ' + item for item in module_summaries) or '- 暂无'}

不要输出 JSON 之外的内容。
"""
