from __future__ import annotations

from .models import AgentProfile, ScanPlan, StepBudget, StepSpec, make_id
from .skills import SkillCatalog


STEP_BUDGET_OVERRIDES: dict[str, StepBudget] = {
    "state_bootstrap": StepBudget(max_iterations=2, max_tool_calls=2),
    "recon": StepBudget(max_iterations=6, max_tool_calls=6),
    "backup_audit_extended": StepBudget(max_iterations=4, max_tool_calls=4),
    "config_audit": StepBudget(max_iterations=3, max_tool_calls=3),
    "sql_scan": StepBudget(max_iterations=3, max_tool_calls=3),
    "sql_bypass": StepBudget(max_iterations=3, max_tool_calls=3),
    "js_audit": StepBudget(max_iterations=6, max_tool_calls=6),
    "xss_triage": StepBudget(max_iterations=4, max_tool_calls=4),
    "ssrf_triage": StepBudget(max_iterations=6, max_tool_calls=6),
    "permission_bypass": StepBudget(max_iterations=7, max_tool_calls=7),
    "cors_audit": StepBudget(max_iterations=2, max_tool_calls=2),
    "jwt_audit": StepBudget(max_iterations=2, max_tool_calls=2),
    "weak_password": StepBudget(max_iterations=3, max_tool_calls=3),
    "poc_verify": StepBudget(max_iterations=12, max_tool_calls=12),
}


def build_plan(
    target: str,
    profile: AgentProfile,
    skills: SkillCatalog,
    *,
    module_bundle: str = "full",
    task_mode: str = "",
    task_mode_label: str = "",
) -> ScanPlan:
    cards = [skills.get(name) for name in profile.skill_names]
    steps: list[StepSpec] = []
    completed_name_to_step: dict[str, str] = {}
    for card in cards:
        depends_on: list[str] = []
        if card.module != "state_bootstrap" and "state_bootstrap" in completed_name_to_step:
            depends_on.append(completed_name_to_step["state_bootstrap"])
        if card.module != "recon" and "recon" in completed_name_to_step:
            depends_on.append(completed_name_to_step["recon"])
        if card.module == "config_audit" and "backup_audit_extended" in completed_name_to_step:
            depends_on.append(completed_name_to_step["backup_audit_extended"])
        if card.module == "xss_triage" and "js_audit" in completed_name_to_step:
            depends_on.append(completed_name_to_step["js_audit"])
        if card.module == "sql_bypass" and "sql_scan" in completed_name_to_step:
            depends_on.append(completed_name_to_step["sql_scan"])
        if card.module == "poc_verify":
            for item in ("backup_audit_extended", "config_audit", "sql_scan", "sql_bypass", "xss_triage", "ssrf_triage", "permission_bypass", "cors_audit", "jwt_audit", "weak_password"):
                if item in completed_name_to_step:
                    depends_on.append(completed_name_to_step[item])
        budget = STEP_BUDGET_OVERRIDES.get(
            card.module,
            StepBudget(max_iterations=max(3, profile.max_step_iterations), max_tool_calls=max(4, profile.max_step_iterations + 2)),
        )
        step = StepSpec(
            step_id=make_id("step"),
            name=card.module,
            goal=card.when_to_use or card.description,
            skill_names=[card.name],
            allowed_tools=card.recommended_tools + ["artifact_capture"],
            depends_on=depends_on,
            verification_policy="strict" if card.module == "poc_verify" else "bounded",
            budget=StepBudget(max_iterations=budget.max_iterations, max_tool_calls=budget.max_tool_calls),
            category=card.category,
        )
        steps.append(step)
        completed_name_to_step[card.module] = step.step_id
    return ScanPlan(
        target=target,
        steps=steps,
        profile_name=profile.name,
        module_bundle=module_bundle,
        task_mode=task_mode,
        task_mode_label=task_mode_label,
    )
