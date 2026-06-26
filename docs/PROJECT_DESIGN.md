# 项目设计文档

本文档对应项目书 7.2 文档验收中的“完整的项目设计文档”，覆盖架构设计、模块接口说明和数据库设计。

## 1. 架构设计

项目采用“同一套核心引擎 + 多任务模式 + 可扩展 Skill/Tool/POC 链路”的结构。页面上的黑盒渗透、前端审计、SQL 注入专项、暴露面审计、认证与权限审计都进入同一个 v2 Agent 引擎。

核心链路如下：

```text
Workbench/API
  -> AgentService
  -> Profile
  -> Task Mode
  -> Planner
  -> Skill/Tool execution
  -> Lead / VerificationRecord / VerifiedFinding
  -> ReportBuilder
  -> JSON / HTML / PDF
```

主要组件：

- `Profile`：声明 Agent 默认角色、模型服务商、模型、预算和默认技能集合。
- `Task Mode`：声明本次任务范围，例如黑盒 Web 渗透、前端 JS 审计、SQL 注入专项。
- `Planner`：根据目标、Profile、任务模式生成执行步骤。
- `Skill`：安全能力单元，例如 SQL 注入检测、XSS 检测、备份文件审计、JS 敏感信息检测。
- `Tool`：实际执行器，负责 HTTP 请求、浏览器上下文验证、POC 生成、沙箱验证等。
- `POC Verify`：将候选线索转化为可验证证据。
- `ReportBuilder`：输出已验证安全报告，包含 JSON、HTML、PDF。

## 2. 任务模式与内部模块映射

页面展示的是任务模式，内部仍复用统一模块能力。

| 任务模式 | 内部能力组合 |
| --- | --- |
| 黑盒 Web 渗透 | recon、sql_scan、sql_bypass、xss_triage、ssrf_triage、permission_bypass、backup_audit_extended、config_audit、js_audit、poc_verify |
| 前端 JS 审计 | js_audit、xss_triage、permission_bypass、poc_verify |
| SQL 注入专项 | sql_scan、sql_bypass、poc_verify |
| 暴露面 / 备份配置审计 | recon、backup_audit_extended、config_audit、js_audit、poc_verify |
| 认证与权限审计 | js_audit、permission_bypass、weak_password、jwt_audit、cors_audit、poc_verify |

## 3. 模块接口说明

### 3.1 API 输入

创建扫描的核心参数：

| 参数 | 说明 |
| --- | --- |
| `target` | 目标 URL |
| `task_mode` | 页面任务模式，优先级高于兼容字段 |
| `module_bundle` | 旧版兼容字段 |
| `profile_name` | Agent Profile 名称 |
| `provider_name` | 模型服务商 |
| `model_id` | 模型 ID |
| `base_url` | 模型服务接口地址 |

### 3.2 扫描状态输出

扫描快照主要包含：

| 字段 | 说明 |
| --- | --- |
| `scan_id` | 扫描 ID |
| `target` | 目标地址 |
| `task_mode` | 当前任务模式 |
| `status` | 执行状态 |
| `stage` | 当前阶段 |
| `plan.steps` | 执行计划 |
| `step_states` | 每个步骤的运行状态 |
| `decision_records` | Agent 决策轨迹 |
| `verification_records` | 验证记录 |
| `verified_findings` | 已验证漏洞 |
| `artifacts` | 运行产物 |
| `report_manifest` | 报告文件路径与 URL |

### 3.3 结果模型

| 模型 | 作用 |
| --- | --- |
| `Lead` | 待验证线索，不能直接进入正式报告主结论 |
| `VerificationRecord` | 验证过程记录，保留 proof、artifact、source |
| `VerifiedFinding` | 已验证漏洞，可进入正式报告主结论 |
| `DecisionRecord` | LLM 或规则决策记录，用于追踪执行原因 |

### 3.4 报告接口

生成报告：

```http
POST /api/scans/{scan_id}/report
```

报告输出：

- `verified_report.json`
- `verified_report.html`
- `verified_report.pdf`

正式报告主结论只接收满足验证门槛的 `VerifiedFinding`。

## 4. 数据库设计

当前项目没有引入传统关系型数据库，采用文件态状态存储，便于课程验收、离线运行和复现实验结果。

### 4.1 当前文件态存储

| 路径 | 说明 |
| --- | --- |
| `runs/<scan_id>/scan_state.json` | 单次扫描完整状态 |
| `runs/<scan_id>/report/verified_report.json` | 结构化报告数据 |
| `runs/<scan_id>/report/verified_report.html` | 可交互 HTML 报告 |
| `runs/<scan_id>/report/verified_report.pdf` | PDF 报告 |
| `runs/<scan_id>/artifacts/` | 截图、POC、沙箱证据等产物 |
| `runs/subagents/<subagent_id>/` | 子 Agent 独立运行状态 |

### 4.2 逻辑数据表设计

如果后续迁移到数据库，可按以下逻辑表建模：

| 表 | 主键 | 主要字段 |
| --- | --- | --- |
| `scans` | `scan_id` | target、task_mode、profile_name、status、stage、created_at、updated_at |
| `scan_steps` | `step_id` | scan_id、name、status、loop_count、started_at、completed_at |
| `decision_records` | `decision_id` | scan_id、step_id、source、reason、tool_name、created_at |
| `leads` | `lead_id` | scan_id、category、severity、title、location、evidence、status |
| `verification_records` | `verification_id` | scan_id、lead_id、method、status、proof_type、evidence_bundle |
| `verified_findings` | `finding_id` | scan_id、category、severity、title、location、verification_id |
| `artifacts` | `artifact_id` | scan_id、kind、path、summary、created_at |
| `reports` | `report_id` | scan_id、json_path、html_path、pdf_path、generated_at |

### 4.3 设计取舍

- 文件态存储降低部署复杂度，适合单机课程环境。
- JSON 状态便于调试、复现和报告生成。
- 后续如需多人协作或长期留存，可将上述逻辑表迁移到 SQLite、PostgreSQL 或 MySQL。
