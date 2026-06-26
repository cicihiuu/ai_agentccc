# Acceptance

本文档面向当前 `v2-only` 真 AI 漏洞挖掘链路。

## 1. 最小验收命令

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_v2_engine tests.test_v2_api tests.test_api_app tests.test_frontend_static -v
```

全量：

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## 2. 验收点

### 主 Agent

- 存在四阶段：
  - `plan`
  - `step`
  - `step_replan`
  - `final_answer`
- 同一 step 内存在多轮 action / observation
- `decision_records` 可追踪每轮决策来源

### 子 Agent

- 子 Agent 是独立运行单元，不是模块线程池
- 至少可见：
  - `backup-source-audit-child`
  - `js-derived-api-child`
  - `xss-multi-entry-child`
  - `auth-differential-child`
- 子 Agent 具备独立：
  - `decision_records`
  - `llm_fallback_count`
  - `done_reason`

### 结果模型

- 存在：
  - `Lead`
  - `VerificationRecord`
  - `VerifiedFinding`
- 正式报告只接收 `VerifiedFinding`

### 报告

- 一次生成三份：
  - JSON
  - HTML
  - PDF
- manifest 返回：
  - `json_path/json_url`
  - `html_path/html_url`
  - `pdf_path/pdf_url`
- `verification_records` 中包含：
  - `source`
  - `proof_type`
  - `evidence_bundle`

## 3. 演示路径

1. 启动 API / Workbench
2. 创建扫描
3. 执行 `continue`
4. 观察：
   - `step_states`
   - `subagents`
   - `decision_records`
   - `verification_records`
   - `verified_findings`
5. 调用 `report`
6. 打开三份报告

## 4. 预期结果

- 能看到主 Agent 多轮执行
- 能看到 child agent 并行探索
- 能看到 fallback 次数
- 能看到 verified-only 正式报告
- 能从 finding 追到 verification / proof / artifacts / contributing step or child agent

## 5. 7.2 文档验收

项目书 7.2 文档验收不直接修改原 `.docx`，当前项目以内置 Markdown 文档作为验收交付物。

验收声明：

- `docs/DOCUMENT_ACCEPTANCE.md`

对应交付文档：

- `docs/PROJECT_DESIGN.md`：完整的项目设计文档，包含架构设计、模块接口说明、数据库设计。
- `docs/USER_MANUAL.md`：用户使用手册，包含环境搭建、工具使用、参数说明。
- `docs/DEVELOPER_GUIDE.md`：开发文档，包含各模块的开发说明、代码注释规范。

验收命令：

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_docs_acceptance
```
