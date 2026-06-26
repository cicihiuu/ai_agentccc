# 开发文档

本文档对应项目书 7.2 文档验收中的“开发文档”，覆盖模块开发说明和代码注释规范。

## 1. 项目目录结构

| 路径 | 说明 |
| --- | --- |
| `src/ai_security_agent/api/` | FastAPI 工作台接口与静态页面 |
| `src/ai_security_agent/v2/` | v2 Agent 核心引擎、服务、模型、报告 |
| `src/ai_security_agent/modules/` | 安全能力模块 |
| `profiles/` | Agent Profile 声明式配置 |
| `skills/` | Skill 定义 |
| `templates/` | POC 和报告模板 |
| `docs/` | 项目文档 |
| `tests/` | 单元测试与验收测试 |
| `scripts/` | 启动、清理和辅助脚本 |

## 2. 模块开发说明

新增安全模块时应满足以下约定：

1. 模块输入应包含目标地址、上游上下文和必要配置。
2. 模块输出应区分待验证线索、验证记录和已验证漏洞。
3. 不确定结果只能进入 `Lead` 或辅助评估，不能直接进入正式报告主结论。
4. 已验证漏洞必须具备可复现证据、验证方法、来源步骤和证据类型。
5. 模块应支持失败降级，不应因单个模块异常中断整次扫描。

推荐输出结构：

```text
module input
  -> discovery / probe
  -> lead candidates
  -> verification
  -> verification_records
  -> verified_findings
```

## 3. 新增 Profile 方法

Profile 位于 `profiles/`，用于声明不同安全场景下 Agent 的默认角色、模型和预算。

新增 Profile 时应说明：

- Profile 名称
- 适用场景
- 默认模型服务商
- 默认模型
- 最大循环次数
- 最大子 Agent 数
- 默认 Skill 集合

Profile 不等于任务模式。Profile 是引擎配置，任务模式是本次执行范围。

## 4. 新增 Skill / 安全模块方法

新增 Skill 时应补充：

- Skill 名称
- 使用场景
- 输入要求
- 输出结果
- 验证要求
- 误报缓解策略
- 对应测试

如果 Skill 需要接入页面任务模式，应同步更新任务模式到内部模块的映射。

## 5. POC 验证链路接入规范

POC 验证用于将候选线索提升为已验证漏洞。

接入要求：

- POC 必须是可复现的。
- 证据必须绑定 `lead_id` 或来源 finding。
- 验证记录必须包含 `method`、`status`、`proof_type`、`evidence_bundle`。
- 高风险或不可自动执行的步骤应进入人工确认或辅助评估。
- 报告主结论只展示通过验证门槛的 `VerifiedFinding`。

## 6. 报告字段规范

正式报告字段应保持稳定：

| 字段 | 说明 |
| --- | --- |
| `report_version` | 报告版本 |
| `scan_id` | 扫描 ID |
| `target` | 目标地址 |
| `execution_summary` | 执行摘要 |
| `severity_summary` | 严重级别统计 |
| `verified_findings` | 已验证漏洞 |
| `verification_records` | 验证记录 |
| `appendix.unverified_leads` | 待验证线索 |
| `artifacts` | 产物 |

## 7. 测试规范

新增或修改能力时，应优先补充最小相关测试。

常用命令：

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_v2_api
.\.venv\Scripts\python.exe -m unittest tests.test_v2_engine
.\.venv\Scripts\python.exe -m unittest tests.test_modules
.\.venv\Scripts\python.exe -m unittest tests.test_frontend_static
```

文档验收：

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_docs_acceptance
```

## 8. 代码注释规范

代码注释规范：

- 只在意图不明显、存在安全边界、存在兼容策略或非平凡算法时添加注释。
- 不添加重复解释语法的注释。
- 注释应说明“为什么这样做”，而不是复述“代码做了什么”。
- 对外接口、报告字段和兼容字段变更应在文档和测试中同步体现。
- 安全模块中的验证门槛、误报规避和人工确认条件应保持可追踪。
