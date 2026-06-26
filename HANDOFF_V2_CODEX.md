# HANDOFF_V2_CODEX

> 这是一份给 **下一位使用 Codex 接手本项目的组员** 的快速交接文档。  
> 目标不是介绍背景，而是让接手者 **最短时间进入有效开发状态**。

---

## 0. 先看什么

如果你是新的 Codex，请按这个顺序进入项目：

1. 先读本文：`C:\Users\ASUS\Desktop\python_mvp\HANDOFF_V2_CODEX.md`
2. 再读项目总说明：`C:\Users\ASUS\Desktop\python_mvp\README.md`
3. 再读快速启动：`C:\Users\ASUS\Desktop\python_mvp\docs\quickstart.md`
4. 跑测试：

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

5. 启动 Workbench：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start_workbench.ps1
```

6. 再开始读核心代码

---

## 1. 你接手的目标是什么

当前项目的最终目标不是“LLM 参与规划”，而是：

> 让 LLM 真正持续参与漏洞挖掘闭环：  
> **观察结果 -> 形成假设 -> 选择动作 -> 调用工具 -> 读取反馈 -> 再次决策 -> 验证 -> 报告**

参考方向来自：

- `C:\Users\ASUS\Desktop\xalgorix-main.zip`

但不是照抄目录结构。真正要借鉴的是：

1. **持续 LLM 工具循环**
2. **原子化工具层**
3. **强报告门禁**
4. **可观测 telemetry**

---

## 2. 当前项目状态（非常重要）

当前仓库已经完成了收口，不要再按 v1 思路改。

### 已完成

1. **v1 对外链路已删除**
   - 不再保留旧 `/api/runs/*`
   - 不再保留旧前端双轨入口
   - 不再保留旧 HTML/PDF 报告链路

2. **只保留当前主链路**
   - API：`/api/scans*`
   - 前端：单一 Workbench 入口
   - 报告：verified-only

3. **主 Step 已是 LLM-first**
   - 主 step 优先尝试 LLM 决策
   - 规则层只作为 fallback / guardrail
   - 已记录 `decision_records`

4. **child agent 已有 LLM child loop**
   - `js-derived-api-child`
   - `xss-multi-entry-child`
   - `auth-differential-child`
   - `backup-source-audit-child` 仍有明显静态成分

5. **报告体系已升级**
   - JSON
   - HTML
   - PDF
   - 正式结论只接受 `VerifiedFinding`

6. **UI 已可演示**
   - 主 Agent / 子 Agent 状态树
   - decision trace
   - verification trace
   - transcript
   - report manifest

7. **默认 provider 已切 DeepSeek**
   - `provider_name: deepseek`
   - `model_id: deepseek-v4-flash`
   - `api_key_env: DEEPSEEK_API_KEY`

8. **测试通过**
   - 当前全量测试通过

---

## 3. 你现在不要做什么

### 不要回退到这些模式

1. 不要把项目改回“LLM 规划，规则执行”
2. 不要恢复 v1 UI / v1 API / v1 报告
3. 不要把 child agent 改回线程池跑模块
4. 不要把报告改成 finding 全量展示
5. 不要优先做产品化外围功能

### 当前第一优先级

> 继续把 v2 做成 **更像 xalgorix 执行模型** 的真实挖洞型 Agent。

---

## 4. 必须先读的项目代码

## 4.1 v2 核心

- `C:\Users\ASUS\Desktop\python_mvp\src\ai_security_agent\v2\models.py`
- `C:\Users\ASUS\Desktop\python_mvp\src\ai_security_agent\v2\engine.py`
- `C:\Users\ASUS\Desktop\python_mvp\src\ai_security_agent\v2\service.py`
- `C:\Users\ASUS\Desktop\python_mvp\src\ai_security_agent\v2\tools.py`
- `C:\Users\ASUS\Desktop\python_mvp\src\ai_security_agent\v2\planner.py`
- `C:\Users\ASUS\Desktop\python_mvp\src\ai_security_agent\v2\skills.py`
- `C:\Users\ASUS\Desktop\python_mvp\src\ai_security_agent\v2\profiles.py`
- `C:\Users\ASUS\Desktop\python_mvp\src\ai_security_agent\v2\reporting.py`

## 4.2 API / UI

- `C:\Users\ASUS\Desktop\python_mvp\src\ai_security_agent\api\app.py`
- `C:\Users\ASUS\Desktop\python_mvp\src\ai_security_agent\api\static\index.html`

## 4.3 默认 profile

- `C:\Users\ASUS\Desktop\python_mvp\profiles\blackbox_web.yaml`

## 4.4 关键测试

- `C:\Users\ASUS\Desktop\python_mvp\tests\test_v2_engine.py`
- `C:\Users\ASUS\Desktop\python_mvp\tests\test_v2_api.py`
- `C:\Users\ASUS\Desktop\python_mvp\tests\test_api_app.py`
- `C:\Users\ASUS\Desktop\python_mvp\tests\test_frontend_static.py`

---

## 5. xalgorix 应该怎么看

不要先看“目录多不多”，要先看“执行模型”。

## 推荐阅读顺序

先解压：

- `C:\Users\ASUS\Desktop\xalgorix-main.zip`

然后重点看：

### 1. 主 Agent 循环

优先找类似：

- `internal/agent/agent.go`

重点看：

- message history 如何组织
- LLM 如何输出 tool call
- tool result 如何回灌
- 下一轮如何继续
- 何时停止

### 2. Tool registry

优先找类似：

- `internal/tools/registry.go`

重点看：

- 工具如何注册
- schema 如何暴露
- 工具结果如何结构化
- 为什么工具粒度小

### 3. report gate

优先看类似：

- `internal/tools/reporting/reporting.go`

重点看：

- 什么时候允许 report
- 什么证据才允许进报告
- 为什么不是“有 finding 就能报”

### 4. telemetry / event

重点看：

- 每轮思考有没有记录
- 工具调用有没有事件
- 最终结果能否回溯路径

---

## 6. 当前项目相对 xalgorix 仍有的差距

## 6.1 主 step 虽然已 LLM-first，但 skill-specific prompt 还不够强

当前：

- 已有 LLM-first
- 已有 decision record

不足：

- prompt 仍偏通用
- 还没做到 skill 级别的精准裁剪

---

## 6.2 child agent 仍保留较重 fallback

当前：

- child 已先走 LLM

不足：

- fallback 逻辑仍偏重
- `backup-source-audit-child` 仍偏静态

---

## 6.3 工具层仍有旧模块桥接痕迹

当前：

- SQL 深逻辑保留下来了
- 一些 triage 仍通过 bridge 复用旧模块

不足：

- 还不是纯原子工具体系
- 仍有“黑盒模块”感

---

## 6.4 Skill 体系还没完全变成“执行策略包”

当前：

- 有 skill / plan / child policy

不足：

- skill 还不够完整表达：
  - decision_prompt
  - tool_schema_subset
  - success_criteria
  - stop_conditions
  - false_positive_rules
  - verification_requirements

---

## 7. 当前最推荐的开发入口

如果你要继续优化，优先从这里开始：

### 第一入口：`engine.py`

看：

- `StepExecutor`
- `LLMDecisionEngine`
- fallback 如何触发
- `DecisionRecord` 如何记录

### 第二入口：`service.py`

看：

- child spawn
- child loop
- report generation
- snapshot 结构

### 第三入口：`tools.py`

看：

- 哪些工具足够原子
- 哪些仍是 bridge
- 哪些还缺能力

---

## 8. 后续详细优化计划（下一任 Codex 的主任务）

下面这部分就是你下一阶段该继续做的事。

---

## Phase 1：强化主 Agent 的真实 LLM 挖洞能力

### 目标

让主 step 从“LLM-first”升级为“LLM skill-guided decision engine”。

### 要做的事

#### 1. skill-specific prompt builder

新增独立构造器，例如：

- `build_step_decision_prompt(...)`
- `build_step_tool_schema_subset(...)`
- `build_step_stop_policy(...)`

目标：

- 不同 skill 给不同 prompt
- 不同 skill 给不同 allowed tools
- 不同 skill 给不同 verification target

#### 2. 决策去重 / 无进展检测

新增：

- 连续相似动作检测
- progress score
- stagnation rounds
- duplicate action ratio

目标：

- 避免 LLM 在 step 里反复试同类动作

#### 3. 更细的 fallback 分类

区分：

- llm unavailable
- invalid json
- tool not allowed
- hallucinated tool
- empty decision
- provider timeout
- provider rate limit

目标：

- 后续可视化更准确
- 错误归因更清晰

---

## Phase 2：继续去规则化 child agent

### 目标

让 child agent 更接近真正的独立 LLM 子循环。

### 要做的事

#### 1. 强化 child task spec

为 child task 增加：

- success criteria
- stop conditions
- verification gap
- already attempted
- output contract

#### 2. 重构 backup child

当前 `backup-source-audit-child` 仍偏静态。

改造方向：

- 保留基础下载 / 解压 / 初筛
- follow-up 决策交给 LLM

例如让 LLM 决定：

- 哪个配置最危险
- 哪个源码入口值得回流
- 是否继续派生 auth/sql/js follow-up

#### 3. child 回流能力增强

child 不应只回 finding，还应回：

- leads
- verification records
- recommended next actions
- route candidates
- session seeds
- endpoint seeds

---

## Phase 3：把工具层继续做深

### 目标

让 LLM 真正有“手和脚”。

### 要做的事

#### 1. HTTP 原语增强

继续补：

- parameter extraction
- form extraction
- link extraction
- replay with mutation
- richer diff

#### 2. Browser 工具增强

补：

- click
- fill
- submit
- execute_js
- dom dump
- console capture
- network capture

#### 3. Auth / Session 工具增强

补：

- save/load/switch/clone session
- token extraction
- same-request different-session replay

#### 4. SSRF / OOB 工具增强

补：

- redirect chain replay
- parser confusion probes
- richer callback evidence

#### 5. SQL 工具继续原子化

继续围绕这些工具深化：

- `discover_sql_candidates`
- `probe_sql_boolean`
- `probe_sql_time`
- `generate_sql_bypass_plan`
- `run_sql_bypass_probe`
- `run_waf_bypass_strategy`
- `run_sqlmap_safe`

要求：

- 返回必须结构化
- 可供下一轮 LLM 直接消费

---

## Phase 4：重建 Skill System

### 目标

让 Skill 不再是说明卡，而是 LLM 可执行策略包。

### 每个 skill 应逐步具备

- decision_prompt
- tool_schema_subset
- checklist
- success_criteria
- stop_conditions
- false_positive_rules
- verification_requirements
- followup_routes

### 优先改的 skill

1. `sql-scan`
2. `sql-bypass`
3. `xss-triage`
4. `ssrf-triage`
5. `permission-bypass`
6. `js-audit`
7. `poc-verify`

---

## Phase 5：继续强化 Verification Gate

### 目标

让 `Lead -> VerificationRecord -> VerifiedFinding` 变成更严格的强类型门禁。

### 要做的事

#### 1. 明确 promotion rule

`VerifiedFinding` 至少应满足：

- 有 verification record
- 有可追踪 proof
- 有 repro steps
- 有 artifacts 或证据摘要

#### 2. 增加 evidence completeness score

维度可包括：

- request/response
- screenshot
- callback
- sandbox proof
- repro steps
- contributing step / child agent

#### 3. 加 false positive guard

例如：

- XSS 不能只因反射就报
- Auth 不能只因 body diff 就报
- SSRF 不能只因参数像 url 就报
- SQL 不能只因 error 就报

---

## Phase 6：继续增强 UI / 答辩演示力

### 目标

让老师/组员一眼看懂“AI 在干什么”。

### 要做的事

1. 强化当前 hypothesis 展示
2. 强化当前 verification gap 展示
3. 强化 fallback trace 展示
4. 强化 child contribution 展示
5. 增加“为什么现在选这个动作”的解释层

---

## Phase 7：补 benchmark / 靶场回归体系

### 目标

避免项目继续迭代后退化。

### 建议靶场分组

1. SQL
2. XSS
3. Auth / IDOR
4. SSRF
5. Backup / Config / JS

### 每类 benchmark 建议断言

- 预期 step
- 预期 child spawn
- 预期 verified findings
- 允许的 fallback 次数
- 报告字段完整性

---

## 9. 运行 / 调试 / 测试

## 9.1 启动

### 方式 A：Workbench

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start_workbench.ps1
```

### 方式 B：直接起 API

```powershell
.\.venv\Scripts\python.exe -m uvicorn ai_security_agent.api.app:app --app-dir .\src --host 127.0.0.1 --port 8000
```

---

## 9.2 测试

### 全量测试

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

### 最小 v2 回归

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_v2_engine tests.test_v2_api tests.test_api_app tests.test_frontend_static -v
```

---

## 9.3 关于 DeepSeek

生产 / 演示默认 profile 已指向 DeepSeek：

- `DEEPSEEK_API_KEY`

注意：

- 当前测试为了稳定与离线回归，会在测试中把复制出来的 profile 改成 `llm_enabled: false`
- 这是**测试策略**，不是产品默认配置

---

## 10. 给下一位 Codex 的明确约束

1. 不要恢复 v1
2. 不要引入新的双轨 UI / API
3. 不要把 child agent 改回规则线程池
4. 不要让报告重新接收未验证 finding
5. 每次修改前后都跑测试
6. 优先做小 diff、可审查 patch
7. 保留 SQL 深逻辑资产，但继续工具化

---

## 11. 可直接复制给下一位 Codex 的提示词

下面这段可以直接复制给新的 Codex：

---

你现在接手的项目根目录是：

`C:\Users\ASUS\Desktop\python_mvp`

参考项目压缩包是：

`C:\Users\ASUS\Desktop\xalgorix-main.zip`

任务书是：

`C:\Users\ASUS\Desktop\基于AI Agent的网络安全工具开发.docx`

请先阅读：

1. `C:\Users\ASUS\Desktop\python_mvp\HANDOFF_V2_CODEX.md`
2. `C:\Users\ASUS\Desktop\python_mvp\README.md`
3. `C:\Users\ASUS\Desktop\python_mvp\docs\quickstart.md`

然后先运行：

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

当前项目状态：

- 已经完成单链路收口
- 旧 `/api/runs/*` 已删除
- 前端是单一 Workbench
- 默认 provider 是 DeepSeek
- 主 step 是 LLM-first
- child agent 已优先走 LLM child loop
- 报告已是 JSON + HTML + PDF
- 报告主结论只允许 `VerifiedFinding`

你当前的任务不是回退兼容，而是继续把项目向 xalgorix 的真实执行模型靠拢：

- 强化主 Agent 的持续 LLM 工具循环
- 继续去规则化 child agent
- 深化工具 schema 与 skill strategy
- 强化 verification gate
- 补 benchmark 与演示能力

优先阅读这些代码：

- `src/ai_security_agent/v2/models.py`
- `src/ai_security_agent/v2/engine.py`
- `src/ai_security_agent/v2/service.py`
- `src/ai_security_agent/v2/tools.py`
- `src/ai_security_agent/v2/reporting.py`
- `src/ai_security_agent/api/app.py`
- `src/ai_security_agent/api/static/index.html`

修改后必须回归测试通过。

---

## 12. 一句话总结

你接手的不是一个“LLM 规划器项目”，而是一个已经开始成型的 **真实 AI 挖洞 Agent**。  
接下来最重要的工作，是继续削弱规则骨架，让 LLM 在 skill 约束下更真实、更稳定地驱动漏洞挖掘。
