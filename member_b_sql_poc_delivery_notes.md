# 成员 B（SQL / POC）交付细节说明

## 1. 文档目的

这份文档用于解释当前仓库里“成员 B”负责的 SQL 检测与 POC 验证交付具体做了什么、做到什么程度、如何接入现有主链、现阶段有哪些优点和边界。

这不是泛泛总结，而是基于当前代码和联调结果做的技术说明，适合以下用途：

- 组长验收
- 答辩前自我梳理
- 给其他组员解释成员 B 到底改了什么
- 后续继续扩展时作为交接材料


## 2. 先说结论

结论可以概括为四句话：

- 这份交付是合格的，可以进入当前 `python_mvp` 主链。
- 成员 B 主要增强了两个高风险模块：`sql_scan` 和 `poc_verify`。
- 他没有破坏统一数据结构，也没有重写 Agent 主链、API、报告层。
- 现在的问题主要不在模块逻辑，而在本地 Docker 靶场是否真的跑起来。


## 3. 成员 B 的责任范围

结合项目口径，成员 B 负责的是“SQL 检测与 POC 验证”，不是整套系统。

当前仓库里，这个责任主要落在以下文件：

- `C:\Users\ASUS\Desktop\python_mvp\src\ai_security_agent\modules\sql_scan.py`
- `C:\Users\ASUS\Desktop\python_mvp\src\ai_security_agent\modules\poc_verify.py`
- `C:\Users\ASUS\Desktop\python_mvp\skills\sql_scan.yaml`
- `C:\Users\ASUS\Desktop\python_mvp\skills\poc_verify.yaml`
- `C:\Users\ASUS\Desktop\python_mvp\tests\test_modules.py`
- `C:\Users\ASUS\Desktop\python_mvp\tests\test_agent_stage_5_6_7.py`

也就是说，他负责的是：

- SQL 候选参数识别
- 授权靶场内的受控短验证
- 把 SQL 结果转成可展示的证据链
- 把高危 finding 转成 POC verification record
- 保留人工确认门禁
- 让测试覆盖这条链路

他**不负责**：

- 修改统一 schema
- 改 AgentRuntime 主链
- 改 FastAPI 工作台逻辑
- 改 HTML 报告生成器
- 做公网扫描器
- 做无门禁自动 EXP


## 4. 他实际改了哪些文件

### 4.1 代码文件

1. `C:\Users\ASUS\Desktop\python_mvp\src\ai_security_agent\modules\sql_scan.py`
2. `C:\Users\ASUS\Desktop\python_mvp\src\ai_security_agent\modules\poc_verify.py`

### 4.2 技能说明文件

1. `C:\Users\ASUS\Desktop\python_mvp\skills\sql_scan.yaml`
2. `C:\Users\ASUS\Desktop\python_mvp\skills\poc_verify.yaml`

### 4.3 测试文件

1. `C:\Users\ASUS\Desktop\python_mvp\tests\test_modules.py`
2. `C:\Users\ASUS\Desktop\python_mvp\tests\test_agent_stage_5_6_7.py`


## 5. `sql_scan` 具体做了什么

`sql_scan.py` 是这次交付中最核心的一个文件。

它已经不是之前那种“只给一句占位文案”的演示模块，而是变成了一个**受控的、可解释的 SQL 候选参数发现与短验证模块**。

### 5.1 入口限制

它首先做了一层边界限制：

- 只允许本地或课程靶场目标
- 非 allowlist 目标直接 `skipped`

用到的基础能力来自：

- `C:\Users\ASUS\Desktop\python_mvp\src\ai_security_agent\modules\common.py`

这说明它没有被做成公网扫描器，而是仍然留在课程授权边界内。

### 5.2 页面发现能力

它不再只看单一 URL，而是会做一个**同源、有限深度的小范围 crawl**：

- 最大页数 `max_pages=60`
- 最大深度 `max_depth=3`
- 只抓同源页面
- 自动跳过 `.css`、`.js`、图片、字体、`logout` 等低价值或危险路径

这一层的作用是：即使用户只输入一个首页 URL，它也能在同源范围内尽量找到可能存在 SQL 注入入口的页面。

### 5.3 候选参数提取

它会从三个来源找参数：

1. URL query 参数
2. HTML form 的 input name
3. 页面链接里的 query 参数

并为每个候选参数记录：

- 页面 URL
- 参数名
- 来源（query / form / linked-query）
- 为什么它被认定为候选参数
- 请求方法（GET / POST）

对应的数据结构是：

- `Candidate`

这说明成员 B 做的不只是“扫一下”，而是把每个候选点都变成了**可解释对象**。

### 5.4 候选优先级排序

模块会对候选点打优先级，优先尝试更像 SQLi 的路径和参数，例如：

- URL 中包含 `sqli`、`sql`、`search`
- 参数名是 `id`、`uid`、`keyword`、`search`、`q`

同时降低低价值字段的优先级，例如：

- `password`
- `csrf`
- `captcha`
- `submit`

这意味着它不是“无脑乱试”，而是尽量先碰最有价值的点。

### 5.5 受控短探测

这是这次交付里最关键的增强之一。

它增加了一套**受控、短超时、有限 payload 的验证策略**，包括：

- 单引号探测
- 布尔真/假探测
- 基础 union 探测
- 注释绕过变体
- 大小写混合关键字
- 空白替换变体
- 运算符符号替换
- `BETWEEN` / `LIKE` 变体
- MySQL version comment 变体

这里的重点不是“攻击能力变强”，而是：

- 仍然限制在本地 / 课程靶场
- 仍然是短超时
- 仍然是有限策略
- 目的是提高**证据链质量**

### 5.6 支持 GET 和 POST

它不只支持改 query string，也支持对 form POST 做短探测：

- GET：通过 URL query 发送
- POST：通过 `application/x-www-form-urlencoded` 发送

这是一个明显进步，因为很多 SQLi 入口不在 query，而在表单提交。

### 5.7 输出不是一句话，而是完整 evidence

`sql_scan` 的输出有两种形态：

#### 情况 A：没有确认到明确注入信号

会输出一条“候选参数复核记录”，内容包括：

- 目标
- 入口页抓取情况
- 候选参数数量
- 候选详情
- 如果跑了探测，还会有 probe summary

这时通常：

- `severity = high`
- `verified = false`

#### 情况 B：确认到较强信号

会输出一条更完整的 finding，内容包括：

- Page
- Parameter
- Source
- Reason
- Baseline URL / body
- Quote / boolean / union / bypass 各种长度信息
- Confirmed strategies
- Decision basis
- 可选 sqlmap 增强验证结果

这时通常：

- `severity = high`
- `verified = true`

### 5.8 可选 sqlmap 增强验证

代码里还留了一个可选增强路径：

- 环境变量：`AI_SECURITY_AGENT_SQLMAP`

如果显式开启，它会尝试在本地靶场中调用 `sqlmap.py` 做增强验证。

但这里仍然有边界控制：

- 目标必须是本地 / 课程靶场
- 默认不开
- 超时受限
- 只作为补充，不是默认主流程

这个设计说明成员 B 预留了扩展能力，但没有强行把主链变成“自动化攻击链”。


## 6. `poc_verify` 具体做了什么

`poc_verify.py` 的变化同样很大。

它已经不再是之前那种“拿到 high finding 后只吐一句说明”的占位模块，而是能生成**结构化 POC verification record**。

### 6.1 输入来源

这个模块不是自己独立找漏洞，而是吃主链传入的：

- `context["high_findings"]`

也就是说，`poc_verify` 的输入前提是：

- 上游已经出现高危 finding
- 该 finding 被主链传给它

如果没有 high-risk finding，它会：

- `status = skipped`
- 保留清楚的错误原因

### 6.2 输出结构化验证记录

每条 high-risk finding，`poc_verify` 会生成一个 record，内容包括：

- `Record ID`
- 原始 finding 标题
- 原始严重级别
- 漏洞类型
- 是否识别到 CVE
- replay mode
- 原始位置
- 验证方法
- Reachability check
- Controlled replay
- Manual reproduction steps
- Verification conclusion
- Evidence carried forward
- Risk statement
- Recommended next steps

这意味着它产出的已经不是“备注”，而是接近答辩展示材料的格式。

### 6.3 会尝试解析上游 evidence

它会从 SQL finding 的 evidence 里抽取结构化字段，例如：

- `Page`
- `Parameter`
- `Method`
- `Baseline URL`
- `Confirmed strategies`

这样做的意义是：

- 上游 SQL finding 不需要改 schema
- 下游 `poc_verify` 可以直接消费既有证据文本
- 保持兼容现有 `Finding` 结构

这是这份交付里一个比较聪明的点：**不动 schema，但提升了信息利用率**。

### 6.4 自动识别漏洞类型

它支持按 evidence / location 粗分漏洞类型：

- SQL
- XSS
- CSRF
- SSRF
- XXE
- CVE
- generic

虽然当前课程主线是 SQL/POC，但成员 B 没把实现写死在 SQL 上，而是做成了“类型可扩展”的验证记录器。

### 6.5 安全 replay 机制

它实现了一套**按类型分流的安全 replay 模板**：

- SQL：安全 GET replay，尝试 quote 探测重放
- SSRF：尝试受控本地 URL replay
- XSS：尝试 harmless marker 反射确认
- CSRF：做表单/Token 复核
- XXE：仅给 manual-only 提示
- CVE：按模板做 safe replay 或 fingerprint

需要注意的是，这些 replay 都不是“放开打”，而是有明显限制：

- 本地 / 课程靶场限定
- POST 和复杂交互大量保持 `manual-only`
- XXE 不自动交危险 payload
- CVE 有 allowlist 与开关

### 6.6 CVE 模板能力

它内置了若干 CVE 模板，例如：

- `CVE-2021-41773`
- `CVE-2021-42013`
- `CVE-2022-1388`
- `CVE-2022-22965`
- `CVE-2017-5638`
- `CVE-2023-3519`

并通过以下环境变量控制行为：

- `POC_EXP_ALLOWLIST`
- `POC_ALLOW_ACTIVE_EXP`

默认策略仍然偏保守：

- localhost 默认在 allowlist 中
- active EXP 默认关闭
- 很多模板仍然是 `manual-only`

这说明成员 B 做了“可扩展的 POC 框架雏形”，但没有把它做成危险的自动化利用器。

### 6.7 输出适合报告和答辩

`poc_verify` 的输出是当前交付中最像“答辩展示材料”的部分。

它不仅告诉你“验证过了”，还告诉你：

- 如何复现
- 为什么是这个结论
- 当前是 confirmed、manual-only 还是 needs-review
- 下一步应当做什么


## 7. Skill YAML 做了什么

成员 B 不只改了 Python 模块，也同步维护了 skill 描述文件：

- `C:\Users\ASUS\Desktop\python_mvp\skills\sql_scan.yaml`
- `C:\Users\ASUS\Desktop\python_mvp\skills\poc_verify.yaml`

这里的作用主要有两个：

1. 让 skill 的描述、触发词、检查清单和真实模块行为一致
2. 让主链规划时的风险级别与语义说明更清晰

### 7.1 `sql_scan.yaml`

新增和强化了：

- 更明确的 description
- `sqli` / `database` / `parameter` 等触发词
- 明确写出人审后才执行短探测
- 明确写出可选 sqlmap 增强验证

### 7.2 `poc_verify.yaml`

新增和强化了：

- verification / reproduce / proof 等触发词
- 针对 SQL/XSS/CSRF/SSRF/XXE/CVE 的 checklist
- replay 范围、manual-only 边界和截图要求

### 7.3 一个需要知道的小细节

YAML 里有：

- `requires_approval: true`

但当前主链真正决定人工确认门禁的关键，仍然是：

- `risk_level: high`

也就是说，`requires_approval` 现在更像说明性字段，不是唯一生效点。


## 8. 测试补了什么

这部分是很多组员交付里容易缺失的，但成员 B 这次有补。

### 8.1 `test_modules.py`

增加了两类验证：

1. `sql_scan` 输出里必须出现更具体的 evidence / logs
2. `poc_verify` 在给定高危 finding 上下文时，必须生成结构化 verification record

这证明他不是只改功能，不补测试。

### 8.2 `test_agent_stage_5_6_7.py`

增加了一个关键链路测试：

- 批准 `sql_scan`
- 再批准 `poc_verify`
- 最终 `poc_verify` 必须执行成功
- evidence 中必须出现 `POC verification record`

这个测试非常重要，因为它证明：

- 模块不只是“单测能跑”
- 它和主链的审批逻辑、状态迁移、依赖关系是兼容的


## 9. 它是如何接入主链的

虽然成员 B 没改主链文件，但他的模块已经和主链形成稳定配合。

关键配合关系如下：

### 9.1 规划阶段

`blackbox_pentest` profile 默认启用：

- recon
- backup_audit
- sql_scan
- js_audit
- poc_verify

### 9.2 风险门禁

`sql_scan` 和 `poc_verify` 都是：

- `risk_level = high`

因此主链会要求人工确认。

### 9.3 依赖关系

`poc_verify` 依赖：

- recon
- sql_scan

这保证它不会在 SQL finding 之前乱跑。

### 9.4 重规划触发

当 `sql_scan` 产生高危 finding 后，主链会把：

- `poc_verify`

重新标记为需要人工确认的高风险步骤，再进入下一阶段。

这条链已经在联调 run 中体现出来了。


## 10. 我实际跑出来的联调证据

我已经用当前仓库直接跑过一次非 UI 主链联调，run 文件是：

- `C:\Users\ASUS\Desktop\python_mvp\runs\d4e2c73d-4421-43e4-b5e7-eb7349be98d3.json`

### 10.1 这次联调确认了什么

确认了以下几点：

- `sql_scan` 会在未审批前停住
- 审批 `sql_scan` 后，它会正常执行并写入 finding
- 主链识别到高危 finding 后，会把 `poc_verify` 标成需要确认
- 审批 `poc_verify` 后，它会正常执行并写入 verification record
- 最终报告可以生成

### 10.2 这次联调为什么没有拿到真实 SQL 参数

因为当时本地 `127.0.0.1:8765` 靶场没有正常响应，run 里能看到：

- `Entrypoint fetch: <urlopen error timed out>`

所以这次 `sql_scan` 最终产生的是：

- `SQL injection candidate parameter review`
- `verified = false`
- `location = no confirmed parameter`

但这并不说明模块坏了，只说明：

- 主链和模块逻辑是通的
- live 靶场环境当时没起来

### 10.3 这次联调下 `poc_verify` 的表现

即使 SQL 没抓到真实参数，它仍然成功把上游 finding 转成了结构化记录：

- `POC verification record: SQL injection candidate parameter review`
- `verified = true`

这说明 `poc_verify` 的“记录化能力”已经接上主链了。


## 11. 他没有做什么

这个部分很重要，因为它能帮你判断边界是否被破坏。

成员 B 这次**没有**做下面这些事：

- 没改 `schemas.py`
- 没改 `api/app.py`
- 没改 `api/service.py`
- 没改 `agent/runtime.py`
- 没把系统改成公网扫描器
- 没默认启用危险主动利用
- 没把人工确认门禁删掉

也就是说，这份交付是“增强模块实现”，不是“改系统规则”。


## 12. 我对这份交付的评价

### 12.1 优点

- 方向对：完全落在成员 B 的职责范围内
- 粒度对：主要动模块、技能说明、测试，不乱动主链
- 可交付：evidence 比以前强很多，适合写报告、做答辩
- 可扩展：已经为 SQL 之外的类型留好了 replay 模板骨架
- 可集成：现有主链已验证兼容

### 12.2 不足

- `poc_verify` 范围略大，已经超出“仅 SQL/POC”最小交付面
- 真正 live 靶场下的高质量证据，还依赖本地 Docker Pikachu 正常启动
- `sqlmap` 路径和工具目录现在只是预留，不一定在所有环境都可直接跑

### 12.3 总体判断

如果从课程项目的角度判断，这份交付已经达到：

- **能进总控**
- **能进报告**
- **能进答辩**

如果从“产品化”角度看，它还只是第一版，不是最终版。


## 13. 你可以怎么向别人解释这份交付

如果你需要一句比较像组长口径的话，可以直接这样说：

> 成员 B 没有去改 Agent 主链或统一接口，而是把 `sql_scan` 和 `poc_verify` 从演示占位版提升成了有证据链、有审批门、有报告输出的真实靶场验证模块。`sql_scan` 现在能做候选参数发现和受控短验证，`poc_verify` 能把高危 finding 转成结构化 POC verification record，并且已经通过主链联调证明可集成。


## 14. 后续建议

如果后续还要继续推进，建议按下面顺序做：

1. 先把 Docker Pikachu 8765 环境稳定拉起来
2. 再跑一次 live 联调，拿到真实页面、真实参数、真实截图
3. 把 `sql_scan` 的 confirmed finding 跑出来，而不是只有 candidate review
4. 让 `poc_verify` 复用这条真实 SQL finding，生成更强的最终答辩材料
5. 如有必要，再决定是否继续扩展 CVE / SSRF / XSS 模板


## 15. 一句话结论

成员 B 这次真正做的，不是“补了两段说明文字”，而是把 SQL 检测和 POC 验证这条链，从占位演示，推进成了**可审批、可落盘、可进报告、可继续扩展**的一套模块实现。
