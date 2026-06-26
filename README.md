# Python MVP / Workbench

当前仓库已收口为 **真 AI 漏洞挖掘链路**。

## 交接入口

如果你是新的组员或新的 Codex，**先读这份文档**：

- `C:\Users\ASUS\Desktop\python_mvp\HANDOFF_V2_CODEX.md`

这份文档包含：

- 当前项目真实状态
- 核心代码入口
- xalgorix 对照阅读路径
- 下一阶段详细优化计划
- 可直接复制给新 Codex 的交接提示词

核心目标：

- `LLM -> tool call -> observation -> next action` 的持续闭环
- 主 Agent + LLM child agent 并行探索
- 仅将 `VerifiedFinding` 输出到正式报告
- 默认使用 **DeepSeek** 作为 v2 主 provider

## 1. 当前 v2 能力

- 四阶段主流程：`plan -> step -> step_replan -> final_answer`
- step 内多轮 action / observation 闭环
- child agent 独立上下文、独立预算、独立决策记录
- 结构化结果模型：
  - `Lead`
  - `VerificationRecord`
  - `VerifiedFinding`
  - `DecisionRecord`
- verified-only 报告输出：
  - JSON
  - HTML
  - PDF

已接入代表能力：

- `sql_scan`
- `sql_bypass`
- `xss_triage`
- `ssrf_triage`
- `permission_bypass`
- `backup_audit_extended`
- `config_audit`
- `js_audit`
- `poc_verify`

## 2. 启动

### API / Workbench

```powershell
.\.venv\Scripts\python.exe -m uvicorn ai_security_agent.api.app:app --app-dir .\src --host 127.0.0.1 --port 8000
```

打开：

- `http://127.0.0.1:8000/`

### 一键脚本

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start_workbench.ps1
```

> 之前的一键启动脚本 **仍可继续使用**，但它现在只启动 `v2` Workbench。

## 3. 最短使用路径

### HTTP API

```http
POST /api/scans
{
  "target": "http://127.0.0.1:8765/",
  "profile_name": "blackbox_web"
}
```

```http
POST /api/scans/{scan_id}/continue
```

```http
POST /api/scans/{scan_id}/report
```

### Python

```python
from pathlib import Path
from ai_security_agent.v2 import V2AgentService

service = V2AgentService(project_root=Path("."))
scan = service.create_scan("http://127.0.0.1:8765/")
service.continue_scan(scan["scan_id"])
report = service.generate_report(scan["scan_id"])
print(report["json_path"])
print(report["html_path"])
print(report["pdf_path"])
```

## 4. 报告输出

报告目录：

- `C:\Users\ASUS\Desktop\python_mvp\runs\<scan_id>\report\verified_report.json`
- `C:\Users\ASUS\Desktop\python_mvp\runs\<scan_id>\report\verified_report.html`
- `C:\Users\ASUS\Desktop\python_mvp\runs\<scan_id>\report\verified_report.pdf`

报告主结论只包含 `VerifiedFinding`。

## 5. 测试

最小回归：

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_v2_engine tests.test_v2_api tests.test_api_app tests.test_frontend_static
```

全量：

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## 文档交付物

项目书 7.2 文档验收对应的 Markdown 交付物如下，原项目书 `.docx` 不修改：

- `docs/PROJECT_DESIGN.md`：项目设计文档，包含架构设计、模块接口说明、数据库设计。
- `docs/USER_MANUAL.md`：用户使用手册，包含环境搭建、工具使用、参数说明。
- `docs/DEVELOPER_GUIDE.md`：开发文档，包含模块开发说明、代码注释规范。
- `docs/DOCUMENT_ACCEPTANCE.md`：7.2 文档验收声明，列出验收矩阵和对应文件。

文档验收命令：

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_docs_acceptance
```
