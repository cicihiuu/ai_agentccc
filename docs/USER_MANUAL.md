# 用户使用手册

本文档对应项目书 7.2 文档验收中的“用户使用手册”，覆盖环境搭建、工具使用和参数说明。

## 1. 环境搭建

### 1.1 Python 环境

推荐使用项目自带虚拟环境：

```powershell
.\.venv\Scripts\python.exe --version
```

如需重新安装依赖：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 1.2 模型服务配置

项目支持通过 Profile 配置模型服务商。常见配置项：

| 配置 | 说明 |
| --- | --- |
| `provider_name` | 模型服务商，例如 deepseek、ollama、openai_compatible |
| `model_id` | 模型名称 |
| `base_url` | OpenAI-compatible 接口地址 |
| API Key | 通过环境变量配置，不在页面输入真实密钥 |

PowerShell 环境变量示例：

```powershell
setx DEEPSEEK_API_KEY "你的 API Key"
```

设置后需要重新打开终端。

### 1.3 靶场准备

支持本地靶场或课程授权靶场。常见示例：

| 靶场 | 示例地址 |
| --- | --- |
| Pikachu | `http://127.0.0.1:8765/` |
| DVWA | `http://127.0.0.1:8764/` |

## 2. Workbench 启动

推荐启动脚本：

```powershell
.\scripts\start_workbench.ps1
```

手动启动：

```powershell
.\.venv\Scripts\python.exe -m uvicorn ai_security_agent.api.app:app --app-dir .\src --host 127.0.0.1 --port 8000
```

浏览器打开：

```text
http://127.0.0.1:8000/
```

## 3. 工具使用

### 3.1 页面使用流程

1. 选择任务模式。
2. 输入目标地址。
3. 选择 Agent Profile。
4. 确认模型服务商、模型和接口地址。
5. 点击启动扫描。
6. 点击执行一步或并发持续执行。
7. 等待扫描完成。
8. 生成已验证报告。
9. 查看 HTML、PDF、JSON 报告。

### 3.2 任务模式说明

| 任务模式 | 适用场景 |
| --- | --- |
| 黑盒 Web 渗透 | 综合扫描，覆盖 SQL、XSS、SSRF、权限、备份、配置等 |
| 前端 JS 审计 | 关注 JS 敏感信息、DOM/XSS、前端派生接口 |
| SQL 注入专项 | 重点验证 SQL 注入和绕过能力 |
| 暴露面 / 备份配置审计 | 关注备份文件、配置泄露、入口发现 |
| 认证与权限审计 | 关注弱口令、JWT、CORS、IDOR、权限绕过 |

### 3.3 API 使用流程

创建扫描：

```http
POST /api/scans
Content-Type: application/json

{
  "target": "http://127.0.0.1:8765/",
  "task_mode": "blackbox_pentest",
  "profile_name": "blackbox_web"
}
```

执行一步：

```http
POST /api/scans/{scan_id}/step
```

持续执行：

```http
POST /api/scans/{scan_id}/continue
```

生成报告：

```http
POST /api/scans/{scan_id}/report
```

## 4. 参数说明

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `target` | 是 | 目标 URL |
| `task_mode` | 否 | 新任务模式字段，优先级高 |
| `module_bundle` | 否 | 旧兼容字段 |
| `profile_name` | 否 | Agent Profile |
| `provider_name` | 否 | 模型服务商 |
| `model_id` | 否 | 模型 ID |
| `base_url` | 否 | 模型服务接口 |

## 5. 报告查看

报告位于：

```text
runs/<scan_id>/report/
```

文件说明：

| 文件 | 说明 |
| --- | --- |
| `verified_report.html` | 可交互 HTML 报告，详细信息可点击展开 |
| `verified_report.pdf` | PDF 报告，正文精简，详细证据在附录 |
| `verified_report.json` | 结构化原始报告数据 |

## 6. 运行产物清理

查看将清理的文件：

```powershell
.\scripts\clean_generated.ps1 -DryRun
```

执行清理：

```powershell
.\scripts\clean_generated.ps1
```

清理脚本会删除历史运行报告、缓存和临时文件，不删除源码、测试、Profile、Skill、依赖声明。
