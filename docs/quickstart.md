# Quickstart

> 如果你是新接手项目的组员 / Codex，先读：
>
> `C:\Users\ASUS\Desktop\python_mvp\HANDOFF_V2_CODEX.md`
>
> 再继续本页。

## 1. 启动 Workbench

```powershell
.\.venv\Scripts\python.exe -m uvicorn ai_security_agent.api.app:app --app-dir .\src --host 127.0.0.1 --port 8000
```

或：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start_workbench.ps1
```

打开：

- `http://127.0.0.1:8000/`

## 2. 最小 API 流程

### 创建扫描

```http
POST /api/scans
Content-Type: application/json

{
  "target": "http://127.0.0.1:8765/",
  "profile_name": "blackbox_web"
}
```

### 单步执行

```http
POST /api/scans/{scan_id}/step
```

### 持续执行

```http
POST /api/scans/{scan_id}/continue
```

### 生成报告

```http
POST /api/scans/{scan_id}/report
```

## 3. 推荐演示顺序

1. 创建扫描
2. 执行 `continue`
3. 观察：
   - `step_states`
   - `subagents`
   - `decision_records`
   - `verification_records`
   - `verified_findings`
4. 生成报告
5. 打开：
   - `verified_report.json`
   - `verified_report.html`
   - `verified_report.pdf`

## 4. 报告位置

- `C:\Users\ASUS\Desktop\python_mvp\runs\<scan_id>\report\verified_report.json`
- `C:\Users\ASUS\Desktop\python_mvp\runs\<scan_id>\report\verified_report.html`
- `C:\Users\ASUS\Desktop\python_mvp\runs\<scan_id>\report\verified_report.pdf`
