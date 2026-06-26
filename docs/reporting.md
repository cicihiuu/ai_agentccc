# Reporting

当前仓库只保留当前 Workbench 报告体系。

## 输出格式

`POST /api/scans/{scan_id}/report` 会生成：

- `verified_report.json`
- `verified_report.html`
- `verified_report.pdf`

目录：

- `C:\Users\ASUS\Desktop\python_mvp\runs\<scan_id>\report\`

## 报告原则

- 主结论只包含 `VerifiedFinding`
- `Lead` 仅进入附录
- `VerificationRecord` 作为一级对象展示

## manifest 返回

```json
{
  "scan_id": "...",
  "generated_at": "...",
  "finding_count": 3,
  "json_path": "...",
  "json_url": "...",
  "html_path": "...",
  "html_url": "...",
  "pdf_path": "...",
  "pdf_url": "..."
}
```

## 报告核心字段

- `scan_overview`
- `execution_summary`
- `severity_summary`
- `verified_findings`
- `verification_records`
- `artifacts`
- `attack_paths`
- `appendix.unverified_leads`
