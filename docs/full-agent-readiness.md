# Full Agent Readiness

完整 Agent 模式会检查以下依赖：

- LLM Provider（Ollama / DeepSeek / OpenAI）
- Docker
- sqlmap
- Node、espree、js-beautify
- patool、unrar
- MCP server

## 核心原则

- 完整模式缺关键依赖时直接报错
- 不再静默回退为“看起来跑了”的伪完整模式

## 常见检查项

### Ollama

```powershell
ollama serve
```

### DeepSeek

```powershell
setx DEEPSEEK_API_KEY "你的 API Key"
```

### OpenAI

```powershell
setx OPENAI_API_KEY "你的 API Key"
```

### sqlmap

确认 `sqlmap` 可在命令行直接调用，或在 profile 中配置二进制路径。

### patool / unrar

确认系统可执行文件存在，并已写入对应 profile 配置。
