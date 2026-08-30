# 手机号检测 Agent

这个目录只保留一个功能：中国大陆手机号检测。

执行流程固定为：

```text
用户文本 -> Ollama 选择 detect 工具 -> detect 检查完整原文 -> 返回 has_phone/count
```

Agent 只有一个工具 `detect(text)`，一次运行只允许一次 Tool Call。检测结果不会返回原始手机号，
默认也关闭了可能回显原始输入的 Agent 日志。

## 环境准备

要求 Python 3.10+、Ollama 和一个支持 Tool Calling 的模型。在仓库根目录安装：

```bash
python3 -m pip install -e ".[litellm]"
```

默认配置与服务器一致：

| 环境变量 | 默认值 |
|---|---|
| `SG_OLLAMA_MODEL` | `qwen3.5:9b` |
| `SG_OLLAMA_API_BASE` | `http://127.0.0.1:11436` |
| `SG_OLLAMA_NUM_CTX` | `8192` |
| `SG_OLLAMA_API_KEY` | `ollama` |

先确认服务和模型：

```bash
curl -sS http://127.0.0.1:11436/api/tags
OLLAMA_HOST=http://127.0.0.1:11436 ollama list
```

## 运行

```bash
python examples/sensitiveguard/run_ollama_agent.py "请联系 13800138000"
```

预期结果：

```text
=== Detection result ===
{'has_phone': True, 'count': 1}
```

不传文本时会进入交互输入：

```bash
python examples/sensitiveguard/run_ollama_agent.py
```

## 测试

```bash
python -m pytest tests/sensitiveguard -q
```

测试不连接 Ollama，而是使用固定模型响应验证正则、唯一工具、完整原文绑定以及 Tool Call 失败行为。
