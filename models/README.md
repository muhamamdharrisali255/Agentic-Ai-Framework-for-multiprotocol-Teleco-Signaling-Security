# Local models

Optional weights for full local LLM inference:

| Path | Hub |
| --- | --- |
| `Qwen2.5-14B-Instruct/` | `Qwen/Qwen2.5-14B-Instruct` |
| `Qwen-telecom-chatbot-model/` | `ligaments-dev/Qwen-telecom-chatbot-model` |
| `Qwen3-Reranker-0.6B/` | `Qwen/Qwen3-Reranker-0.6B` |

```bash
huggingface-cli download Qwen/Qwen2.5-14B-Instruct --local-dir models/Qwen2.5-14B-Instruct
```

Set `LLM_MODEL_PATH` / `EMBEDDING_MODEL` in `.env`. `python test/reproduce.py` does not require these downloads.
