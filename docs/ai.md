# AI explanations (optional)

AI is strictly an *explainer*. Findings exist with or without it — the
deterministic rules already decided what is risky. AI only turns a finding into
a clearer, friendlier explanation and remediation narrative.

```bash
opsguard scan ./k8s --ai --ai-provider ollama --ai-model llama3
opsguard scan ./k8s --ai --ai-provider gemini   # needs GEMINI_API_KEY
```

## Providers

| Provider | Network | Notes |
|---|---|---|
| `offline` (default) | None | Composes a clear explanation from the finding itself. Deterministic — ideal for air-gapped CI and reproducible tests. |
| `ollama` | Local | Calls a local Ollama server (`OLLAMA_HOST`, default `http://localhost:11434`). Needs the `ai` extra. |
| `gemini` | Remote | Calls Google Gemini (`GEMINI_API_KEY`). Needs the `ai` extra. |

## Graceful degradation

Any provider failure — missing dependency, no API key, timeout, HTTP error, or
an empty response — falls back to the offline explanation. **A scan never breaks
because an LLM was unavailable.**

!!! warning "AI never changes a verdict"
    The AI layer only populates the `ai_explanation` field on a finding. It
    cannot create, suppress, or re-score a finding. This is a hard
    architectural boundary — see [Architecture](architecture.md).
