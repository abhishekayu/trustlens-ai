# Local LLM Setup Guide for TrustLens AI

> Run TrustLens with **zero external API calls** using Ollama + open-weight models.

---

## Table of Contents

1. [Install Ollama](#1-install-ollama)
2. [Recommended Models](#2-recommended-models)
3. [Pull & Configure a Model](#3-pull--configure-a-model)
4. [TrustLens Configuration](#4-trustlens-configuration)
5. [Verify the Pipeline](#5-verify-the-pipeline)
6. [Hardware Requirements](#6-hardware-requirements)
7. [Performance Tuning](#7-performance-tuning)
8. [Troubleshooting](#8-troubleshooting)
9. [Fallback Strategy](#9-fallback-strategy)

---

## 1. Install Ollama

### macOS

```bash
brew install ollama
# or download from https://ollama.com/download
```

### Linux

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### Docker

```bash
docker run -d -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama
```

### Verify installation

```bash
ollama --version
curl http://localhost:11434/api/tags  # Should return {"models":[...]}
```

---

## 2. Recommended Models

| Model                    | Size   | VRAM  | JSON Reliability | Speed  | Recommended For       |
| ------------------------ | ------ | ----- | ---------------- | ------ | --------------------- |
| **`llama3`** (8B)        | 4.7 GB | 6 GB  | ★★★★☆            | Fast   | Default, good balance |
| **`llama3.1`** (8B)      | 4.7 GB | 6 GB  | ★★★★★            | Fast   | Best JSON compliance  |
| **`mistral`** (7B)       | 4.1 GB | 6 GB  | ★★★★☆            | Fast   | Good alternative      |
| **`mistral-nemo`** (12B) | 7.1 GB | 10 GB | ★★★★★            | Medium | Best accuracy         |
| **`llama3.1:70b`**       | 40 GB  | 48 GB | ★★★★★            | Slow   | Maximum accuracy      |
| **`gemma2`** (9B)        | 5.4 GB | 8 GB  | ★★★★☆            | Fast   | Good for low VRAM     |

### Model Selection Criteria

For TrustLens, the model **must**:

- Follow structured JSON output instructions reliably
- Handle the `format: "json"` Ollama parameter
- Reason about cybersecurity concepts
- Not hallucinate indicators not present in the input
- Be deterministic with low temperature settings

**Our recommendation: `llama3.1` (8B) for most setups, `mistral-nemo` for higher accuracy.**

---

## 3. Pull & Configure a Model

### Option A: Llama 3.1 (Recommended)

```bash
# Pull the model (4.7 GB download, one-time)
ollama pull llama3.1

# Quick test – should return JSON
ollama run llama3.1 '{"task": "Return a JSON object with key \"status\" and value \"ok\""}' --format json
```

### Option B: Mistral

```bash
ollama pull mistral

# Quick test
ollama run mistral '{"task": "Return a JSON object with key \"status\" and value \"ok\""}' --format json
```

### Option C: Mistral Nemo (Higher Accuracy)

```bash
ollama pull mistral-nemo

# Quick test
ollama run mistral-nemo '{"task": "Return a JSON object with key \"status\" and value \"ok\""}' --format json
```

### Create a Custom Modelfile (Optional, Advanced)

For optimal TrustLens performance, create a custom Modelfile:

````bash
cat > Modelfile.trustlens << 'EOF'
FROM llama3.1

# System message baked into the model
SYSTEM """You are TrustLens-Classifier, a deterministic cybersecurity analysis function. You consume structured webpage telemetry and emit a fixed JSON object. You are NOT a chatbot. You MUST return ONLY valid JSON."""

# Parameters optimised for structured output
PARAMETER temperature 0.05
PARAMETER top_p 0.9
PARAMETER repeat_penalty 1.1
PARAMETER num_predict 4096
PARAMETER seed 42
PARAMETER stop "```"
EOF

# Create the custom model
ollama create trustlens-classifier -f Modelfile.trustlens

# Test it
ollama run trustlens-classifier '{"task": "Return JSON: {\"status\": \"ready\"}"}' --format json
````

Then set in your `.env`:

```ini
TRUSTLENS_OLLAMA_MODEL=trustlens-classifier
```

---

## 4. TrustLens Configuration

### Minimal `.env` for Local LLM

```ini
# AI Provider
TRUSTLENS_AI_PROVIDER=ollama

# Ollama settings
TRUSTLENS_OLLAMA_BASE_URL=http://localhost:11434
TRUSTLENS_OLLAMA_MODEL=llama3.1

# Optional: Use the custom Modelfile
# TRUSTLENS_OLLAMA_MODEL=trustlens-classifier
```

### If Ollama runs on a different machine

```ini
TRUSTLENS_OLLAMA_BASE_URL=http://192.168.1.100:11434
```

### If Ollama runs in Docker alongside TrustLens

```ini
# In docker-compose, use the service name
TRUSTLENS_OLLAMA_BASE_URL=http://ollama:11434
```

### Docker Compose Example

```yaml
version: "3.9"

services:
  trustlens:
    build: .
    ports:
      - "8000:8000"
    environment:
      TRUSTLENS_AI_PROVIDER: ollama
      TRUSTLENS_OLLAMA_BASE_URL: http://ollama:11434
      TRUSTLENS_OLLAMA_MODEL: llama3.1
    depends_on:
      - ollama

  ollama:
    image: ollama/ollama
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    # Uncomment for GPU support:
    # deploy:
    #   resources:
    #     reservations:
    #       devices:
    #         - driver: nvidia
    #           count: 1
    #           capabilities: [gpu]

volumes:
  ollama_data:
```

---

## 5. Verify the Pipeline

### Step 1: Confirm Ollama is Running

```bash
curl -s http://localhost:11434/api/tags | python3 -m json.tool
```

### Step 2: Test JSON Output Directly

```bash
curl -s http://localhost:11434/api/chat -d '{
  "model": "llama3.1",
  "messages": [
    {"role": "system", "content": "Return ONLY valid JSON."},
    {"role": "user", "content": "Analyze this URL for phishing: https://example.com. Return JSON with keys: risk_score (0-100), explanation (string)."}
  ],
  "stream": false,
  "format": "json",
  "options": {"temperature": 0.05, "seed": 42}
}' | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(json.loads(d['message']['content']), indent=2))"
```

### Step 3: Test via TrustLens API

```bash
# Start TrustLens
uvicorn trustlens.main:app --reload &

# Submit a test URL
curl -s -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}' | python3 -m json.tool

# Check health (should show ai_provider: "ollama")
curl -s http://localhost:8000/health | python3 -m json.tool
```

---

## 6. Hardware Requirements

### Minimum (7B/8B models)

| Component      | Requirement                        |
| -------------- | ---------------------------------- |
| RAM            | 8 GB                               |
| CPU            | 4 cores                            |
| GPU            | Not required (CPU inference works) |
| Disk           | 10 GB free                         |
| Inference time | 15-45 seconds per URL (CPU)        |

### Recommended (7B/8B models with GPU)

| Component      | Requirement                              |
| -------------- | ---------------------------------------- |
| RAM            | 16 GB                                    |
| GPU            | 6+ GB VRAM (NVIDIA RTX 3060+, Apple M1+) |
| Disk           | 15 GB free                               |
| Inference time | 3-8 seconds per URL                      |

### For 12B+ models

| Component      | Requirement          |
| -------------- | -------------------- |
| RAM            | 32 GB                |
| GPU            | 10+ GB VRAM          |
| Disk           | 20 GB free           |
| Inference time | 5-15 seconds per URL |

### Apple Silicon Notes

Ollama runs natively on Apple Silicon with Metal GPU acceleration:

- **M1/M2 (8 GB)**: Runs 7B models well
- **M1/M2 Pro (16 GB)**: Runs 7B-12B models comfortably
- **M1/M2 Max/Ultra (32+ GB)**: Can run 70B models

---

## 7. Performance Tuning

### Reduce Latency

```ini
# Use a smaller model
TRUSTLENS_OLLAMA_MODEL=llama3.1

# In the Modelfile, reduce num_predict if responses are slower than needed
PARAMETER num_predict 2048  # Fewer output tokens = faster
```

### Keep Model Loaded (Warm Start)

Ollama unloads models after idle timeout. Keep it loaded:

```bash
# Set keep-alive to 24 hours
curl http://localhost:11434/api/chat -d '{
  "model": "llama3.1",
  "keep_alive": "24h",
  "messages": [{"role": "user", "content": "ping"}],
  "stream": false
}'
```

Or set globally:

```bash
export OLLAMA_KEEP_ALIVE=24h
ollama serve
```

### Parallel Requests

Ollama handles concurrency internally. TrustLens's task queue already limits
concurrent analysis jobs (default: 5). For CPU-only systems, reduce this:

```python
# In main.py lifespan, adjust:
queue = AsyncTaskQueue(max_concurrent=2)  # Lower for CPU-only
```

---

## 8. Troubleshooting

### "Cannot connect to Ollama"

```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# If not, start it
ollama serve

# If it's on a different port
OLLAMA_HOST=0.0.0.0:11434 ollama serve
```

### "Model not found"

```bash
# List installed models
ollama list

# Pull the model
ollama pull llama3.1
```

### "Ollama request timed out"

The model may be too large for your hardware. Try a smaller model:

```bash
ollama pull llama3.1  # 8B, 4.7 GB
# instead of
# ollama pull llama3.1:70b  # 70B, 40 GB
```

### "No valid JSON in model output"

Some models don't respect `format: "json"` perfectly. Solutions:

1. **Use `llama3.1`** – best JSON compliance in our testing
2. **Create a custom Modelfile** (see section 3, Option C)
3. **The validation layer handles this** – TrustLens has multi-layer JSON
   extraction (direct parse → markdown strip → regex) and will retry twice
   before falling back to rule-only scoring

### "AI always returns low scores"

This is **by design**. TrustLens's confidence calibration enforces:

- Default anchor at 0.10 (conservative)
- Ceiling of 0.95 (never claims certainty)
- Sigmoid squashing toward centre
- Evidence-count gating (no evidence → cap at 0.2)

The AI is advisory only (30% weight). This prevents false positives.

---

## 9. Fallback Strategy

TrustLens handles AI failures gracefully with a three-tier fallback:

### Tier 1: Retry with Backoff

- Up to 2 retries with exponential delay (1s, 2s)
- Each retry goes through full validation

### Tier 2: Partial Recovery

- If the AI returned _some_ parseable JSON, salvage valid fields
- Cap all recovered confidence values at 0.3
- Mark result as `[DEGRADED]`

### Tier 3: Rule-Only Mode

- If AI completely fails, return neutral scores (all zeros)
- Score explanation clearly states "AI UNAVAILABLE"
- The 70/30 scoring engine detects this and effectively becomes 100% rule-based
- **No false positives** from AI failure

### Configuration for Unreliable Connections

If your Ollama setup is intermittent, you can reduce AI weight:

```ini
# Reduce AI influence
TRUSTLENS_SCORE_WEIGHT_AI=0.15
TRUSTLENS_SCORE_WEIGHT_RULES=0.85
```

Or disable AI entirely for a pure rule-based engine:

```ini
# Pure rule-based mode (no AI calls)
# Set via API options: {"enable_ai": false}
```

---

## Quick Reference

```bash
# Install Ollama + model in one go
brew install ollama && ollama pull llama3.1

# Start Ollama
ollama serve

# Configure TrustLens
echo 'TRUSTLENS_AI_PROVIDER=ollama
TRUSTLENS_OLLAMA_BASE_URL=http://localhost:11434
TRUSTLENS_OLLAMA_MODEL=llama3.1' > .env

# Run TrustLens
uvicorn trustlens.main:app --reload

# Test
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

---

_All AI analysis is advisory. Rules decide. Evidence explains._
