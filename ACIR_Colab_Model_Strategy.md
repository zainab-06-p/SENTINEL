# ACIR Platform — Google Colab LLM Strategy & Model Selection Guide

**Document Version:** 1.0  
**Status:** Internal Technical Reference  
**Scope:** Task 2 — Agentic AI Core (LLM Infrastructure Decision)

---

## 1. Why Google Colab Instead of Local Ollama

Running the LLM locally via Ollama requires significant hardware (a 70B model needs ~40GB VRAM). For a development/demo environment, Google Colab is a practical and cost-effective alternative. Here is a direct comparison:

| Factor | Local Ollama | Google Colab |
|---|---|---|
| Setup Time | 30–60 min (driver config, RAM issues) | ~5 min |
| Hardware Required | High-end GPU (16–80GB VRAM) | None — GPU provided free/paid |
| Cost | High (hardware investment) | Free tier available; Pro ~$12/month |
| Data Privacy | 100% air-gapped | Data leaves your machine (**see note below**) |
| Persistence | Permanent | Session resets every 12 hrs (free) |
| Speed | Fast (local NVMe) | Depends on Colab GPU allocation |
| Best For | Production deployment | Development, demos, prototyping |

> **Important Privacy Note:** For the final Barclays production deployment, local Ollama (air-gapped) remains mandatory due to FCA data residency rules. Colab is strictly for development and prototyping. Never send real customer data through Colab.

---

## 2. Recommended Model: Which Size to Use

### The Answer: **7B–8B Parameter Model**

For the ACIR platform during development on Colab, a **7B or 8B parameter model** is the optimal choice. Here is the full reasoning:

### Model Size Comparison Table

| Model | Params | VRAM Needed | Colab Tier | Reasoning Quality | Speed | ACIR Fit |
|---|---|---|---|---|---|---|
| Llama 3.2 3B | 3B | ~3 GB | Free T4 | Basic | Very Fast | Too weak for multi-step ReAct |
| **Llama 3.1 8B** | **8B** | **~6 GB** | **Free T4** | **Good** | **Fast** | **RECOMMENDED** |
| Mistral 7B v0.3 | 7B | ~5 GB | Free T4 | Good | Fast | Strong alternative |
| DeepSeek-R1 7B | 7B | ~5 GB | Free T4 | Excellent (reasoning) | Moderate | Best for chain-of-thought |
| Llama 3.1 70B | 70B | ~40 GB | Colab A100 (Pro+) | Excellent | Slow | Overkill for dev |
| Mixtral 8x7B | 47B | ~26 GB | Colab Pro A100 | Very Good | Moderate | Good if budget allows |

### Why 7B/8B is the sweet spot for ACIR

1. **Fits on Colab Free T4 GPU (16GB VRAM)** — no paid tier required for development.
2. **Sufficient for ReAct reasoning** — 7B+ models reliably follow structured `Thought → Action → Observation` prompting patterns.
3. **JSON output compliance** — 8B models can consistently output structured JSON tool-call responses, which LangGraph depends on.
4. **Speed** — generates a full reasoning chain in 3–8 seconds on T4, acceptable for demo latency.
5. **Fine-tuning friendly** — 7B models can be LoRA fine-tuned on security-specific data later without massive compute.

### Top 3 Recommended Models (in order)

**1. Llama 3.1 8B Instruct** ← Primary recommendation
- Best instruction-following in the 8B class
- Officially supported by LangChain/LangGraph tool-calling
- Meta's open weights, fully open source (Meta Llama License)

**2. DeepSeek-R1 Distill Llama 8B** ← Best reasoning
- Distilled from DeepSeek-R1's reasoning traces
- Superior chain-of-thought, ideal for the "Think" node in your ReAct loop
- Recommended if reasoning quality matters more than raw speed

**3. Mistral 7B Instruct v0.3** ← Lightweight alternative
- Slightly smaller VRAM footprint
- Very fast token generation
- Good fallback if T4 allocation is limited

---

## 3. Architecture Adjustment: Colab as a Remote Inference Server

When using Colab, the LLM does not run on your local machine. You expose it as an API endpoint that your local ACIR pipeline calls. Here is how the architecture shifts:

### Standard Local Architecture
```
[Your Machine] → PyOD Alert → LangGraph Agent → Ollama (local) → Action
```

### Colab-Based Architecture
```
[Your Machine] → PyOD Alert → LangGraph Agent → HTTP Request → [Colab ngrok URL] → LLM → Response
                                                                       ↑
                                                              Colab runs the model
                                                              and exposes it via ngrok
```

The rest of the stack (Elasticsearch, Hyperledger Fabric, FastAPI, Redis, React) still runs locally. Only the LLM inference is offloaded to Colab.

---

## 4. Setting Up the Colab Inference Server

### Step 1 — Open a New Colab Notebook

Go to [colab.research.google.com](https://colab.research.google.com) and create a new notebook.  
Set Runtime: `Runtime → Change runtime type → T4 GPU`

### Step 2 — Install Dependencies in Colab

```python
# Cell 1 — Install required packages
!pip install transformers accelerate bitsandbytes fastapi uvicorn pyngrok nest_asyncio -q
```

### Step 3 — Load the Model (4-bit Quantized to save VRAM)

```python
# Cell 2 — Load Llama 3.1 8B in 4-bit quantization
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig

MODEL_ID = "meta-llama/Meta-Llama-3.1-8B-Instruct"
# Alternative: "deepseek-ai/DeepSeek-R1-Distill-Llama-8B"
# Alternative: "mistralai/Mistral-7B-Instruct-v0.3"

bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.float16,
    bnb_4bit_use_double_quant=True,
)

tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID,
    quantization_config=bnb_config,
    device_map="auto",
    trust_remote_code=True,
)

print("Model loaded. VRAM used:", torch.cuda.memory_allocated() / 1e9, "GB")
```

> **Note on Llama 3.1 Access:** Llama 3.1 requires accepting Meta's license at [huggingface.co/meta-llama](https://huggingface.co/meta-llama) and setting your HuggingFace token in Colab Secrets. DeepSeek-R1 and Mistral are fully gated-free.

### Step 4 — Create a FastAPI Inference Server inside Colab

```python
# Cell 3 — Build the inference API endpoint
import nest_asyncio
from fastapi import FastAPI
from pydantic import BaseModel
from transformers import pipeline
import uvicorn
import threading

nest_asyncio.apply()

app = FastAPI(title="ACIR LLM Inference Server")

# Build generation pipeline
pipe = pipeline(
    "text-generation",
    model=model,
    tokenizer=tokenizer,
    max_new_tokens=512,
    temperature=0.1,          # Low temp for deterministic tool-calling
    do_sample=True,
    repetition_penalty=1.15,
)

class InferenceRequest(BaseModel):
    system_prompt: str
    user_message: str

class InferenceResponse(BaseModel):
    response: str
    model: str = MODEL_ID

@app.get("/health")
def health():
    return {"status": "online", "model": MODEL_ID}

@app.post("/generate", response_model=InferenceResponse)
def generate(req: InferenceRequest):
    messages = [
        {"role": "system", "content": req.system_prompt},
        {"role": "user",   "content": req.user_message},
    ]
    output = pipe(messages)
    generated = output[0]["generated_text"][-1]["content"]
    return InferenceResponse(response=generated)

# Run server in background thread
def run_server():
    uvicorn.run(app, host="0.0.0.0", port=8000)

thread = threading.Thread(target=run_server, daemon=True)
thread.start()
print("Inference server running on port 8000")
```

### Step 5 — Expose via ngrok (Public HTTPS Tunnel)

```python
# Cell 4 — Create public URL with ngrok
from pyngrok import ngrok, conf

# Paste your ngrok authtoken from https://dashboard.ngrok.com/get-started/your-authtoken
NGROK_AUTH_TOKEN = "YOUR_NGROK_TOKEN_HERE"

conf.get_default().auth_token = NGROK_AUTH_TOKEN
public_url = ngrok.connect(8000, "http")

print("=" * 60)
print(f"  ACIR LLM Endpoint: {public_url.public_url}/generate")
print(f"  Health Check:      {public_url.public_url}/health")
print("=" * 60)
print("Copy this URL into your local ACIR config.")
```

---

## 5. Connecting Your Local ACIR Agent to Colab

On your local machine, configure LangChain to call your Colab endpoint instead of Ollama:

### Local Configuration (`config.py`)

```python
# acir_platform/config.py

# --- Switch between local Ollama and Colab ---
LLM_MODE = "colab"   # Options: "local" | "colab"

OLLAMA_BASE_URL    = "http://localhost:11434"
COLAB_ENDPOINT_URL = "https://xxxx-xx-xx-xx-xx.ngrok-free.app"  # Paste from Colab output
MODEL_NAME         = "meta-llama/Meta-Llama-3.1-8B-Instruct"

RISK_THRESHOLD     = 0.95   # Top 5% of anomalies trigger the agent
HITL_TIMEOUT_SECS  = 300    # 5-min window for analyst approval
```

### LangChain LLM Wrapper (`llm_client.py`)

```python
# acir_platform/llm_client.py
import requests
from langchain.llms.base import LLM
from typing import Optional, List
from config import LLM_MODE, COLAB_ENDPOINT_URL, OLLAMA_BASE_URL, MODEL_NAME

class ColabLLM(LLM):
    """LangChain-compatible wrapper for the Colab-hosted inference server."""

    endpoint: str = COLAB_ENDPOINT_URL
    system_prompt: str = "You are a cybersecurity AI agent. Respond only in valid JSON."

    @property
    def _llm_type(self) -> str:
        return "colab_llm"

    def _call(self, prompt: str, stop: Optional[List[str]] = None) -> str:
        payload = {
            "system_prompt": self.system_prompt,
            "user_message": prompt,
        }
        response = requests.post(
            f"{self.endpoint}/generate",
            json=payload,
            timeout=60,
        )
        response.raise_for_status()
        return response.json()["response"]

def get_llm():
    if LLM_MODE == "colab":
        return ColabLLM()
    else:
        # Fallback to local Ollama
        from langchain_community.llms import Ollama
        return Ollama(base_url=OLLAMA_BASE_URL, model="llama3.1:8b")
```

---

## 6. System Prompt for ACIR ReAct Agent

This is the structured prompt that instructs the 8B model to behave as a cybersecurity ReAct agent:

```python
ACIR_SYSTEM_PROMPT = """
You are ACIR-Agent, an autonomous cybersecurity incident response AI.
You operate in a bank's Security Operations Center.

## Your ReAct Loop
Always respond using this exact JSON format:
{
  "thought": "Your internal reasoning about the threat",
  "action": "tool_name",
  "action_input": { "param": "value" },
  "risk_level": "LOW | MEDIUM | HIGH"
}

## Available Tools
- block_ip(ip_address: str) — Blocks an IP at the firewall. Risk: LOW
- isolate_endpoint(hostname: str) — Disconnects a machine from the network. Risk: MEDIUM
- query_elasticsearch(query: str) — Reads logs. Risk: LOW (read-only)
- create_incident_ticket(summary: str) — Creates a SOC ticket. Risk: LOW
- shutdown_server(server_id: str) — Shuts down a server. Risk: HIGH (REQUIRES HUMAN APPROVAL)
- escalate_to_human(reason: str) — Escalates to SOC analyst. Risk: LOW

## Hard Rules (Non-Negotiable)
1. Never recommend shutdown_server without setting risk_level = HIGH
2. Never fabricate IP addresses or hostnames not present in the alert
3. If you are uncertain, always choose escalate_to_human
4. Always explain your thought before choosing an action
"""
```

---

## 7. Colab Session Management & Limitations

| Limitation | Colab Free | Colab Pro ($12/mo) | Workaround |
|---|---|---|---|
| Session timeout | ~12 hours | ~24 hours | Save model weights to Google Drive |
| GPU availability | Not guaranteed | Priority T4/A100 | Use Pro for demo day |
| Concurrent sessions | 1 | 3 | One inference server per agent |
| VRAM | 15 GB (T4) | 40 GB (A100) | Use 4-bit quant on free tier |
| Public URL | ngrok (changes on restart) | Same | Store URL in `.env`, update after restart |

### Keeping Your Session Alive (Anti-Idle Script)

```javascript
// Run this in your browser's DevTools Console (F12) on the Colab tab
// Prevents Colab from disconnecting due to inactivity
function KeepColabAlive() {
  document.querySelector("#connect").click();
  console.log("Keep-alive ping sent: " + new Date().toLocaleTimeString());
}
setInterval(KeepColabAlive, 60000); // Ping every 60 seconds
```

---

## 8. Migration Path: Colab → Production (Local Ollama)

When moving from development to a real bank environment:

```
Phase 1 (Now)       → Colab T4 + Llama 3.1 8B (Development & Demo)
Phase 2 (Staging)   → Local server + Ollama + Llama 3.1 8B (Air-gapped test)
Phase 3 (Production)→ On-premise GPU server + Ollama + Llama 3.1 70B (Full deployment)
```

The `get_llm()` factory function in `llm_client.py` above means your agent code requires **zero changes** between phases — only the `LLM_MODE` config value changes.

---

## 9. Quick-Start Checklist

- [ ] Create Google account and go to [colab.research.google.com](https://colab.research.google.com)
- [ ] Set runtime to **T4 GPU**
- [ ] Get free ngrok token at [ngrok.com](https://ngrok.com) (free account)
- [ ] (For Llama 3.1) Accept Meta license at [huggingface.co/meta-llama](https://huggingface.co/meta-llama) and add HF token to Colab Secrets
- [ ] (No license needed) Use `deepseek-ai/DeepSeek-R1-Distill-Llama-8B` for zero-friction start
- [ ] Run Cells 1–4 in order, copy the ngrok URL
- [ ] Paste URL into local `config.py → COLAB_ENDPOINT_URL`
- [ ] Test with: `curl -X POST <ngrok_url>/generate -H "Content-Type: application/json" -d '{"system_prompt":"You are a security AI","user_message":"What is a SQL injection?"}'`

---

*Document Status: Final Version 1.0 | Confidentiality: Internal Development Use Only*
