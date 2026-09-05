# 🦅 eagleI — Prompt Injection Tester & AI Security Platform

**eagleI** is an authorized cybersecurity platform designed to test, analyze, and secure AI chatbots and Large Language Models (LLMs) against **Prompt Injection Attacks**, **Jailbreaks**, and **System Prompt / Canary Leakage**.

Connected directly to the **Hugging Face API** and custom LLM endpoints, eagleI evaluates how vulnerable or resilient an AI model is, generates actionable remediation policies, and provides before-and-after retest verification.

---

## ⚡ Core Security Workflow

```text
 ┌─────────────────┐      ┌─────────────────────────┐      ┌─────────────────────────┐
 │  ATTACK INJECT  │ ───► │  STAGE 1: INBOUND GUARD │ ───► │   TARGET AI MODEL       │
 │ 144+ Patterns & │      │ Heuristics, Similarity, │      │ Hugging Face API /      │
 │ 13 Evasion Mods │      │ De-obfuscation Firewall │      │ Mistral-7B / Llama-3.1  │
 └─────────────────┘      └─────────────────────────┘      └────────────┬────────────┘
                                                                        │
 ┌─────────────────┐      ┌─────────────────────────┐                   │
 │ RETEST / DELTA  │ ◄─── │  THREAT ANALYZER & FIX  │ ◄─────────────────┘
 │ Before vs After │      │ Verdict, Risk Score,    │      ┌─────────────────────────┐
 │ Improvement     │      │ & Remediation Guidance  │ ◄─── │ STAGE 2: OUTBOUND GUARD │
 └─────────────────┘      └─────────────────────────┘      │ Canary Secret Detection │
                                                           │ & Surgical Redaction    │
                                                           └─────────────────────────┘
```

---

## 🚀 Quick Start Guide (Run Locally in 2 Steps)

### Prerequisites:
- Python 3.10+
- Node.js 18+

### Step 1: Start Backend API (FastAPI)
```powershell
# From project root directory:
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
*Backend API will be live at: `http://127.0.0.1:8000` (Docs: `http://127.0.0.1:8000/docs`)*

### Step 2: Start Frontend UI (Vite + React)
```powershell
cd frontend
npm install
npm run dev
```
*Frontend will be live at: `http://localhost:5173`*

---

## 🤖 Hugging Face Integration Setup

eagleI uses the official **Hugging Face Serverless Inference Router** for testing models:

- **Router Endpoint:** `https://router.huggingface.co/hf-inference/v1/chat/completions`
- **Default Model:** `mistralai/Mistral-7B-Instruct-v0.3` (or `meta-llama/Meta-Llama-3.1-8B-Instruct`)
- **API Key / Token:**
  1. Get your free token from [Hugging Face Settings > Tokens](https://huggingface.co/settings/tokens) (Token Type: **Inference**).
  2. Enter the token in the **Targets** tab in eagleI UI (or save in `.env` as `HF_TOKEN=hf_...`).

### 🧪 Optional Local Test Target (Offline Demo):
If you want to test prompt injections offline without an internet connection or API credits, run the built-in controlled target fixture:
```powershell
python target/huggingface_target.py
```
*Running on `http://127.0.0.1:8002/chat` with toggleable **`WEAK`** (vulnerable) and **`HARDENED`** (defended) modes.*

---

## 🖥️ 3-Panel Unified Testing Workspace

| Workspace Area | Description |
|---|---|
| **1. Injection Module (Left)** | Choose from **144+ Curated Attack Patterns** across 14 categories (*Roleplay Hijack, Direct System Prompt Leak, Delimiter Escapes, Developer Mode Overrides*) with **13 Adversarial Mutations** (*Base64, Hex, Leetspeak, Unicode Homoglyphs, Zero-Width Insertion*). |
| **2. Interactive Chatbox (Right)** | Real-time chat stream with the target AI model. Displays gateway firewall intercept status, latency, and automatic `[REDACTED]` masking of sensitive Canary Secrets (`GENESIS-7731-INTERNAL`). |
| **3. Threat Analyzer (Bottom)** | Instant vulnerability verdict (**VULNERABLE**, **RESISTED**, **SAFE**), quantitative 0–100 risk score breakdown, security findings, and **Retest Delta Comparison** showing security improvements after remediation. |

---

## 📁 Project Architecture & Directory Tree

```
eagleI/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── attacks.py           # Attack library & payload generation
│   │   │   ├── targets.py           # Dynamic target management (Hugging Face / custom)
│   │   │   ├── inspect.py           # Unified /inspect/pipeline endpoint
│   │   │   ├── reports.py           # Assessment report generator
│   │   │   ├── alerts.py            # Real-time security alert feeds
│   │   │   └── tests.py             # Batch testing battery orchestrator
│   │   │
│   │   ├── services/
│   │   │   ├── hf_adapter.py        # Dedicated Hugging Face Router & Inference adapter
│   │   │   ├── adapter.py           # Target dispatcher & response parser
│   │   │   ├── request_inspector.py # Stage 1 Inbound heuristics, similarity & firewall
│   │   │   ├── response_inspector.py# Stage 2 Outbound canary leakage & secret redaction
│   │   │   ├── analyzer.py          # Threat scoring (0-100), verdicts & retest delta
│   │   │   ├── mutator.py           # Adversarial payload transformations
│   │   │   └── secrets.py           # Encryption & surgical redaction utilities
│   │   │
│   │   ├── main.py                  # FastAPI app entry point & CORS configuration
│   │   ├── database.py              # SQLite database session manager
│   │   ├── models.py                # Database models
│   │   └── schemas.py               # Pydantic validation schemas
│   └── requirements.txt
│
├── frontend/
│   └── src/
│       ├── main.tsx                 # 2-Tier Workspace UI (Injection + Chatbox + Analyzer)
│       ├── style.css                # Base styling & modern design tokens
│       └── upgrade.css              # Cyber-defense dark theme, glassmorphism & risk gauges
│
├── target/
│   └── huggingface_target.py        # Controlled Hugging Face target bot (WEAK vs HARDENED)
│
├── corpus/
│   └── seed/                        # Curated seed attack patterns across 14 categories
│
├── tests/                           # Pytest Test Suite (37/37 passing)
│   ├── test_hf_adapter.py           # Hugging Face target adapter tests
│   ├── test_inspectors.py           # Request & Response inspector tests
│   ├── test_mutator_v24.py          # Evasion mutation tests
│   └── test_security.py             # Secret protection & redaction tests
│
└── scripts/
    ├── seed_corpus.py               # Seed database with initial attack library
    └── benchmark.py                 # Accuracy & evasion benchmark suite
```

---

## 🧪 Verification & Automated Testing

All backend and frontend components are verified with automated test suites:

```powershell
# Run backend pytest suite (37 tests):
python -m pytest -q

# Build frontend production bundle:
cd frontend
npm run build
```

---

## 🔒 Security & Compliance Notice

> **⚠️ Authorization Required:** eagleI is strictly intended for authorized security audits, red-teaming, and defensive hardening of AI systems. Only test endpoints and models that you own or have explicit permission to evaluate.
