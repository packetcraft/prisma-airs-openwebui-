
# 🛡️ Prisma AIRS & Promptfoo Security Eval

This project integrates the **Palo Alto Networks Prisma AIRS SDK** with **Promptfoo** to perform automated security evaluations, red-teaming, and DLP masking validation on local LLM stacks (Ollama + Open WebUI).

## 📂 Folder Structure

Maintaining a clean directory is critical for Python imports. **Note:** Do not rename the parent folder after creating the `.venv`, as it will break Python internal paths.

Plaintext

```
test-suite-promptfoo/
├── .venv/                      # Python Virtual Environment (Homebrew-based)
├── eval.config.yaml            # Standard Pass/Fail testing config
├── redteam.config.yaml         # Adversarial/Security scan config
├── provider.py                 # API Bridge: Promptfoo -> Open WebUI -> Prisma
├── prisma_airs_sdk_enforced.py # v7.9 Pure Markdown Filter logic
├── .promptfoo/                 # Auto-generated logs and cache
└── README.md                   # This file
```

---

## ⚙️ Installation

### 1. System Dependencies (macOS)

Use Homebrew's Python to ensure compatibility with modern OpenSSL/urllib3.

Bash

```
# Install Node.js & Promptfoo
brew install node
npm install -g promptfoo

# Install Homebrew Python
brew install python@3.11
```

### 2. Python Environment Setup

Bash

```
cd test-suite-promptfoo
rm -rf .venv  # Clean start

# Create environment using the Homebrew Python path
/opt/homebrew/bin/python3.11 -m venv .venv
source .venv/bin/activate

# Install Prisma SDK & Requirements
pip install pan-aisecurity requests
```

---

## 🛠️ Configuration & Integration

### 1. The Model Alias (Open WebUI)

Ensure you have created a model alias in Open WebUI:

1. Go to **Workspace > Models**.
    
2. Create a model named **`ol---enforcedsdk`** based on `llama3.2`.
    
3. Attach the `prisma_airs_sdk_enforced.py` filter to this model.
    

### 2. The Bridge (`provider.py`)

This script routes Promptfoo attacks to your secured model alias.

Python

```
import requests, json, asyncio

async def call_api(prompt, options, context):
    url = "http://localhost:3000/api/chat/completions"
    headers = {
        "Authorization": "Bearer sk-YOUR_API_KEY",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "ol---enforcedsdk",
        "messages": [{"role": "user", "content": prompt}],
        "stream": False
    }
    response = requests.post(url, headers=headers, json=payload)
    data = response.json()
    return {"output": data['choices'][0]['message']['content']}
```

### 3. Red Team Config (`redteam.config.yaml`)

YAML

```
targets:
  - id: python:provider.py
    label: "Prisma-Secured-Llama"

redteam:
  purpose: "A secure assistant that protects PII and blocks toxic content."
  plugins:
    - id: hijacking
    - id: overreliance
    - id: pii:direct
  strategies:
    - id: jailbreak:meta
```

---

## 🚀 Running Evaluations

### **1. Security Red Team Run**

Generate adversarial attempts to bypass the Prisma Inlet/Outlet.

Bash

```
promptfoo redteam run -c redteam.config.yaml
```

### **2. View Results**

Open the interactive dashboard to see the **Prisma Security Reports** rendered inside the response bubbles.

Bash

```
promptfoo view
```

---

## ⚠️ Troubleshooting

|**Error**|**Cause**|**Fix**|
|---|---|---|
|`Error 401`|Session expired or API Key invalid.|Generate a new `sk-` key in Open WebUI Account Settings.|
|`NoneType` subscriptable|Model is loading or API structure is unexpected.|Use the updated `provider.py` with safe-access checks.|
|`Connection Refused`|Open WebUI is not running or URL is wrong.|Ensure `localhost:3000` is accessible in browser.|
|Dashboard shows raw HTML|UI Sanitizer escaping tags.|Ensure you are using **v7.9 (Pure Markdown)** of the filter script.|
