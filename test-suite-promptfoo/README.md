This `README.md` provides a comprehensive guide for setting up and running **Promptfoo** to evaluate your **Prisma AIRS** demo implementation. It covers the installation, the "bridge" provider setup, and automated red-teaming configurations.

---

# 🛡️ Prisma AIRS & Promptfoo Security Eval

This project integrates the **Palo Alto Networks Prisma AIRS SDK** with **Promptfoo** to perform automated security evaluations, red-teaming, and DLP masking validation on local LLM stacks (Ollama).

## 📂 Folder Structure

Maintaining a clean directory is critical for Python imports to work correctly across the Promptfoo worker.

```text
prisma-airs-eval/
├── .venv/                     # Python Virtual Environment
├── functions/                 # (Optional) Production filter scripts
├── test-suite/                # Main Promptfoo directory
│   ├── eval.config.yaml       # Standard Pass/Fail testing config
│   ├── redteam.config.yaml    # Adversarial/Security scan config
│   ├── provider.py            # Python bridge between Promptfoo & SDK
│   ├── prisma_airs_sdk.py     # Your v7.0 Enforcement/Filter logic
│   └── .promptfoo/            # Auto-generated logs and cache
└── README.md                  # This file

```

---

## ⚙️ Installation

### 1. System Dependencies

Ensure you have **Node.js** (for Promptfoo CLI) and **Python 3.11+** (for the SDK) installed.

```bash
# Install Node.js via Homebrew (if not present)
brew install node

# Install Promptfoo CLI globally
npm install -g promptfoo

```

### 2. Python Environment Setup

Navigate to the `test-suite` folder and create a localized environment to avoid path issues.

```bash
cd test-suite
python3 -m venv .venv
source .venv/bin/activate

# Install Prisma SDK and requirements
pip install pan-aisecurity
# Fix for macOS LibreSSL/urllib3 v2 compatibility
pip install "urllib3<2.0"

```

---

## 🛠️ Configuration Files

### 1. The Bridge (`provider.py`)

This script allows Promptfoo to send its generated attack prompts through your Prisma Filter.

```python

```

### 2. Red Team Config (`redteam.config.yaml`)

This configuration triggers the "Attacker" LLM to try and bypass your `inlet` shield.

```yaml

```

---

## 🚀 Running Evaluations

### **Standard Eval (Sanity Check)**

Verify that your script is correctly masking the "AKIA" keys we mocked in the provider.

```bash
promptfoo eval -c eval.config.yaml

```

### **Security Red Team Run**

Generate 40+ adversarial attempts to bypass your Prisma profile.

```bash
promptfoo redteam run -c redteam.config.yaml

```

### **View Results**

Open the interactive dashboard to see precisely where the leak occurred.

```bash
promptfoo view

```

---

## ⚠️ Troubleshooting

| Error | Cause | Fix |
| --- | --- | --- |
| `IndentationError` | Mix of tabs and spaces in `provider.py`. | Use 4 spaces consistently. |
| `ModuleNotFoundError` | `.venv` not active or SDK not installed. | Run `source .venv/bin/activate`. |
| `NotOpenSSLWarning` | `urllib3 v2` incompatibility with macOS. | Run `pip install "urllib3<2.0"`. |
| `Invariant failed` | Using `indirect-prompt-injection` ID. | Change plugin ID to `hijacking`. |

---
