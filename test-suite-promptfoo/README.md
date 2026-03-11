Here is the updated **README.md**. I have overhauled the installation section to use the Homebrew Python solution (fixing the SSL/deadlock issues), added the **Model Lineage (Audit)** section, and populated the configuration blocks for a complete, copy-paste-ready guide.

---

# 🛡️ Prisma AIRS & Promptfoo Security Eval

This project integrates the **Palo Alto Networks Prisma AIRS SDK** with **Promptfoo** to perform automated security evaluations, red-teaming, and DLP masking validation on local LLM stacks (Ollama).

## 📂 Folder Structure

Maintaining a clean directory is critical for Python imports to work correctly across the Promptfoo worker. **Note:** Do not rename the parent folder after creating the `.venv`, as it will break Python internal paths.

```text
prisma-airs-eval/
├── .venv/                     # Python Virtual Environment (Homebrew-based)
├── test-suite-promptfoo/      # Main Promptfoo directory
│   ├── eval.config.yaml       # Standard Pass/Fail testing config
│   ├── redteam.config.yaml    # Adversarial/Security scan config
│   ├── provider.py            # Python bridge between Promptfoo & Open WebUI
│   ├── prisma_airs_sdk.py     # Your v7.0 Enforcement/Filter logic
│   └── .promptfoo/            # Auto-generated logs and cache
└── README.md                  # This file

```

---

## ⚙️ Installation

### 1. System Dependencies (macOS)

To avoid the `LibreSSL` and `urllib3` version conflicts, use Homebrew's Python, which is compiled with modern OpenSSL.

```bash
# Install Node.js & Promptfoo
brew install node
npm install -g promptfoo

# Install Homebrew Python (Required for Prisma SDK + urllib3 v2)
brew install python@3.11

```

### 2. Python Environment Setup

Navigate to the `test-suite-promptfoo` folder. If you have an existing `.venv`, delete it first to ensure the new Homebrew paths take effect.

```bash
cd test-suite-promptfoo
rm -rf .venv  # Clean start

# Create environment using the Homebrew Python path
/opt/homebrew/bin/python3.11 -m venv .venv
source .venv/bin/activate

# Install Prisma SDK & ModelAudit (No pinning needed with Python 3.11)
pip install pan-aisecurity modelaudit[all]

```

---

## 🛠️ Configuration Files

### 1. The Bridge (`provider.py`)

This script acts as the connector, sending Promptfoo's test cases to your **Open WebUI** instance (which is protected by your Prisma Filter).

```python


```

### 2. Red Team Config (`redteam.config.yaml`)

This configuration triggers an "Attacker" LLM to find bypasses for your Prisma security profile.

```yaml


```

---

## 🚀 Running Evaluations & Audits

### **1. Model Lineage Audit**

Verify the integrity of your local model files and establish a security baseline (hash tracking).

```bash
# Scans Ollama blobs for backdoors/vulnerabilities
promptfoo scan-model ~/.ollama/models/blobs/

```

### **2. Standard Eval (Sanity Check)**

Verify that DLP masking is functioning for known sensitive patterns.

```bash
promptfoo eval -c eval.config.yaml

```

### **3. Security Red Team Run**

Generate adversarial attempts to bypass the Prisma Inlet.

```bash
promptfoo redteam run -c redteam.config.yaml

```

### **4. View Results**

Open the interactive dashboard to see lineage hashes and security heatmaps.

```bash
promptfoo view

```

---

## ⚠️ Troubleshooting

| Error | Cause | Fix |
| --- | --- | --- |
| `bad interpreter` | Renamed folder after creating `.venv`. | Delete `.venv` and recreate it. |
| `401 Unauthorized` | Open WebUI API Key is missing/invalid. | Admin Panel > Enable API Keys > Generate `sk-` key. |
| `urllib3 conflict` | Using System Python (LibreSSL). | Use Homebrew Python 3.11+ (OpenSSL). |
| `Invariant failed` | Plugin ID mismatch. | Use official IDs like `hijacking` or `overreliance`. |

---

**Would you like me to add a section on how to export these results into a PDF Security Report for your compliance team?**
