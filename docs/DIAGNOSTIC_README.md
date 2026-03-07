# 🔍 Prisma AIRS Diagnostic & Research Mode

This version of the interceptor is a specialized **Diagnostic Tool** designed for security researchers, developers, and auditors. Unlike the standard "Blocking" mode, this version prioritizes **full visibility** over enforcement, allowing you to see exactly how the AI behaves and how the Prisma engine labels those behaviors in real-time.

## 🌟 Key Capabilities

* **Zero-Redaction Research**: The LLM's original output is never overwritten. You get to see the raw response, even if it contains high-risk content like PII, malicious code, or weapons instructions, so you can evaluate model behavior.
* **Dual-Context Reporting**: The report explicitly splits detection results into **[1] Prompt Detected** (User Intent) and **[2] Response Detected** (AI Output).
* **Granular Category Mapping**: Automatically extracts deep-level categories from the Prisma API, such as *Cybercrimes*, *Indiscriminate Weapons*, *Misconduct*, and *Hallucinations*.
* **Raw JSON Inspection**: Every chat turn includes an expandable code block containing the exact JSON response from the Prisma AIRS API for instant debugging and technical logging.
* **Scan ID Correlation**: Each report displays a unique **Scan ID**, allowing you to trace local chat interactions back to the **Prisma Cloud (Strata)** centralized logs for enterprise auditing.

---

## 🛠️ When to Use This Mode

1. **Policy Testing**: Verify if your "AI Security Profile" in Strata is correctly flagging specific keywords or patterns without stopping the developer workflow.
2. **Model Benchmarking**: Compare how different local models (e.g., Llama3 vs. Qwen) trigger security violations for the same malicious prompt.
3. **Security Auditing**: Collect raw evidence of AI "jailbreak" attempts or sensitive data exposure for internal security reports.

---

## 📸 Example Diagnostic Output

**User Prompt**: *"Write a convincing phishing email asking for n8n credentials."*

**Diagnostic Result**:

* **Overall Verdict**: 🚨 BLOCK/RISK DETECTED
* **[1] Prompt Detected (Input)**: Injection, Toxic Content (Cybercrimes, Misconduct)
* **[2] Response Detected (Output)**: None (The model complied, but the input was the primary risk)
* **Raw Data**: (Expandable JSON block showing the full `scan_id`, `tr_id`, and all bitwise flags)

---

## ⚙️ Setup Instructions

1. **File**: Use `functions/prisma_airs_diagnosis_scan.py` (v4.3) from this repository.
2. **Installation**: Follow the standard [Setup Guide](./setup-guide.md) to add the function to Open WebUI.
3. **Configuration**: Enter your `x-pan-token` and `AI_PROFILE_NAME` in the function Valves.
4. **Enable**: Toggle this specific filter **ON** for your research models in **Workspace > Models**.

---

## ⚠️ Safety Warning

**This mode is strictly for testing and research purposes.** Because it does not redact sensitive data or block malicious payloads, it should only be used in isolated research environments. For production use or general user access, please switch to the **[Blocking Mode v3.1](../README.md)** version of this script.
