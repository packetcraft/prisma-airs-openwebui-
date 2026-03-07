# 🛡️ Prisma AIRS Security Interceptor for Open WebUI

**Enhance your local GenAI deployment with enterprise-grade security guardrails.**

This project provides a seamless integration between [Ollama](https://ollama.com), [Open WebUI](https://openwebui.com), and [Palo Alto Networks Prisma AIRS](https://pan.dev/prisma-airs/). It allows you to run powerful, local LLMs while maintaining real-time monitoring for prompt injections and sensitive data leakage. I typically run all of this on my macbook

---

## 🚀 Why Use This?
Running local AI offers privacy and speed, but it often lacks the security layers found in enterprise cloud LLMs. This interceptor adds:
* **Inbound Protection**: Detects "Jailbreaks" and Prompt Injections before they reach your model.
* **Outbound Protection**: Identifies PII (Social Security Numbers, Credit Cards) and sensitive data in AI responses.
* **Visual Feedback**: Real-time status indicators in the chat UI show you exactly when a scan is occurring.



---

## 🛠️ Quick Start
If you are already familiar with Docker and Ollama, follow these three steps:

1. **Pull the Model**: `ollama pull llama2-uncensored:latest`.
2. **Launch WebUI**: Run the Open WebUI Docker container.
3. **Install Filter**: Copy the code from `functions/prisma_airs_interceptor_(monitor_mode).py` into your Admin Panel.

**Detailed instructions can be found in the [Setup Guide](./docs/setup-guide.md).**

---

## 📂 Repository Structure
* `functions/`: Contains the Python middleware (Filter) for Open WebUI.
* `docs/`: Step-by-step setup guides and troubleshooting for macOS.
* `scripts/`: Helper scripts for local environment preparation.

---

## ⚖️ License
Distributed under the MIT License. See `LICENSE` for more information.
