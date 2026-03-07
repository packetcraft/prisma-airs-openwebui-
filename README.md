# 🛡️ Prisma AIRS Security Interceptor for Open WebUI

**Enhance your local GenAI deployment with enterprise-grade security guardrails.**

This project provides a seamless integration between [Ollama](https://ollama.com), [Open WebUI](https://openwebui.com), and [Palo Alto Networks Prisma AIRS](https://pan.dev/prisma-airs/). It allows you to run powerful, local LLMs while maintaining real-time monitoring for prompt injections and sensitive data leakage.

---

## 🚀 Why Use This?

Running local AI offers privacy and speed, but it often lacks the security layers found in enterprise cloud LLMs. This interceptor adds:

* **Inbound Protection**: Detects jailbreaks and prompt injections before they reach your model.
* **Outbound Protection**: Identifies PII (Social Security Numbers, Credit Cards) and sensitive data in AI responses.
* **Visual Feedback**: Real-time status indicators in the chat UI show you exactly when a scan is occurring.

---

## 🔀 Choose Your Mode

Two filter functions are available depending on how strictly you want to enforce security:

| Mode | File | Behavior |
| --- | --- | --- |
| **Detector** | `prisma_airs_detector.py` | Flags threats by annotating the message with a warning banner. The prompt and response still pass through. Good for visibility and testing. |
| **Enforcer** | `prisma_airs_enforcer.py` | Hard-blocks the message if a threat is detected. Flagged prompts never reach the model; flagged responses are fully redacted. Use for active enforcement. |

Start with Detector if you want to observe behavior before enforcing. Switch to Enforcer when you're ready to enforce.

---

## 🛠️ Quick Start

**Prerequisites**: Docker Desktop, Ollama, and an active Prisma AIRS account with an API key and security profile.

1. **Pull the Model**:
```bash
ollama pull llama2-uncensored:latest
```

2. **Launch WebUI**:
```bash
docker run -d -p 3000:8080 --add-host=host.docker.internal:host-gateway \
  -v open-webui:/app/data --name open-webui \
  ghcr.io/open-webui/open-webui:main
```

3. **Install Filter**: Copy the code from your chosen file in `functions/` into Open WebUI via **Admin Panel > Functions**.

**Detailed instructions can be found in the [Setup Guide](./docs/setup-guide.md).**

---

## 📂 Repository Structure

* `functions/`: Contains the Python middleware (Filter) for Open WebUI.
* `docs/`: Step-by-step setup guides, troubleshooting, and architecture documentation.
  * [Setup Guide](./docs/setup-guide.md) — installation and configuration walkthrough.
  * [PRD](./docs/PRD.md) — filter architecture, request flow diagrams for all three modes, API schema notes, and the streaming obscurement limitation.
* `samples/`: Real Prisma AIRS API JSON responses captured for development and testing reference.

---

## ⚖️ License

Distributed under the MIT License. See `LICENSE` for more information.
