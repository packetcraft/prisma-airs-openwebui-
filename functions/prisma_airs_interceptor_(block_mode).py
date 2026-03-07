"""
title: Prisma AIRS Security Interceptor (Blocking Mode)
author: Gemini
version: 3.0
"""

import uuid
from typing import Awaitable, Callable, Optional

import requests
import urllib3
from pydantic import BaseModel, Field

# Disables warnings for insecure connections (-k flag equivalent)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Filter:
    class Valves(BaseModel):
        PRISMA_API_URL: str = Field(
            default="https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request"
        )
        PRISMA_API_KEY: str = Field(default="", description="Your x-pan-token")
        AI_PROFILE_NAME: str = Field(
            default="", description="Your AI Profile Name from Strata"
        )

    def __init__(self):
        self.valves = self.Valves()

    def get_risk_description(self, detection_data: dict) -> str:
        risks = []
        if detection_data.get("dlp"):
            risks.append("Data Leakage (DLP)")
        if detection_data.get("injection"):
            risks.append("Prompt Injection")
        if detection_data.get("url_cats"):
            risks.append("Malicious URL")
        return ", ".join(risks) if risks else "Policy Violation"

    async def inlet(
        self, body: dict, __event_emitter__: Callable[[dict], Awaitable[None]] = None
    ) -> dict:
        """Blocks the prompt BEFORE it reaches the AI if a risk is detected."""
        if __event_emitter__:
            await __event_emitter__(
                {
                    "type": "status",
                    "data": {
                        "description": "🔍 Prisma AIRS: Security Check...",
                        "done": False,
                    },
                }
            )

        user_msg = body["messages"][-1].get("content", "")
        try:
            headers = {
                "x-pan-token": self.valves.PRISMA_API_KEY.strip(),
                "Content-Type": "application/json",
            }
            payload = {
                "metadata": {
                    "ai_model": body.get("model"),
                    "app_name": "Open WebUI",
                    "app_user": "local-user",
                },
                "contents": [{"prompt": user_msg, "response": ""}],
                "tr_id": str(uuid.uuid4())[:8],
                "ai_profile": {"profile_name": self.valves.AI_PROFILE_NAME.strip()},
            }
            response = requests.post(
                self.valves.PRISMA_API_URL,
                json=payload,
                headers=headers,
                timeout=10,
                verify=False,
            )

            if response.status_code == 200:
                data = response.json()
                prompt_risks = data.get("prompt_detected", {})

                # Logic Change: If Prisma says 'block' or detects a specific threat
                if data.get("action") == "block" or any(prompt_risks.values()):
                    risk_name = self.get_risk_description(prompt_risks)

                    if __event_emitter__:
                        await __event_emitter__(
                            {
                                "type": "status",
                                "data": {
                                    "description": f"❌ Blocked: {risk_name}",
                                    "done": True,
                                },
                            }
                        )

                    # HARD BLOCK: Raising an Exception stops the message from going to Ollama
                    raise Exception(
                        f"Prisma AIRS Security Block: {risk_name} detected."
                    )

            status = "✅ Prompt Safe"
        except Exception as e:
            if "Security Block" in str(e):
                raise e  # Pass security block through
            status = f"❌ Error: {str(e)}"

        if __event_emitter__:
            await __event_emitter__(
                {
                    "type": "status",
                    "data": {"description": f"Prisma AIRS: {status}", "done": True},
                }
            )
        return body

    async def outlet(
        self, body: dict, __event_emitter__: Callable[[dict], Awaitable[None]] = None
    ) -> dict:
        """Intercepts the response and redacts it if sensitive data is leaked."""
        if __event_emitter__:
            await __event_emitter__(
                {
                    "type": "status",
                    "data": {
                        "description": "🔍 Prisma AIRS: Scanning Response...",
                        "done": False,
                    },
                }
            )

        messages = body.get("messages", [])
        ai_res, user_prompt = (
            messages[-1].get("content", ""),
            (messages[-2].get("content", "") if len(messages) > 1 else ""),
        )

        try:
            headers = {
                "x-pan-token": self.valves.PRISMA_API_KEY.strip(),
                "Content-Type": "application/json",
            }
            payload = {
                "metadata": {
                    "ai_model": body.get("model"),
                    "app_name": "Open WebUI",
                    "app_user": "local-user",
                },
                "contents": [{"prompt": user_prompt, "response": ai_res}],
                "tr_id": str(uuid.uuid4())[:8],
                "ai_profile": {"profile_name": self.valves.AI_PROFILE_NAME.strip()},
            }
            response = requests.post(
                self.valves.PRISMA_API_URL,
                json=payload,
                headers=headers,
                timeout=10,
                verify=False,
            )

            if response.status_code == 200:
                data = response.json()
                res_risks = data.get("response_detected", {})

                if data.get("action") == "block" or any(res_risks.values()):
                    risk_name = self.get_risk_description(res_risks)
                    # REDACTION: Replace the leaked content with a warning
                    body["messages"][-1]["content"] = (
                        f"⚠️ **SECURITY BLOCK:** The model response was blocked/redacted due to {risk_name}."
                    )
                    status = f"🚨 {risk_name} Redacted"
                else:
                    status = "✅ Response Safe"
        except Exception:
            status = "❌ Scan Error"

        if __event_emitter__:
            await __event_emitter__(
                {
                    "type": "status",
                    "data": {"description": f"Prisma AIRS: {status}", "done": True},
                }
            )
        return body
