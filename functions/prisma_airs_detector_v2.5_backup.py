"""
title: Prisma AIRS Security Interceptor (Advanced Mapping)
author: Gemini
author_url: https://docs.paloaltonetworks.com/ai-runtime-security/
version: 2.5
"""

import requests
import uuid
import urllib3
from typing import Optional, Callable, Awaitable
from pydantic import BaseModel, Field

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Filter:
    class Valves(BaseModel):
        PRISMA_API_URL: str = Field(
            default="https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request"
        )
        PRISMA_API_KEY: str = Field(
            default="xxxxx"
        )
        AI_PROFILE_NAME: str = Field(default="xxxxx")

    def __init__(self):
        self.valves = self.Valves()

    def get_risk_description(self, detection_data: dict, details: dict = None) -> str:
        """Helper to map all nuanced API boolean flags to a readable string."""
        risks = []

        # Core Detection Flags
        if detection_data.get("injection"):
            risks.append("Prompt Injection")
        if detection_data.get("dlp"):
            risks.append("Sensitive Data (DLP)")
        if detection_data.get("toxic_content"):
            risks.append("Toxic/Hateful Content")
        if detection_data.get("malicious_code"):
            risks.append("Malicious Code")
        if detection_data.get("url_cats"):
            risks.append("Unsafe URL/Link")
        if detection_data.get("ungrounded"):
            risks.append("Hallucination/Ungrounded")
        if detection_data.get("db_security"):
            risks.append("Database Security Risk")
        if detection_data.get("agent"):
            risks.append("Agent System Abuse")

        # Extract specific categories if toxic content is found
        if details and "toxic_content_details" in details:
            cats = details["toxic_content_details"].get("toxic_categories", [])
            if cats:
                risks.append(f"({', '.join(cats)})")

        return ", ".join(risks) if risks else "Policy Violation"

    async def inlet(
        self, body: dict, __event_emitter__: Callable[[dict], Awaitable[None]] = None
    ) -> dict:
        """Scans the prompt and identifies all detection nuances."""
        if __event_emitter__:
            await __event_emitter__(
                {
                    "type": "status",
                    "data": {
                        "description": "🔍 Prisma AIRS: Deep Scanning Prompt...",
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
            status = "✅ Prompt Safe"

            if response.status_code == 200:
                data = response.json()
                prompt_risks = data.get("prompt_detected", {})
                details = data.get("prompt_detection_details", {})

                if data.get("action") == "block" or any(prompt_risks.values()):
                    risk_name = self.get_risk_description(prompt_risks, details)
                    body["messages"][-1]["content"] = (
                        f"🚨 **PRISMA AIRS SECURITY ALERT:** {risk_name}\n\n" + user_msg
                    )
                    status = f"🚩 Risk: {risk_name}"
            else:
                status = f"⚠️ API Error {response.status_code}"

        except Exception as e:
            status = f"❌ Connection Error: {str(e)}"

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
        """Scans AI response for nuanced risks like PII, Malicious Code, or Hallucinations."""
        if __event_emitter__:
            await __event_emitter__(
                {
                    "type": "status",
                    "data": {
                        "description": "🔍 Prisma AIRS: Deep Scanning Response...",
                        "done": False,
                    },
                }
            )

        messages = body.get("messages", [])
        ai_res, user_prompt = messages[-1].get("content", ""), (
            messages[-2].get("content", "") if len(messages) > 1 else ""
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
            status = "✅ Response Safe"

            if response.status_code == 200:
                data = response.json()
                res_risks = data.get("response_detected", {})

                if data.get("action") == "block" or any(res_risks.values()):
                    risk_name = self.get_risk_description(res_risks)
                    body["messages"][-1][
                        "content"
                    ] += f"\n\n---\n🚨 **PRISMA AIRS SECURITY ALERT:** {risk_name} detected in output."
                    status = f"🚩 Risk: {risk_name}"
            else:
                status = f"⚠️ Scan Error {response.status_code}"

        except Exception as e:
            status = f"❌ Scan Error: {str(e)}"

        if __event_emitter__:
            await __event_emitter__(
                {
                    "type": "status",
                    "data": {"description": f"Prisma AIRS: {status}", "done": True},
                }
            )
        return body
