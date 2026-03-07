"""
title: Prisma AIRS Security Interceptor (Blocking + Deep Mapping)
author: Gemini
version: 3.1
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
        PRISMA_API_KEY: str = Field(
            default="xxx",
            description="Your x-pan-token",
        )
        AI_PROFILE_NAME: str = Field(
            default="xxx", description="Your AI Profile Name from Strata"
        )

    def __init__(self):
        self.valves = self.Valves()

    def get_risk_description(self, detection_data: dict, details: dict = None) -> str:
        """Enhanced risk mapper based on official AIRS JSON schema."""
        risks = []

        # Mapping prompt_detected and response_detected fields
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
        if detection_data.get("agent"):
            risks.append("Agent Abuse")
        if detection_data.get("ungrounded"):
            risks.append("Hallucination/Ungrounded")
        if detection_data.get("db_security"):
            risks.append("Database Security")

        # Extract granular toxic categories if present (per provided JSON)
        if details and "toxic_content_details" in details:
            cats = details["toxic_content_details"].get("toxic_categories", [])
            if cats:
                risks.append(f"({', '.join(cats)})")

        return ", ".join(risks) if risks else "Policy Violation"

    async def inlet(
        self, body: dict, __event_emitter__: Callable[[dict], Awaitable[None]] = None
    ) -> dict:
        """HARD BLOCK: Prevents malicious prompts from ever reaching the local AI."""
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
                details = data.get("prompt_detection_details", {})

                # Logic: If 'action' is 'block' or ANY security bit is set to true
                if data.get("action") == "block" or any(prompt_risks.values()):
                    risk_name = self.get_risk_description(prompt_risks, details)

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

                    # Raise Exception to stop the request pipeline immediately
                    raise Exception(
                        f"PRISMA AIRS BLOCK: {risk_name} detected in your request."
                    )

            status = "✅ Prompt Safe"
        except Exception as e:
            if "PRISMA AIRS BLOCK" in str(e):
                raise e
            status = f"❌ Scan Error: {str(e)}"

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
        """REDACTION: Overwrites leaking or toxic AI responses before they are displayed."""
        if __event_emitter__:
            await __event_emitter__(
                {
                    "type": "status",
                    "data": {
                        "description": "🔍 Prisma AIRS: Response Integrity Scan...",
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

            if response.status_code == 200:
                data = response.json()
                res_risks = data.get("response_detected", {})

                if data.get("action") == "block" or any(res_risks.values()):
                    risk_name = self.get_risk_description(res_risks)
                    # REDACT the response content
                    body["messages"][-1][
                        "content"
                    ] = f"🚨 **PRISMA AIRS REDACTION:** This response was blocked due to {risk_name}."
                    status = f"🚩 Risk: {risk_name}"
                else:
                    status = "✅ Response Safe"
        except Exception:
            status = "❌ Integrity Scan Failed"

        if __event_emitter__:
            await __event_emitter__(
                {
                    "type": "status",
                    "data": {"description": f"Prisma AIRS: {status}", "done": True},
                }
            )
        return body
