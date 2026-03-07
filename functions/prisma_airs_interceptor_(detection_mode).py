"""
title: Prisma AIRS Security Interceptor (Detection Mode)
author: Gemini
author_url: https://docs.paloaltonetworks.com/ai-runtime-security/
version: 2.6
"""

import requests
import uuid
import urllib3
from typing import Callable, Awaitable
from pydantic import BaseModel, Field

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Filter:
    class Valves(BaseModel):
        PRISMA_API_URL: str = Field(
            default="https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request"
        )
        PRISMA_API_KEY: str = Field(default="", description="Your x-pan-token API Key")
        AI_PROFILE_NAME: str = Field(
            default="",
            description="The AI Security Profile name from Strata Cloud Manager"
        )

    def __init__(self):
        self.valves = self.Valves()

    # Prompt-only fields (injection and agent are not present in response_detected)
    PROMPT_FIELD_MAP = {
        "injection": "Prompt Injection",
        "agent": "Agent System Abuse",
        "dlp": "Sensitive Data (DLP)",
        "toxic_content": "Toxic Content",
        "malicious_code": "Malicious Code",
        "url_cats": "Unsafe URL",
    }

    # Response-only fields (db_security and ungrounded are not present in prompt_detected)
    RESPONSE_FIELD_MAP = {
        "dlp": "Sensitive Data (DLP)",
        "toxic_content": "Toxic Content",
        "malicious_code": "Malicious Code",
        "url_cats": "Unsafe URL",
        "db_security": "Database Security Risk",
        "ungrounded": "Hallucination/Ungrounded",
    }

    def get_risk_description(self, detection_data: dict, details: dict = None, field_map: dict = None) -> str:
        """Maps API detection flags to a readable string using the correct field map."""
        if field_map is None:
            field_map = self.PROMPT_FIELD_MAP
        risks = []
        for key, label in field_map.items():
            if detection_data.get(key):
                if key == "toxic_content" and details:
                    cats = details.get("toxic_content_details", {}).get("toxic_categories", [])
                    if cats:
                        label = f"Toxic Content ({', '.join(cats)})"
                risks.append(label)
        return ", ".join(risks) if risks else "Unknown Risk"

    def get_dlp_pattern_summary(self, masked_data: dict) -> str:
        """Extracts DLP pattern names and hit counts from response_masked_data."""
        pattern_detections = masked_data.get("pattern_detections", [])
        if not pattern_detections:
            return ""
        counts = {}
        for detection in pattern_detections:
            pattern = detection.get("pattern", "Unknown")
            hits = len(detection.get("locations", []))
            counts[pattern] = counts.get(pattern, 0) + hits
        return ", ".join(f"{name} ({hits} hit{'s' if hits != 1 else ''})" for name, hits in counts.items())

    async def inlet(
        self, body: dict, __event_emitter__: Callable[[dict], Awaitable[None]] = None
    ) -> dict:
        """Scans the user prompt and prepends a warning banner if risks are detected."""
        if not self.valves.PRISMA_API_KEY.strip() or not self.valves.AI_PROFILE_NAME.strip():
            if __event_emitter__:
                await __event_emitter__({
                    "type": "status",
                    "data": {"description": "⚠️ Prisma AIRS: API key or profile name not configured in Valves.", "done": True}
                })
            return body

        if __event_emitter__:
            await __event_emitter__({
                "type": "status",
                "data": {"description": "🔍 Prisma AIRS: Scanning Prompt...", "done": False},
            })

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
                "tr_id": str(uuid.uuid4())[:12],
                "ai_profile": {"profile_name": self.valves.AI_PROFILE_NAME.strip()},
            }

            response = requests.post(
                self.valves.PRISMA_API_URL,
                json=payload,
                headers=headers,
                timeout=15,
                verify=False,
            )
            status = "✅ Prompt Safe"

            if response.status_code == 200:
                data = response.json()
                prompt_risks = data.get("prompt_detected", {})
                prompt_details = data.get("prompt_detection_details", {})

                if data.get("action") == "block" or any(prompt_risks.values()):
                    risk_name = self.get_risk_description(prompt_risks, prompt_details, self.PROMPT_FIELD_MAP)
                    body["messages"][-1]["content"] = (
                        f"🚨 **PRISMA AIRS SECURITY ALERT:** {risk_name}\n\n" + user_msg
                    )
                    status = f"🚩 Risk: {risk_name}"
            else:
                status = f"⚠️ API Error {response.status_code}"

        except Exception as e:
            status = f"❌ Connection Error: {str(e)}"

        if __event_emitter__:
            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Prisma AIRS: {status}", "done": True},
            })
        return body

    async def outlet(
        self, body: dict, __event_emitter__: Callable[[dict], Awaitable[None]] = None
    ) -> dict:
        """Scans the AI response and appends a warning banner if risks are detected."""
        if not self.valves.PRISMA_API_KEY.strip() or not self.valves.AI_PROFILE_NAME.strip():
            return body

        if __event_emitter__:
            await __event_emitter__({
                "type": "status",
                "data": {"description": "🔍 Prisma AIRS: Scanning Response...", "done": False},
            })

        messages = body.get("messages", [])
        ai_res = messages[-1].get("content", "")
        user_prompt = messages[-2].get("content", "") if len(messages) > 1 else ""

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
                "tr_id": str(uuid.uuid4())[:12],
                "ai_profile": {"profile_name": self.valves.AI_PROFILE_NAME.strip()},
            }

            response = requests.post(
                self.valves.PRISMA_API_URL,
                json=payload,
                headers=headers,
                timeout=15,
                verify=False,
            )
            status = "✅ Response Safe"

            if response.status_code == 200:
                data = response.json()
                res_risks = data.get("response_detected", {})
                res_details = data.get("response_detection_details", {})

                if data.get("action") == "block" or any(res_risks.values()):
                    risk_name = self.get_risk_description(res_risks, res_details, self.RESPONSE_FIELD_MAP)

                    # Add DLP pattern details when available
                    masked_data = data.get("response_masked_data")
                    dlp_detail = ""
                    if masked_data and res_risks.get("dlp"):
                        summary = self.get_dlp_pattern_summary(masked_data)
                        if summary:
                            dlp_detail = f" — Patterns: {summary}"

                    body["messages"][-1]["content"] += (
                        f"\n\n---\n🚨 **PRISMA AIRS SECURITY ALERT:** {risk_name} detected in output.{dlp_detail}"
                    )
                    status = f"🚩 Risk: {risk_name}"
            else:
                status = f"⚠️ Scan Error {response.status_code}"

        except Exception as e:
            status = f"❌ Scan Error: {str(e)}"

        if __event_emitter__:
            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Prisma AIRS: {status}", "done": True},
            })
        return body
