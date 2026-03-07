"""
title: Prisma AIRS Detector
author: Gemini
author_url: https://docs.paloaltonetworks.com/ai-runtime-security/
version: 2.7
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
        return ", ".join(risks) if risks else "None Detected"

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

    async def inlet(self, body: dict, __event_emitter__: Callable[[dict], Awaitable[None]] = None) -> dict:
        """Pass-through — scanning is deferred to outlet after the LLM response is available."""
        return body

    async def outlet(self, body: dict, __event_emitter__: Callable[[dict], Awaitable[None]] = None) -> dict:
        """Dual-pass scan of prompt + response. Appends a compact alert when risks are detected."""

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
                "data": {"description": "🔍 Prisma AIRS: Scanning...", "done": False}
            })

        messages = body.get("messages", [])
        ai_res = messages[-1].get("content", "")
        user_prompt = messages[-2].get("content", "") if len(messages) > 1 else ""

        try:
            headers = {
                "x-pan-token": self.valves.PRISMA_API_KEY.strip(),
                "Content-Type": "application/json"
            }
            payload = {
                "metadata": {
                    "ai_model": body.get("model", "unknown"),
                    "app_name": "Open WebUI",
                    "app_user": "local-user"
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
                verify=False
            )

            if response.status_code == 200:
                data = response.json()

                if data.get("timeout"):
                    body["messages"][-1]["content"] += (
                        "\n\n---\n"
                        "⚠️ **PRISMA AIRS:** Scan timed out — result may be incomplete."
                    )
                    status = "⚠️ Scan Timed Out"

                elif data.get("error"):
                    errors = data.get("errors", [])
                    error_detail = ", ".join(str(e) for e in errors) if errors else "Unknown error"
                    body["messages"][-1]["content"] += (
                        "\n\n---\n"
                        f"❌ **PRISMA AIRS:** API error — {error_detail}"
                    )
                    status = f"❌ API Error: {error_detail}"

                else:
                    p_data = data.get("prompt_detected", {})
                    p_details = data.get("prompt_detection_details", {})
                    p_report = self.get_risk_description(p_data, p_details, self.PROMPT_FIELD_MAP)

                    r_data = data.get("response_detected", {})
                    r_details = data.get("response_detection_details", {})
                    r_report = self.get_risk_description(r_data, r_details, self.RESPONSE_FIELD_MAP)

                    is_risk = data.get("action") == "block" or any(p_data.values()) or any(r_data.values())

                    if is_risk:
                        api_category = data.get("category", "")
                        category_label = f" — `{api_category}`" if api_category else ""

                        dlp_line = ""
                        masked_data = data.get("response_masked_data")
                        if masked_data and r_data.get("dlp"):
                            dlp_summary = self.get_dlp_pattern_summary(masked_data)
                            if dlp_summary:
                                dlp_line = f"\n**DLP Patterns:** {dlp_summary}"

                        body["messages"][-1]["content"] += (
                            f"\n\n---\n"
                            f"🚨 **PRISMA AIRS SECURITY ALERT**{category_label}\n"
                            f"**Prompt:** {p_report}\n"
                            f"**Response:** {r_report}"
                            f"{dlp_line}"
                        )
                        status = f"🚩 Risk Detected: {p_report if any(p_data.values()) else r_report}"
                    else:
                        status = "✅ Safe"

            else:
                status = f"⚠️ Scan Error: HTTP {response.status_code}"

        except Exception as e:
            status = f"❌ Analysis Error: {str(e)}"

        if __event_emitter__:
            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Prisma AIRS: {status}", "done": True}
            })

        return body
