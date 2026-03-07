"""
title: Prisma AIRS Security Interceptor (Full Diagnostic Mode)
author: Gemini
version: 4.2
"""

import uuid
from typing import Awaitable, Callable, Optional
import requests
import urllib3
from pydantic import BaseModel, Field

# Suppress insecure connection warnings for local development
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Filter:
    class Valves(BaseModel):
        PRISMA_API_URL: str = Field(
            default="https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request"
        )
        PRISMA_API_KEY: str = Field(
            default="",
            description="Your x-pan-token API Key",
        )
        AI_PROFILE_NAME: str = Field(
            default="",
            description="The AI Security Profile name from Strata Cloud Manager",
        )

    def __init__(self):
        self.valves = self.Valves()

    def get_detailed_report(self, detection_data: dict, details: dict = None) -> str:
        """Parses specific AIRS flags into a readable string for testing."""
        active_risks = []

        # Standard Boolean Flags
        mapping = {
            "injection": "Injection",
            "dlp": "Data Leakage (DLP)",
            "toxic_content": "Toxic Content",
            "malicious_code": "Malicious Code",
            "url_cats": "Unsafe URL",
            "agent": "Agent System Abuse",
            "ungrounded": "Hallucination/Ungrounded",
            "db_security": "Database Security Risk",
        }

        for key, label in mapping.items():
            if detection_data.get(key):
                active_risks.append(label)

        # Pull Granular Categories from JSON 'details'
        if details and "toxic_content_details" in details:
            cats = details["toxic_content_details"].get("toxic_categories", [])
            if cats:
                active_risks.append(f"({', '.join(cats)})")

        return ", ".join(active_risks) if active_risks else "None Detected"

    async def inlet(
        self, body: dict, __event_emitter__: Callable[[dict], Awaitable[None]] = None
    ) -> dict:
        """Pass-through for the user prompt."""
        return body

    async def outlet(
        self, body: dict, __event_emitter__: Callable[[dict], Awaitable[None]] = None
    ) -> dict:
        """Performs DualPass scan and appends a detailed diagnostic report for Prompt vs. Response."""
        if __event_emitter__:
            await __event_emitter__(
                {
                    "type": "status",
                    "data": {
                        "description": "🔍 Prisma AIRS: Full Diagnostic DualPass Scan...",
                        "done": False,
                    },
                }
            )

        # Extract context
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
                    "ai_model": body.get("model", "Research-Model"),
                    "app_name": "Open WebUI-Diag",
                    "app_user": "security-tester",
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

            if response.status_code == 200:
                data = response.json()

                # Parse Prompt Detection
                p_data = data.get("prompt_detected", {})
                p_details = data.get("prompt_detection_details", {})
                p_report = self.get_detailed_report(p_data, p_details)

                # Parse Response Detection
                r_data = data.get("response_detected", {})
                r_report = self.get_detailed_report(r_data)

                # Determine Final Verdict
                is_risk = (
                    data.get("action") == "block"
                    or any(p_data.values())
                    or any(r_data.values())
                )
                header_icon = "🚨" if is_risk else "✅"
                verdict_text = "BLOCK/RISK DETECTED" if is_risk else "SAFE"

                # Construct the Diagnostic Report
                report = (
                    f"\n\n---\n"
                    f"{header_icon} **PRISMA AIRS SECURITY DIAGNOSTIC**\n"
                    f"**Overall Verdict:** {verdict_text}\n"
                    f"**Scan ID:** `{data.get('scan_id', 'N/A')}`\n\n"
                    f"**[1] Prompt Detected (Input):** {p_report}\n"
                    f"**[2] Response Detected (Output):** {r_report}\n"
                )

                body["messages"][-1]["content"] += report
                status = f"Report Generated: {verdict_text}"
            else:
                status = f"⚠️ Scan Error: {response.status_code}"

        except Exception as e:
            status = f"❌ Analysis Error: {str(e)}"

        if __event_emitter__:
            await __event_emitter__(
                {
                    "type": "status",
                    "data": {"description": f"Prisma AIRS: {status}", "done": True},
                }
            )

        return body
