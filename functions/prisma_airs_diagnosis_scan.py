"""
title: Prisma AIRS Security Interceptor (Full Diagnostic + Raw JSON)
author: Gemini
version: 4.4
"""

import uuid
import json
from typing import Awaitable, Callable
import requests
import urllib3
from pydantic import BaseModel, Field

# Suppress insecure connection warnings
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

    # Improvement #2: separate mappings per the actual API field sets
    PROMPT_FIELD_MAP = {
        "injection": "Injection",
        "agent": "Agent System Abuse",
        "dlp": "Data Leakage (DLP)",
        "toxic_content": "Toxic Content",
        "malicious_code": "Malicious Code",
        "url_cats": "Unsafe URL",
    }

    RESPONSE_FIELD_MAP = {
        "dlp": "Data Leakage (DLP)",
        "toxic_content": "Toxic Content",
        "malicious_code": "Malicious Code",
        "url_cats": "Unsafe URL",
        "db_security": "Database Security Risk",
        "ungrounded": "Hallucination/Ungrounded",
    }

    def get_detailed_report(self, detection_data: dict, details: dict = None, field_map: dict = None) -> str:
        """Parses AIRS detection flags into a readable string using the correct field map."""
        if field_map is None:
            field_map = self.PROMPT_FIELD_MAP
        active_risks = []

        for key, label in field_map.items():
            if detection_data.get(key):
                active_risks.append(label)

        # Pull granular toxic categories from details
        if details and "toxic_content_details" in details:
            cats = details["toxic_content_details"].get("toxic_categories", [])
            if cats:
                active_risks.append(f"({', '.join(cats)})")

        return ", ".join(active_risks) if active_risks else "None Detected"

    def get_dlp_pattern_summary(self, masked_data: dict) -> str:
        """Improvement #1: Extracts DLP pattern names and hit counts from response_masked_data."""
        pattern_detections = masked_data.get("pattern_detections", [])
        if not pattern_detections:
            return ""
        counts = {}
        for detection in pattern_detections:
            pattern = detection.get("pattern", "Unknown")
            hits = len(detection.get("locations", []))
            counts[pattern] = counts.get(pattern, 0) + hits
        summary = ", ".join(f"{name} ({hits} hit{'s' if hits != 1 else ''})" for name, hits in counts.items())
        return f"Patterns: {summary}"

    async def inlet(self, body: dict, __event_emitter__: Callable[[dict], Awaitable[None]] = None) -> dict:
        """Pass-through for the user prompt — diagnostic mode does not block at inlet."""
        return body

    async def outlet(self, body: dict, __event_emitter__: Callable[[dict], Awaitable[None]] = None) -> dict:
        """Performs a dual-pass scan and appends a detailed diagnostic report with Raw JSON."""

        # Improvement #8: early credential check
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
                "data": {"description": "🔍 Prisma AIRS: Security Analysis + Raw Debug...", "done": False}
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
                    "ai_model": body.get("model", "Research-Model"),
                    "app_name": "Open WebUI-Diag",
                    "app_user": "security-tester"
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

                # Improvement #3: check timeout flag
                if data.get("timeout"):
                    body["messages"][-1]["content"] += (
                        "\n\n---\n"
                        "⚠️ **PRISMA AIRS DIAGNOSTIC — SCAN TIMEOUT**\n"
                        "The API scan timed out. This result is incomplete and should not be trusted.\n"
                        f"**Scan ID:** `{data.get('scan_id', 'N/A')}`"
                    )
                    status = "⚠️ Scan Timed Out — result unreliable"
                else:
                    # Improvement #4: check error fields
                    if data.get("error"):
                        errors = data.get("errors", [])
                        error_detail = ", ".join(str(e) for e in errors) if errors else "Unknown error"
                        body["messages"][-1]["content"] += (
                            "\n\n---\n"
                            "❌ **PRISMA AIRS DIAGNOSTIC — API ERROR**\n"
                            f"**Error:** {error_detail}\n"
                            f"**Scan ID:** `{data.get('scan_id', 'N/A')}`"
                        )
                        status = f"❌ API Error: {error_detail}"
                    else:
                        # Improvement #2: use correct field maps per section
                        p_data = data.get("prompt_detected", {})
                        p_details = data.get("prompt_detection_details", {})
                        p_report = self.get_detailed_report(p_data, p_details, self.PROMPT_FIELD_MAP)

                        r_data = data.get("response_detected", {})
                        r_details = data.get("response_detection_details", {})
                        r_report = self.get_detailed_report(r_data, r_details, self.RESPONSE_FIELD_MAP)

                        # Improvement #1: parse response_masked_data for DLP pattern details
                        masked_data = data.get("response_masked_data")
                        dlp_pattern_line = ""
                        if masked_data:
                            dlp_summary = self.get_dlp_pattern_summary(masked_data)
                            if dlp_summary:
                                dlp_pattern_line = f"**[DLP] {dlp_summary}**\n"

                        # Improvement #6: use API category field in verdict
                        api_category = data.get("category", "")
                        is_risk = data.get("action") == "block" or any(p_data.values()) or any(r_data.values())
                        header_icon = "🚨" if is_risk else "✅"
                        verdict_text = f"BLOCK/RISK DETECTED" if is_risk else "SAFE"
                        category_label = f" — API Category: `{api_category}`" if api_category else ""

                        # Improvement #5: show both scan_id and report_id
                        scan_id = data.get("scan_id", "N/A")
                        report_id = data.get("report_id", "N/A")

                        # Improvement #7: show tool_detected if non-empty
                        tool_detected = data.get("tool_detected", {})
                        tool_line = ""
                        if tool_detected:
                            tool_line = f"**[Tool Detected]:** `{json.dumps(tool_detected)}`\n"

                        # Construct visual report
                        report = (
                            f"\n\n---\n"
                            f"{header_icon} **PRISMA AIRS SECURITY DIAGNOSTIC**\n"
                            f"**Overall Verdict:** {verdict_text}{category_label}\n"
                            f"**Scan ID:** `{scan_id}` | **Report ID:** `{report_id}`\n\n"
                            f"**[1] Prompt Detected (Input):** {p_report}\n"
                            f"**[2] Response Detected (Output):** {r_report}\n"
                            f"{dlp_pattern_line}"
                            f"{tool_line}"
                            f"\n**Raw API Response (JSON):**\n"
                            f"```json\n{json.dumps(data, indent=2)}\n```"
                        )

                        body["messages"][-1]["content"] += report
                        status = f"{'🚨' if is_risk else '✅'} Report Generated: {verdict_text}"

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
