"""
title: Prisma AIRS SDK Diagnostic (Final Stable v5.7)
author: Gemini
version: 5.7
requirements: pan-aisecurity
"""

import aisecurity
import json
from aisecurity.scan.inline.scanner import Scanner

# Official SDK v0.8.x verified import paths
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
from aisecurity.scan.models.content import Content

from typing import Awaitable, Callable
from pydantic import BaseModel, Field

class Filter:
    class Valves(BaseModel):
        PRISMA_API_KEY: str = Field(default="", description="Your x-pan-token API Key")
        AI_PROFILE_NAME: str = Field(default="ark-sec-profile", description="Your Profile Name")
        APP_NAME: str = Field(default="Open WebUI-SDK-Diag", description="App name for metadata")

    def __init__(self):
        self.valves = self.Valves()

    def get_dlp_summary(self, result) -> str:
        """Extracts granular DLP patterns and hit counts from SDK result object."""
        try:
            raw_data = result.to_dict() if hasattr(result, 'to_dict') else {}
            masked = raw_data.get("response_masked_data", {})
            patterns = masked.get("pattern_detections", [])
            
            if not patterns: return ""
            
            summary = []
            for p in patterns:
                name = p.get("pattern", "Unknown")
                hits = len(p.get("locations", []))
                summary.append(f"{name} ({hits} hit{'s' if hits != 1 else ''})")
            
            return f"\n**[DLP] Patterns:** {', '.join(summary)}"
        except:
            return ""

    def parse_detection_side(self, side_obj):
        """Maps SDK boolean flags for prompt or response sides."""
        risks = []
        if hasattr(side_obj, 'injection') and side_obj.injection: risks.append("Injection")
        if getattr(side_obj, 'dlp', False): risks.append("Data Leakage (DLP)")
        if getattr(side_obj, 'toxic_content', False): risks.append("Toxic Content")
        if getattr(side_obj, 'malicious_code', False): risks.append("Malicious Code")
        if getattr(side_obj, 'url_cats', False): risks.append("Unsafe URL")
        if hasattr(side_obj, 'ungrounded') and side_obj.ungrounded: risks.append("Hallucination")
        
        return ", ".join(risks) if risks else "None Detected"

    async def inlet(self, body: dict, __event_emitter__: Callable[[dict], Awaitable[None]] = None) -> dict:
        return body

    async def outlet(self, body: dict, __user__: dict = None, __event_emitter__: Callable[[dict], Awaitable[None]] = None) -> dict:
        if __event_emitter__:
            await __event_emitter__({"type": "status", "data": {"description": "🔍 Prisma AIRS: SDK Deep Analysis...", "done": False}})

        messages = body.get("messages", [])
        ai_res, user_prompt = messages[-1].get("content", ""), (messages[-2].get("content", "") if len(messages) > 1 else "")

        try:
            # Global initialization
            aisecurity.init(api_key=self.valves.PRISMA_API_KEY.strip())
            scanner = Scanner()
            ai_profile = AiProfile(profile_name=self.valves.AI_PROFILE_NAME.strip())
            content = Content(prompt=user_prompt, response=ai_res)
            
            # Execute Sync Scan
            result = scanner.sync_scan(
                ai_profile=ai_profile, 
                content=content,
                metadata={
                    "ai_model": body.get("model", "Ollama"),
                    "app_name": self.valves.APP_NAME,
                    "app_user": __user__.get("email", "local-user") if __user__ else "local-user"
                }
            )
            
            p_report = self.parse_detection_side(result.prompt_detected)
            r_report = self.parse_detection_side(result.response_detected)
            dlp_line = self.get_dlp_summary(result)
            is_risk = result.action == "block"
            
            # Diagnostic Footer UI
            report = (
                f"\n\n---\n"
                f"{'🚨' if is_risk else '✅'} **PRISMA AIRS SDK DIAGNOSTIC**\n"
                f"**Overall Verdict:** {result.action.upper()} — API Category: `{getattr(result, 'category', 'N/A')}`\n"
                f"**Scan ID:** `{result.scan_id}` | **Report ID:** `{getattr(result, 'report_id', 'N/A')}`\n\n"
                f"**[1] Prompt Detected (Input):** {p_report}\n"
                f"**[2] Response Detected (Output):** {r_report}\n"
                f"{dlp_line}\n"
            )
            
            body["messages"][-1]["content"] += report
            status = f"SDK Verdict: {result.action.upper()}"

        except Exception as e:
            status = f"❌ SDK Scan Error: {str(e)}"

        if __event_emitter__:
            await __event_emitter__({"type": "status", "data": {"description": f"Prisma {status}", "done": True}})
        
        return body
