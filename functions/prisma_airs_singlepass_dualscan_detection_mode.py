"""
title: Prisma AIRS Security Interceptor (Single-Pass Dual Scan)
author: Gemini
version: 4.0
"""

import uuid
from typing import Awaitable, Callable, Optional
import requests
import urllib3
from pydantic import BaseModel, Field

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Filter:
    class Valves(BaseModel):
        PRISMA_API_URL: str = Field(default="https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request")
        PRISMA_API_KEY: str = Field(default="", description="Your x-pan-token")
        AI_PROFILE_NAME: str = Field(default="", description="Your Profile Name")

    def __init__(self):
        self.valves = self.Valves()

    def get_risk_description(self, data: dict) -> str:
        """Helper to combine risks from both prompt and response."""
        risks = []
        p_detect = data.get("prompt_detected", {})
        r_detect = data.get("response_detected", {})
        
        # Check both prompt and response bits
        for detect in [p_detect, r_detect]:
            if detect.get("injection"): risks.append("Injection")
            if detect.get("dlp"): risks.append("Sensitive Data (DLP)")
            if detect.get("toxic_content"): risks.append("Toxic Content")
            if detect.get("malicious_code"): risks.append("Malicious Code")
        
        # Add granular toxic categories from details if available
        details = data.get("prompt_detection_details", {})
        if "toxic_content_details" in details:
            cats = details["toxic_content_details"].get("toxic_categories", [])
            if cats: risks.append(f"({', '.join(cats)})")
            
        return ", ".join(list(set(risks))) if risks else "Policy Violation"

    async def inlet(self, body: dict, __event_emitter__: Callable[[dict], Awaitable[None]] = None) -> dict:
        """Pass-through: We wait for the LLM to finish first."""
        return body

    async def outlet(self, body: dict, __event_emitter__: Callable[[dict], Awaitable[None]] = None) -> dict:
        """The 'Single Pass': Scans both prompt and response together."""
        if __event_emitter__:
            await __event_emitter__({"type": "status", "data": {"description": "🔍 Prisma AIRS: Deep Scanning Full Interaction...", "done": False}})

        # Gather context
        messages = body.get("messages", [])
        ai_res = messages[-1].get("content", "")
        user_prompt = messages[-2].get("content", "") if len(messages) > 1 else ""

        try:
            headers = {"x-pan-token": self.valves.PRISMA_API_KEY.strip(), "Content-Type": "application/json"}
            payload = {
                "metadata": {"ai_model": body.get("model"), "app_name": "Open WebUI", "app_user": "local-user"},
                "contents": [{"prompt": user_prompt, "response": ai_res}], # Dual Scan content
                "tr_id": str(uuid.uuid4())[:8],
                "ai_profile": {"profile_name": self.valves.AI_PROFILE_NAME.strip()},
            }
            
            response = requests.post(self.valves.PRISMA_API_URL, json=payload, headers=headers, timeout=15, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                p_risk = any(data.get("prompt_detected", {}).values())
                r_risk = any(data.get("response_detected", {}).values())
                
                if data.get("action") == "block" or p_risk or r_risk:
                    risk_name = self.get_risk_description(data)
                    # REDACTION: Overwrite the response so the user never sees it
                    body["messages"][-1]["content"] = f"🚨 **PRISMA AIRS SECURITY BLOCK:** This interaction was redacted due to {risk_name}."
                    status = f"🚩 Risk: {risk_name}"
                else:
                    status = "✅ Interaction Safe"
            else:
                status = f"⚠️ Scan Error {response.status_code}"

        except Exception as e:
            status = f"❌ Scan Error: {str(e)}"

        if __event_emitter__:
            await __event_emitter__({"type": "status", "data": {"description": f"Prisma AIRS: {status}", "done": True}})
        
        return body
