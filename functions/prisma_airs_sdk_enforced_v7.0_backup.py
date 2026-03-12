"""
title: Prisma AIRS SDK Enforcement (Block & Mask)
author: Gemini
version: 7.0
requirements: pan-aisecurity
"""

import aisecurity
from aisecurity.scan.inline.scanner import Scanner
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
from aisecurity.scan.models.content import Content
from typing import Awaitable, Callable
from pydantic import BaseModel, Field

class Filter:
    class Valves(BaseModel):
        PRISMA_API_KEY: str = Field(default="", description="Your x-pan-token API Key")
        AI_PROFILE_NAME: str = Field(default="ark-sec-profile", description="AI Security Profile name")

    def __init__(self):
        self.valves = self.Valves()

    async def inlet(self, body: dict, __user__: dict = None, __event_emitter__: Callable[[dict], Awaitable[None]] = None) -> dict:
        """Stage 1: Protect the LLM by blocking malicious prompts."""
        if __event_emitter__:
            await __event_emitter__({"type": "status", "data": {"description": "🛡️ Prisma AIRS: Shielding Prompt...", "done": False}})

        user_prompt = body.get("messages", [])[-1].get("content", "")
        
        try:
            aisecurity.init(api_key=self.valves.PRISMA_API_KEY.strip())
            scanner = Scanner()
            profile = AiProfile(profile_name=self.valves.AI_PROFILE_NAME.strip())
            
            # Perform prompt-only scan
            result = scanner.sync_scan(ai_profile=profile, content=Content(prompt=user_prompt))
            
            if result.action == "block":
                if __event_emitter__:
                    await __event_emitter__({"type": "status", "data": {"description": "🚨 BLOCK: Malicious Prompt", "done": True}})
                # Raise exception to prevent Ollama from processing the prompt
                raise Exception(f"Security Block: Malicious input detected. (Scan ID: {result.scan_id})")

        except Exception as e:
            if "Security Block" in str(e): raise e
            print(f"Inlet Error: {e}")

        return body

    async def outlet(self, body: dict, __user__: dict = None, __event_emitter__: Callable[[dict], Awaitable[None]] = None) -> dict:
        """Stage 2: Sanitize Response - Block threats and MASK sensitive data (DLP)."""
        if __event_emitter__:
            await __event_emitter__({"type": "status", "data": {"description": "🛡️ Prisma AIRS: Sanitizing Response...", "done": False}})

        messages = body.get("messages", [])
        ai_res = messages[-1].get("content", "")
        user_prompt = messages[-2].get("content", "") if len(messages) > 1 else ""

        try:
            aisecurity.init(api_key=self.valves.PRISMA_API_KEY.strip())
            scanner = Scanner()
            profile = AiProfile(profile_name=self.valves.AI_PROFILE_NAME.strip())
            
            # Execute full interaction scan
            result = scanner.sync_scan(ai_profile=profile, content=Content(prompt=user_prompt, response=ai_res))
            
            # Convert to dict for deep inspection of masked_data (as seen in your JSON)
            res_dict = result.to_dict() if hasattr(result, 'to_dict') else {}
            masked_info = res_dict.get("response_masked_data", {})
            has_dlp_hits = len(masked_info.get("pattern_detections", [])) > 0

            # 1. HARD BLOCK: Malicious content (Toxic, Code, etc.)
            if result.action == "block" and not has_dlp_hits:
                body["messages"][-1]["content"] = f"🚨 **Security Block**: Dangerous content detected and removed. (Scan ID: `{result.scan_id}`)"
                status = "🚨 Response Blocked"
            
            # 2. MASKING: Sensitive data like AWS Keys
            elif has_dlp_hits:
                # Replace raw response with the masked version from your API example
                masked_text = masked_info.get("masked_response", " [REDACTED BY SECURITY POLICY] ")
                body["messages"][-1]["content"] = f"{masked_text}\n\n---\n🔐 *Response sanitized (Sensitive patterns detected).* (Scan ID: `{result.scan_id}`)"
                status = "🔐 Response Masked"
            
            else:
                status = "✅ Response Verified"

        except Exception as e:
            status = f"❌ Outlet Error: {e}"

        if __event_emitter__:
            await __event_emitter__({"type": "status", "data": {"description": f"Prisma {status}", "done": True}})
        
        return body
