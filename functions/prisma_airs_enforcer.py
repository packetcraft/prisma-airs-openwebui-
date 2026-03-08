"""
title: Prisma AIRS Enforcer
author: Gemini
version: 3.3

Flow:
  [INLET]  Scan prompt immediately.
           → Risk detected : raise Exception — LLM never invoked.
           → Safe          : emit "💬 LLM generating response" banner
                             that stays visible throughout LLM generation.

  [OUTLET] After LLM finishes streaming, emit a hard "scanning" status
           (done=False) while the dual-pass scan runs.
           → Risk detected : OVERWRITE the full response with a block message.
           → Safe          : response left unchanged, status cleared.

Note: visually obscuring the *stream itself* while tokens are being generated
is not possible with a Filter outlet hook — the outlet only runs after streaming
is complete. True pre-clearance buffering requires a Pipe function. The
persistent status banners (done=False) are the achievable UX equivalent.
"""

import uuid
from typing import Awaitable, Callable
import requests
import urllib3
from pydantic import BaseModel, Field

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
            default="", description="The AI Security Profile name from Strata Cloud Manager"
        )
        APP_NAME: str = Field(default="Open WebUI", description="The app name for API metadata")
        CONTEXT: str = Field(default="", description="Optional context for grounding detection")
        ENABLE_DLP_MASKING: bool = Field(
            default=True,
            description="If True, sensitive data will be masked instead of blocked if no other risks exist."
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

    async def inlet(
        self, body: dict, __user__: dict = None, __event_emitter__: Callable[[dict], Awaitable[None]] = None
    ) -> dict:
        """Scans the prompt immediately. Blocks the request if any risk is detected.
        If safe, emits a persistent banner indicating the LLM is generating,
        which remains visible throughout the LLM generation phase."""

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
            # Dynamic metadata from __user__
            user_email = "local-user"
            if __user__ and "email" in __user__:
                user_email = __user__["email"]

            headers = {
                "x-pan-token": self.valves.PRISMA_API_KEY.strip(),
                "Content-Type": "application/json",
            }

            content_obj = {"prompt": user_msg, "response": ""}
            if self.valves.CONTEXT.strip():
                content_obj["context"] = self.valves.CONTEXT.strip()

            payload = {
                "metadata": {
                    "ai_model": body.get("model"),
                    "app_name": self.valves.APP_NAME.strip(),
                    "app_user": user_email,
                },
                "contents": [content_obj],
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
                prompt_risks = data.get("prompt_detected", {})
                prompt_details = data.get("prompt_detection_details", {})

                if data.get("action") == "block" or any(prompt_risks.values()):
                    risk_name = self.get_risk_description(prompt_risks, prompt_details, self.PROMPT_FIELD_MAP)

                    if __event_emitter__:
                        await __event_emitter__({
                            "type": "status",
                            "data": {"description": f"🚫 Blocked at Prompt: {risk_name}", "done": True},
                        })

                    raise Exception(f"🚫 PRISMA AIRS BLOCK — {risk_name}")

            # Emit done=False so this banner stays visible throughout LLM generation
            if __event_emitter__:
                await __event_emitter__({
                    "type": "status",
                    "data": {"description": "💬 LLM generating response — Prisma AIRS scan will follow", "done": False},
                })
            return body

        except Exception as e:
            if "PRISMA AIRS BLOCK" in str(e):
                raise e
            if __event_emitter__:
                await __event_emitter__({
                    "type": "status",
                    "data": {"description": f"Prisma AIRS: ❌ Scan Error: {str(e)}", "done": True},
                })
            return body

    async def outlet(
        self, body: dict, __user__: dict = None, __event_emitter__: Callable[[dict], Awaitable[None]] = None
    ) -> dict:
        """Dual-pass scan of prompt + response after LLM generation.
        Overwrites the full response with a block message if any risk is detected.
        If ONLY sensitive data (DLP) is detected and masking is enabled, returns masked text."""

        if not self.valves.PRISMA_API_KEY.strip() or not self.valves.AI_PROFILE_NAME.strip():
            return body

        if __event_emitter__:
            await __event_emitter__({
                "type": "status",
                "data": {"description": "🔍 Prisma AIRS: Scanning response...", "done": False},
            })

        messages = body.get("messages", [])
        ai_res = messages[-1].get("content", "")
        user_prompt = messages[-2].get("content", "") if len(messages) > 1 else ""

        try:
            # Dynamic metadata from __user__
            user_email = "local-user"
            if __user__ and "email" in __user__:
                user_email = __user__["email"]

            headers = {
                "x-pan-token": self.valves.PRISMA_API_KEY.strip(),
                "Content-Type": "application/json",
            }

            content_obj = {"prompt": user_prompt, "response": ai_res}
            if self.valves.CONTEXT.strip():
                content_obj["context"] = self.valves.CONTEXT.strip()

            payload = {
                "metadata": {
                    "ai_model": body.get("model"),
                    "app_name": self.valves.APP_NAME.strip(),
                    "app_user": user_email,
                },
                "contents": [content_obj],
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

                if data.get("timeout"):
                    body["messages"][-1]["content"] = (
                        "⚠️ **PRISMA AIRS BLOCK** — scan timed out\n"
                        "Response blocked as a precaution. Please retry."
                    )
                    status = "⚠️ Scan Timeout — blocked for safety"

                elif data.get("error"):
                    errors = data.get("errors", [])
                    error_detail = ", ".join(str(e) for e in errors) if errors else "Unknown error"
                    body["messages"][-1]["content"] = (
                        f"❌ **PRISMA AIRS BLOCK** — API error during response scan\n"
                        f"{error_detail}\n"
                        "Response blocked as a precaution."
                    )
                    status = f"❌ API Error: {error_detail}"

                else:
                    p_data = data.get("prompt_detected", {})
                    p_details = data.get("prompt_detection_details", {})
                    p_report = self.get_risk_description(p_data, p_details, self.PROMPT_FIELD_MAP)

                    r_data = data.get("response_detected", {})
                    r_details = data.get("response_detection_details", {})
                    r_report = self.get_risk_description(r_data, r_details, self.RESPONSE_FIELD_MAP)

                    # Determine if we should block or mask
                    p_hits = any(p_data.values())
                    # Maskable if ONLY DLP is hitting on the response and prompt is clean
                    r_hits_non_dlp = any(v for k, v in r_data.items() if k != "dlp")

                    is_risk = data.get("action") == "block" or p_hits or any(r_data.values())

                    if is_risk:
                        masked_data = data.get("response_masked_data")

                        # Use masking if enabled and only DLP/non-hard risks triggered on response
                        if self.valves.ENABLE_DLP_MASKING and not p_hits and not r_hits_non_dlp and r_data.get("dlp") and masked_data:
                            body["messages"][-1]["content"] = masked_data.get("data", ai_res) + "\n\n*[Prisma AIRS: Sensitive data masked]*"
                            status = "✅ Response Masked (DLP)"
                        else:
                            api_category = data.get("category", "")
                            category_label = f" — `{api_category}`" if api_category else ""

                            dlp_line = ""
                            if masked_data and r_data.get("dlp"):
                                dlp_summary = self.get_dlp_pattern_summary(masked_data)
                                if dlp_summary:
                                    dlp_line = f"\n**DLP Patterns:** {dlp_summary}"

                            body["messages"][-1]["content"] = (
                                f"🚫 **PRISMA AIRS BLOCK**{category_label}\n"
                                f"**Prompt:** {p_report}\n"
                                f"**Response:** {r_report}"
                                f"{dlp_line}"
                            )
                            status = f"🚫 Blocked: {p_report if p_hits else r_report}"

                    else:
                        status = "✅ Response Cleared"

            else:
                status = f"⚠️ Scan Error: HTTP {response.status_code}"

        except Exception as e:
            status = f"❌ Integrity Scan Failed: {str(e)}"

        if __event_emitter__:
            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Prisma AIRS: {status}", "done": True},
            })
        return body
