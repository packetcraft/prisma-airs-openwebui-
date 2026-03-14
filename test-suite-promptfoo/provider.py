import os
import sys
import requests

try:
    from prisma_airs_sdk_enforced import Filter
except ImportError:
    print("❌ ERROR: Could not find prisma_airs_sdk_enforced.py")
    sys.exit(1)


async def call_api(prompt, options, context):
    f = Filter()

    # Prisma AIRS credentials
    f.valves.PRISMA_API_KEY = os.environ.get("PRISMA_API_KEY", "")
    f.valves.AI_PROFILE_NAME = os.environ.get("AI_PROFILE_NAME", "ark-sec-profile")

    # Open WebUI connection
    openwebui_url = os.environ.get("OPENWEBUI_URL", "http://localhost:3000")
    openwebui_key = os.environ.get("OPENWEBUI_API_KEY", "")
    openwebui_model = os.environ.get("OPENWEBUI_MODEL", "ol---enforcedsdk")

    if not f.valves.PRISMA_API_KEY:
        return {"error": "PRISMA_API_KEY environment variable not set"}
    if not openwebui_key:
        return {"error": "OPENWEBUI_API_KEY environment variable not set"}

    body = {
        "messages": [
            {"role": "user", "content": prompt},
        ]
    }

    # Stage 1: Inlet — scan the prompt, raises if blocked
    try:
        body = await f.inlet(body)
    except Exception as e:
        print(f"\n--- PRISMA DEBUG [INLET BLOCK] ---\n{e}\n-------------------\n")
        return {"output": str(e)}

    # Stage 2: Send prompt to Open WebUI and get real LLM response
    try:
        response = requests.post(
            f"{openwebui_url}/api/chat/completions",
            headers={
                "Authorization": f"Bearer {openwebui_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": openwebui_model,
                "messages": body["messages"],
                "stream": False,
            },
            timeout=30,
        )
        response.raise_for_status()
        llm_reply = response.json()["choices"][0]["message"]["content"]
        body["messages"].append({"role": "assistant", "content": llm_reply})
    except Exception as e:
        return {"error": f"Open WebUI request failed: {str(e)}"}

    # Stage 3: Outlet — scan the prompt + real LLM response
    try:
        result_body = await f.outlet(body)
        final_output = result_body["messages"][-1]["content"]
        print(f"\n--- PRISMA DEBUG [OUTLET] ---\n{final_output}\n-------------------\n")
        return {"output": final_output}
    except Exception as e:
        return {"error": str(e)}
