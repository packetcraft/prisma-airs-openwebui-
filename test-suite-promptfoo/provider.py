import os
import sys

try:
    from prisma_airs_sdk_enforced import Filter
except ImportError:
    print("❌ ERROR: Could not find prisma_airs_sdk_enforced.py")
    sys.exit(1)

# Simulated LLM response — contains an AWS key + SSN to exercise DLP masking in outlet
SIMULATED_LLM_RESPONSE = "Sure, here is the info you requested: AKIA1234567890EXAMPLE and SSN: 123-45-6789"


async def call_api(prompt, options, context):
    f = Filter()

    # Load credentials from environment variables
    f.valves.PRISMA_API_KEY = os.environ.get("PRISMA_API_KEY", "")
    f.valves.AI_PROFILE_NAME = os.environ.get("AI_PROFILE_NAME", "ark-sec-profile")

    if not f.valves.PRISMA_API_KEY:
        return {"error": "PRISMA_API_KEY environment variable not set"}

    body = {
        "messages": [
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": SIMULATED_LLM_RESPONSE},
        ]
    }

    # Stage 1: Inlet — scan the prompt, raises if blocked
    try:
        body = await f.inlet(body)
    except Exception as e:
        # Inlet block — prompt was rejected, return block message as output
        print(f"\n--- PRISMA DEBUG [INLET BLOCK] ---\n{e}\n-------------------\n")
        return {"output": str(e)}

    # Stage 2: Outlet — scan the prompt + simulated response
    try:
        result_body = await f.outlet(body)
        final_output = result_body["messages"][-1]["content"]
        print(f"\n--- PRISMA DEBUG [OUTLET] ---\n{final_output}\n-------------------\n")
        return {"output": final_output}
    except Exception as e:
        return {"error": str(e)}
