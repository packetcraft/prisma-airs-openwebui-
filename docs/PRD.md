# Product Requirements Document — Prisma AIRS Security Interceptor for Open WebUI

## Overview

This project integrates Palo Alto Networks Prisma AIRS (AI Runtime Security) into Open WebUI as a Python Filter middleware. It provides real-time prompt and response scanning for local LLM deployments running on Ollama.

Three filter functions are provided, each targeting a different use case:

| Filter | File | Purpose |
| --- | --- | --- |
| **Detection Mode** | `prisma_airs_interceptor_(detection_mode).py` | Flags threats by appending a compact security alert to the response. Prompt and response always pass through. |
| **Block Mode** | `prisma_airs_interceptor_(block_mode).py` | Hard-blocks prompts before they reach the LLM; overwrites flagged responses with a block message. |
| **Diagnostic Mode** | `prisma_airs_diagnosis_scan.py` | Full diagnostic report with raw API JSON appended. For security testing and development. |

---

## Filter Architecture

Open WebUI Filters expose two hooks per message cycle:

- **`inlet`** — runs before the LLM generates. Receives and can modify the user prompt.
- **`outlet`** — runs after the LLM finishes streaming. Receives and can modify the AI response.

Both hooks can emit status events visible in the chat UI via `__event_emitter__`.

---

## Detection Mode — Request Flow (v2.7)

```
User sends prompt
      │
      ▼
[INLET]  Pass-through — no scan, no API call
      │
      ▼
[LLM STREAMING] response appears in chat
      │
      ▼
[OUTLET] "🔍 Prisma AIRS: Scanning..."   ← status bar (done=False)
      │
      │  Single dual-pass API call: prompt + response together
      │
      │ risk ↓
      ▼  APPEND to response:
         ---
         🚨 PRISMA AIRS SECURITY ALERT — `malicious`
         **Prompt:** Injection, Toxic Content (Cybercrimes)
         **Response:** Database Security Risk, Sensitive Data (DLP)
         **DLP Patterns:** Credit Card Number (1 hit), Tax Id - US - TIN (3 hits)
      │
      │ safe ↓
      ▼  Nothing appended — "✅ Safe" shown in status bar
```

---

## Block Mode — Request Flow

### v3.2 (previous)

```
User sends prompt
      │
      ▼
[INLET] Scan prompt only ──── risk? ──▶ raise Exception → HARD BLOCK ✋
      │                                  (LLM never invoked)
      │ safe
      ▼
[LLM generates response]
      │
      ▼
[OUTLET] Dual-pass scan (prompt + response) ──── risk? ──▶ OVERWRITE response 🚫
      │                                            (block message shown instead)
      │ safe
      ▼
Response shown to user ✅
```

### v3.3 (current)

```
User sends prompt
      │
      ▼
[INLET] "🔍 Prisma AIRS: Scanning Prompt..."    ← status bar (done=False, spinning)
      │
      │ risk → "🚫 Blocked at Prompt: ..." (done=True) → request killed ✋
      │         LLM never invoked
      │
      │ safe ↓
      ▼
[INLET] "⏳ Response pending security clearance — do not act on content yet"
      │                                    ← done=False banner stays visible
      ▼
[LLM STREAMING] tokens appear in chat window
      │           ^ clearance pending banner still showing above
      ▼
[OUTLET] "🔍 Prisma AIRS: Scanning response..."  ← done=False while scan runs
      │
      │ risk ↓
      ▼  Full response OVERWRITTEN with:
         🚫 PRISMA AIRS BLOCK — `malicious`
         **Prompt:** Injection, Toxic Content (Cybercrimes)
         **Response:** Database Security Risk, Sensitive Data (DLP)
         **DLP Patterns:** Credit Card Number (1 hit), Tax Id - US - TIN (3 hits)
      │
      │ safe ↓
      ▼  "✅ Response Cleared" — original response left untouched
```

**Key difference from v3.2:** The persistent `done=False` inlet banner provides a visual hold signal throughout the entire LLM generation phase, indicating the response has not yet been security-cleared.

---

## Streaming Obscurement — Known Limitation

> **The LLM response stream cannot be visually obscured during token generation using a Filter outlet hook.**

The `outlet` hook only runs **after** the LLM has finished streaming its full response. By the time `outlet` runs, the raw tokens have already been rendered in the user's chat window. Any modifications made in `outlet` (blocking, replacing, appending) only take effect on the final stored message state — they do not retroactively obscure what was shown during streaming.

The `done=False` status banners (clearance pending / scanning) are the achievable UX equivalent: they remain visible throughout the generation and scan phases, signalling to users that content should not be acted upon until clearance is confirmed.

### True pre-clearance buffering — requires a Pipe function

To fully buffer the LLM stream so the user **never sees** the raw response until it has been security-cleared, the implementation must be converted from a **Filter** to a **Pipe** function.

In a Pipe:
- The LLM generates its full response internally (not streamed to the client)
- The Pipe runs the AIRS scan on the complete response
- If safe: the Pipe streams the cleared response to the user
- If blocked: the Pipe streams the block message instead

The user never sees the unchecked content. This is the correct architecture for maximum enforcement.

---

## Diagnostic Mode — Request Flow (v4.5)

```
User sends prompt
      │
      ▼
[INLET]  Pass-through — no scan, no API call
      │
      ▼
[LLM STREAMING] response appears in chat
      │
      ▼
[OUTLET] "🔍 Prisma AIRS: Security Analysis + Raw Debug..."  ← done=False
      │
      │  Single dual-pass API call: prompt + response together
      │
      ▼  APPEND to response:
         ---
         🚨 / ✅  PRISMA AIRS SECURITY DIAGNOSTIC
         **Overall Verdict:** BLOCK/RISK DETECTED — API Category: `malicious`
         **Scan ID:** `xxx` | **Report ID:** `xxx`

         **[1] Prompt Detected (Input):** Injection, Toxic Content (Cybercrimes)
         **[2] Response Detected (Output):** Database Security Risk
         **[DLP] Patterns: Credit Card Number (1 hit)**

         **Raw API Response (JSON):**
         ```json
         { ... full AIRS API response ... }
         ```
```

---

## API Schema Notes

The Prisma AIRS API returns asymmetric field sets for prompt vs response detections:

| Field | `prompt_detected` | `response_detected` |
| --- | :---: | :---: |
| `injection` | ✅ | ✗ |
| `agent` | ✅ | ✗ |
| `dlp` | ✅ | ✅ |
| `toxic_content` | ✅ | ✅ |
| `malicious_code` | ✅ | ✅ |
| `url_cats` | ✅ | ✅ |
| `db_security` | ✗ | ✅ |
| `ungrounded` | ✗ | ✅ |

All three filters use separate `PROMPT_FIELD_MAP` and `RESPONSE_FIELD_MAP` to match this schema.

---

## Block Message Format (Detection and Block Mode)

Both modes use a consistent compact format. Detection mode **appends**; block mode **overwrites**.

```
🚨 / 🚫  PRISMA AIRS SECURITY ALERT / BLOCK — `<api_category>`
**Prompt:** <comma-separated risk labels>
**Response:** <comma-separated risk labels>
**DLP Patterns:** <pattern name> (<N> hit/hits), ...   ← only when dlp: true in response
```

Toxic categories are always rendered inline: `Toxic Content (Cybercrimes, Other Non-violent crime and Misconduct)`.
