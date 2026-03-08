# Product Requirements Document — Prisma AIRS Security Interceptor for Open WebUI

## Overview

This project integrates Palo Alto Networks Prisma AIRS (AI Runtime Security) into Open WebUI as a Python Filter middleware. It provides real-time prompt and response scanning for local LLM deployments running on Ollama.

Three filter functions are provided, each targeting a different use case:

| Filter | File | Purpose |
| --- | --- | --- |
| **Detector** | `prisma_airs_detector.py` | Flags threats by appending a compact security alert to the response. Prompt and response always pass through. |
| **Enforcer** | `prisma_airs_enforcer.py` | Hard-blocks prompts before they reach the LLM; overwrites flagged responses with a block message. |
| **Diagnostics** | `prisma_airs_diagnostics.py` | Full diagnostic report with raw API JSON appended. For security testing and development. |

---

## Filter Architecture

Open WebUI Filters expose two hooks per message cycle:

- **`inlet`** — runs before the LLM generates. Receives and can modify the user prompt.
- **`outlet`** — runs after the LLM finishes streaming. Receives and can modify the AI response.

Both hooks can emit status events visible in the chat UI via `__event_emitter__`.

---

## Detector — Request Flow

### v2.6 (previous)

```
User sends prompt
      │
      ▼
[INLET] "🔍 Prisma AIRS: Scanning Prompt..."    ← status bar (done=False)
      │
      │  API call — prompt only (response: "")
      │
      │ risk ↓
      ▼  PREPEND warning to user message (LLM sees the alert in its own context):
         🚨 PRISMA AIRS SECURITY ALERT: Injection, Toxic Content (Cybercrimes)

         <original user prompt>
      │
      │ safe ↓
      ▼ "✅ Prompt Safe" — prompt unchanged, LLM invoked
      │
      ▼
[LLM STREAMING] response appears in chat
      │
      ▼
[OUTLET] "🔍 Prisma AIRS: Scanning Response..."   ← status bar (done=False)
      │
      │  Second API call — response only
      │
      │ risk ↓
      ▼  APPEND to response:
         ---
         🚨 PRISMA AIRS SECURITY ALERT: Database Security Risk detected in output.
      │
      │ safe ↓
      ▼  Nothing appended — "✅ Response Safe" in status bar
```

**Problem with v2.6:** Two separate API calls per turn (inlet + outlet). The inlet prepends the security alert to the prompt, which the LLM reads as part of its own context — causing cascade signals where the model adjusts its output in response to seeing its own alert banner.

### v2.7 (current)

```
User sends prompt
      │
      ▼
[INLET]  Pass-through — no scan, no API call
      │  LLM sees the clean, unmodified prompt
      ▼
[LLM STREAMING] response appears in chat
      │
      ▼
[OUTLET] "🔍 Prisma AIRS: Scanning..."    ← status bar (done=False)
      │
      │  Single dual-pass API call: prompt + response together
      │
      ├─ timeout ──▶ APPEND: "⚠️ Prisma AIRS: Scan timed out — result may be incomplete."
      │
      ├─ API error ──▶ APPEND: "❌ Prisma AIRS: API error — <detail>"
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
      ▼  Nothing appended — "✅ Safe" in status bar
```

**Key improvements over v2.6:**
- Single API call instead of two — lower latency, fewer AIRS quota units consumed.
- No cascade signal — the LLM never reads its own security alert during generation.
- Timeout and API error cases surfaced as visible inline messages.
- DLP pattern detail (pattern names + hit counts) shown when `dlp: true` fires on response.

---

## Enforcer — Request Flow

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
[INLET] "💬 LLM generating response — Prisma AIRS scan will follow"
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

### v3.4 (current)

```
User sends prompt
      │
      ▼
[INLET] "🔍 Prisma AIRS: Scanning Prompt..."    ← status bar (done=False)
      │
      │ risk → "🚫 Blocked at Prompt: ..." (done=True) → request killed ✋
      │
      │ safe ↓
      ▼
[INLET] "💬 LLM generating response — Prisma AIRS scan will follow"
      │
      ▼
[LLM STREAMING] tokens appear in chat window
      │
      ▼
[OUTLET] "🔍 Prisma AIRS: Scanning response..."
      │
      ├─ dual-pass risk (non-DLP or hard block) ─▶ Full response OVERWRITTEN
      │                                          🚫 PRISMA AIRS BLOCK
      │
      ├─ DLP-only risk ─▶ Append Prominent Masking Marker
      │                  🛡️ **[PRISMA AIRS: SENSITIVE DATA MASKED]** 🛡️
      │
      └─ safe ─▶ "✅ Response Cleared" — original response untouched
```

**Key difference from v3.3:** Introduced attention-grabbing visual clues (shield emojis and bold markers) when masking sensitive data to ensure security actions are not missed by the user.

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

## Diagnostics — Request Flow (v4.5)

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

## Alert / Block Message Format (Detector and Enforcer)

Both filters use a consistent compact format. Detector **appends**; Enforcer **overwrites**.

```
🚨 / 🚫  PRISMA AIRS SECURITY ALERT / BLOCK — `<api_category>`
**Prompt:** <comma-separated risk labels>
**Response:** <comma-separated risk labels>
**DLP Patterns:** <pattern name> (<N> hit/hits), ...   ← only when dlp: true in response

---
🛡️ **[PRISMA AIRS: SENSITIVE DATA MASKED]** 🛡️   ← added for DLP violations in Enforcer v3.4
```

Toxic categories are always rendered inline: `Toxic Content (Cybercrimes, Other Non-violent crime and Misconduct)`.
