# Changelog

All notable changes to this project are documented here, organised by version and date.

---

## **[v4.5] - 2026-03-07**

### **Fixed: Toxic Category Inline Formatting**

* **Inline Category Labels**: Toxic categories now render inline with the `Toxic Content` label (e.g. *Toxic Content (Cybercrimes, Misconduct)*) instead of appearing as a separate comma-separated item after it.

---

## **[v4.4] - 2026-03-07**

### **Improved: Diagnosis Scan — Sample-Driven Enhancements**

* **DLP Pattern Detail**: The diagnostic report now extracts and displays specific PII pattern names and hit counts from `response_masked_data` (e.g. *National Id - US SSN (4 hits), Credit Card Number (1 hit)*) instead of the generic "Data Leakage (DLP)" label.
* **Accurate Field Mapping**: Separated `prompt_detected` and `response_detected` into two distinct field maps matching the actual asymmetric API schema confirmed by real scan samples. `injection` and `agent` are prompt-only; `db_security` and `ungrounded` are response-only.
* **Timeout Handling**: Scan results where `timeout: true` are now flagged as unreliable in the report rather than silently reported as SAFE.
* **API Error Surfacing**: `error` and `errors` fields are now checked and displayed in the report when the API returns an error state.
* **Report ID**: Both `scan_id` and `report_id` are now shown in the report header for full Strata console cross-referencing.
* **API Category Label**: The API's top-level `category` field (`malicious` / `benign`) is now shown alongside the verdict.
* **Tool Detection**: `tool_detected` is now shown in the report when non-empty, covering agent/tool abuse scenarios.
* **Credential Validation**: Early check on `PRISMA_API_KEY` and `AI_PROFILE_NAME` — emits a clear error message in the UI if either is unconfigured, instead of a cryptic HTTP 401.

---

## **[v4.3] - 2026-03-07**

### **Added: Full Diagnostic & Raw JSON Mode**

* **Raw JSON Inspection**: Integrated a Markdown code block at the end of every response to show the complete, original Prisma AIRS API JSON for debugging.
* **Diagnostic Split**: The report now explicitly separates findings into **[1] Prompt Detected** and **[2] Response Detected** to mirror the API schema.
* **Scan ID Correlation**: Added the unique `scan_id` to the UI footer to allow auditors to cross-reference local hits with the Prisma Cloud (Strata) console.

---

## **[v4.2] - 2026-03-07**

> *(add release notes here)*

---

## **[v4.1] - 2026-03-07**

### **Added: Research Mode (Non-Redacting)**

* **Content Preservation**: Modified logic to **append** security reports rather than **overwriting** them, allowing testers to see the LLM's raw output.
* **Dual-Pass Scan**: Consolidated prompt and response scanning into a single `outlet` call to prevent LLM "cascade signals" (where the AI reads its own security banner).

---

## **[v4.0] - 2026-03-07**

> *(add release notes here)*

---

## **[v3.3] - 2026-03-08**

### **Improved: Block Mode — Clearance Banner + Unified Report Format**

* **LLM Generating Banner**: After the inlet clears the prompt as safe, a persistent `done=False` status banner — *"💬 LLM generating response — Prisma AIRS scan will follow"* — remains visible throughout the entire LLM generation phase. Framed around the LLM being the active process rather than AIRS being a bottleneck.
* **Hard Scanning Banner in Outlet**: The outlet emits a second `done=False` status — *"🔍 Scanning response..."* — while the dual-pass scan runs after streaming ends, covering the scan latency window.
* **Block Message Format Unified with Detection Mode**: The outlet block message now uses the same `Prompt: / Response: / DLP Patterns:` structure as detection mode, with `🚫 PRISMA AIRS BLOCK — \`category\`` header, replacing the old single-line redaction string.
* **DLP Pattern Detail**: Added `get_dlp_pattern_summary()` — when `dlp: true` fires on the response, the block message includes the specific PII pattern names and hit counts from `response_masked_data`.
* **Timeout and API Error Blocking**: Scan timeouts and API-level errors in the outlet now produce a blocking response instead of silently passing through.
* **Architecture Note**: True visual obscuring of the streamed tokens during LLM generation is not achievable with a Filter outlet hook (which only runs after streaming completes). The persistent `done=False` status banners are the equivalent UX mechanism. A Pipe function would be required for full pre-clearance stream buffering.

---

## **[v3.2] - 2026-03-07**

### **Refactored: Block Mode — Prompt-First Block + Dual-Pass Outlet**

* **Inlet Hard Block**: Prompt is scanned immediately before reaching the LLM. If any risk is detected, the request pipeline is terminated with a `raise Exception` and the LLM is never invoked.
* **Outlet Dual-Pass Block**: After the LLM responds, a single API call scans both the original prompt and the AI response together. If either side triggers a risk, the full response is **overwritten** with a compact block message showing `**Prompt:**` and `**Response:**` findings.
* **Asymmetric Field Maps**: Separated into `PROMPT_FIELD_MAP` and `RESPONSE_FIELD_MAP` matching the actual API schema — response-side detections now correctly use `db_security` and `ungrounded` instead of prompt-only fields.
* **Toxic Category Inline Formatting**: Toxic categories now render inline (e.g. *Toxic Content (Cybercrimes)*) instead of floating as a separate item.
* **Response Detection Details**: `response_detection_details` is now passed when building the outlet block message so toxic categories appear correctly for response-side detections.
* **Credential Validation**: Early check on `PRISMA_API_KEY` and `AI_PROFILE_NAME` with clear status message if unconfigured.
* **Timeout + tr_id**: Bumped timeout from 10s → 15s; tr_id length from 8 → 12 chars.

---

## **[v3.1] - 2026-03-06**

### **Added: Active Blocking Mode**

* **Hard Blocking**: Implemented `raise Exception()` in the `inlet` phase to terminate malicious requests before they reach the local Ollama model.
* **Granular Category Mapping**: Added support for specific toxic categories (e.g., *Cybercrimes*, *Indiscriminate Weapons*) and *Hallucination* (ungrounded) flags.
* **Response Redaction**: Programmed the `outlet` to overwrite leaking responses with a standard security block message.

---

## **[v2.7] - 2026-03-07**

### **Refactored: Detection Mode — Dual-Pass Outlet Logic**

* **Inlet Pass-Through**: `inlet` no longer makes an API call. Scanning is deferred to `outlet` where both prompt and response are available, eliminating the LLM cascade signal problem (where the AI reads its own pre-response security banner and adjusts its output).
* **Single Dual-Pass Scan**: `outlet` sends prompt and response together in one API call — matching the approach used by the diagnostic scan.
* **Compact Alert Format**: When risks are detected, appends a concise banner showing `**Prompt:**` and `**Response:**` findings inline, with DLP pattern details on a separate line if applicable. Nothing is appended when the scan is clean.
* **Timeout and API Error Handling**: Scan timeouts and API-level errors are now surfaced as visible inline messages rather than failing silently.
* **API Category Label**: The API's top-level `category` field (`malicious` / `benign`) is shown in the alert header.

---

## **[v2.6] - 2026-03-07**

### **Improved: Detection Mode — Sample-Driven Corrections**

* **Asymmetric Field Maps**: Replaced the single combined field map with separate `PROMPT_FIELD_MAP` (`injection`, `agent`, `dlp`, `toxic_content`, `malicious_code`, `url_cats`) and `RESPONSE_FIELD_MAP` (`dlp`, `toxic_content`, `malicious_code`, `url_cats`, `db_security`, `ungrounded`) matching the actual API schema.
* **Toxic Category Inline Formatting**: Toxic categories now render inline (e.g. *Toxic Content (Cybercrimes)*) instead of appearing as a floating comma-separated item.
* **Response Detection Details**: `response_detection_details` is now passed when building the outlet alert, so toxic categories are correctly shown for response-side detections.
* **DLP Pattern Detail in Outlet**: When `dlp: true` fires on the response, the alert now appends the specific PII pattern names and hit counts extracted from `response_masked_data`.
* **Credential Validation**: Early check on `PRISMA_API_KEY` and `AI_PROFILE_NAME` — emits a clear status error if either is unconfigured instead of failing silently.
* **Default Valve Values**: Changed `"xxxxx"` placeholder defaults to `""` with proper field descriptions.
* **Removed Unused Import**: Removed `Optional` from the `typing` import.
* **Timeout + tr_id**: Bumped timeout from 10s → 15s; tr_id length from 8 → 12 chars (consistent with diagnosis scan).

---

## **[v2.1] - 2026-03-05**

### **Added: Enhanced Detection Mode**

* **Status Emitters**: Added real-time visual loaders (e.g., `🔍 Prisma AIRS: Scanning...`) to improve user experience during API latency.
* **Multi-Risk Support**: Expanded detection to include Malicious URLs, Prompt Injections, and DLP.

---

## **[v1.0] - 2026-03-04**

### **Initial Release: Basic Monitor Mode**

* **Sync API Integration**: Initial connection to `https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request`.
* **Basic Valves**: Setup for `x-pan-token` and `AI_PROFILE_NAME` configuration.
* **Warning Banners**: Simple text prepending/appending for detected risks.
