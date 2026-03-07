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

## **[v3.1] - 2026-03-06**

### **Added: Active Blocking Mode**

* **Hard Blocking**: Implemented `raise Exception()` in the `inlet` phase to terminate malicious requests before they reach the local Ollama model.
* **Granular Category Mapping**: Added support for specific toxic categories (e.g., *Cybercrimes*, *Indiscriminate Weapons*) and *Hallucination* (ungrounded) flags.
* **Response Redaction**: Programmed the `outlet` to overwrite leaking responses with a standard security block message.

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
