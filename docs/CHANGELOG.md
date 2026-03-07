## **[v4.3] - 2026-03-07**

### **Added: Full Diagnostic & Raw JSON Mode**

* **Raw JSON Inspection**: Integrated a Markdown code block at the end of every response to show the complete, original Prisma AIRS API JSON for debugging.
* **Diagnostic Split**: The report now explicitly separates findings into **[1] Prompt Detected** and **[2] Response Detected** to mirror the API schema.
* **Scan ID Correlation**: Added the unique `scan_id` to the UI footer to allow auditors to cross-reference local hits with the Prisma Cloud (Strata) console.

---

## **[v4.1] - 2026-03-07**

### **Added: Research Mode (Non-Redacting)**

* **Content Preservation**: Modified logic to **append** security reports rather than **overwriting** them, allowing testers to see the LLM's raw output.
* **Dual-Pass Scan**: Consolidated prompt and response scanning into a single `outlet` call to prevent LLM "cascade signals" (where the AI reads its own security banner).

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
