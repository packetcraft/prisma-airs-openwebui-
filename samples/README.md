# 📦 Prisma AIRS Sample API Responses

This folder stores real JSON responses captured from the Prisma AIRS API. They are used as reference material when developing and improving the interceptor functions.

## How to add a sample

1. Trigger the detection scenario in Open WebUI with the diagnostic filter (`prisma_airs_diagnosis_scan.py`) active.
2. Copy the **Raw API Response (JSON)** block from the chat output.
3. Save it as a `.json` file in this folder using the naming convention below.

## Naming convention

```
<detection_type>_<scan_target>_<result>.json
```

Examples:
- `prompt_injection_inlet_block.json`
- `dlp_outlet_block.json`
- `url_cats_inlet_block.json`
- `toxic_content_inlet_block.json`
- `clean_inlet_allow.json`

## File index

| File | Detection Type | Scan Target | Result |
| --- | --- | --- | --- |
| `clean_allow.json` | None | prompt + response | allow |
| `prompt_injection_block.json` | Prompt Injection | prompt (inlet) | block |
| `dlp_block.json` | Data Leakage (DLP) | response (outlet) | block |
| `url_cats_block.json` | Malicious URL | prompt (inlet) | block |
| `toxic_content_block.json` | Toxic Content | prompt (inlet) | block |

> Update this table as you add new samples.
