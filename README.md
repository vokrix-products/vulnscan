# VulnScan

VulnScan is an automated security-report ingestion backend. It accepts uploaded vulnerability reports from scanners and converts them into normalized finding records that the VulnScan dashboard ingests and tracks.

## Archetype

Document extraction pipeline. A single uploaded file (PDF, Excel, CSV, or plain text) is parsed, its header row is mapped against a canonical VulnScan schema, and each data row is emitted as one normalized record.

## Primary Entity

The entity tracked is the vulnerability finding, not the document or report container. The title field resolves to the vulnerability / finding title, falling back to CVE ID, target, or the first populated cell when a report has no explicit title column.

## API

    from processor import process_file
    records = process_file(file_bytes)

Every returned record has exactly this shape:

    {
        "title": str,
        "status": str,
        "details": dict,
        "due_date": str | None
    }

## Status Normalization

status is always one of:

- open:critical
- in-progress:high
- resolved:good
- false-positive:good
- accepted-risk:warning
- reopened:high

Unknown scanner values default to open:critical.

## Input Handling

The poller hands process_file the raw bytes of one uploaded report at a time. Input is sniffed in this order:

1. PDF via pdfplumber (tables first, then raw text lines)
2. Excel via openpyxl (all worksheets)
3. UTF-8 text / CSV fallback via csv.Sniffer with , ; tab | delimiters

The first non-empty row is the header row. Invalid or empty byte streams return [].

## Files

- processor.py — core extraction module, defines process_file
- poller.py — Railway polling worker
- run_demo.py — zero-argument demo with hardcoded CSV bytes
- run_tests.py — zero-argument unit test runner
- requirements.txt — openai, requests, pdfplumber, openpyxl

## Run

    pip install -r requirements.txt
    python3 run_tests.py
    python3 run_demo.py

## Deploy

- Poller: Railway, built from repo root Dockerfile, runs poller.py.
- Dashboard: Vercel, built from dashboard/.
Dashboard: https://vulnscan.vokrix.co
Vercel: vulnscan
Railway: vulnscan
Cloudflare: vulnscan.vokrix.co

Billing: price_1UHv022c9uGCcgMS4SryIvna

Landing: https://vokrix.co/vulnscan
