# VulnScan Processor

VulnScan is an automated security-report ingestion backend. It accepts uploaded
vulnerability reports from scanners and converts them into normalized finding
records that the VulnScan dashboard can ingest and track.

## Archetype

Document extraction pipeline. A single uploaded file (PDF, Excel, CSV, or plain
text) is parsed, its header row is mapped against a canonical VulnScan schema,
and each data row is emitted as one normalized record.

## Primary Entity

The entity this processor tracks is the **vulnerability finding**, not the
document or report container. The `title` field therefore resolves to the
vulnerability / finding title (falling back to CVE ID, target, or the first
populated cell when a report has no explicit title column).

## API

```python
from processor import process_file

records = process_file(file_bytes)  # file_bytes: bytes -> list[dict]
```

Every returned record has exactly this shape:

```python
{
    "title": str,          # vulnerability / finding title
    "status": str,         # one of the allowed status strings
    "details": dict,       # remaining dashboard fields, normalized keys
    "due_date": str | None # ISO-8601 date or None
}
```

## Status Normalization

`status` is always one of:

- `open:critical`
- `in-progress:high`
- `resolved:good`
- `false-positive:good`
- `accepted-risk:warning`
- `reopened:high`

Free-text scanner values are normalized into these buckets (for example
`false positive` becomes `false-positive:good`, and unknown values default to
`open:critical`).

## What The Poller Expects As Input

The Railway poller hands `process_file` the raw bytes of one uploaded report at
a time. It does not pass a filename, path, or content type. Input is therefore
sniffed in this order:

1. PDF via `pdfplumber` (tables first, then raw text lines)
2. Excel via `openpyxl` (first worksheet rows, all worksheets)
3. UTF-8 text / CSV fallback via `csv.Sniffer` with `, ; \t |` delimiters

The first non-empty row is treated as the header row. Known VulnScan dashboard
columns are mapped to canonical fields; unrecognized columns are preserved in
`details` under a sanitized key. Invalid or empty byte streams return `[]`.

## Files

- `processor.py` — core extraction module, defines `process_file`
- `run_demo.py` — zero-argument demo with hardcoded CSV bytes
- `run_tests.py` — zero-argument unit test runner
- `requirements.txt` — `openai`, `requests`, `pdfplumber`, `openpyxl`

## Run

```bash
pip install -r requirements.txt
python3 run_tests.py
python3 run_demo.py
```
