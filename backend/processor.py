import csv
import io
import re
from datetime import datetime, date
from typing import Any, Dict, List

import openpyxl
import pdfplumber

STATUSES = [
    "open:critical",
    "in-progress:high",
    "resolved:good",
    "false-positive:good",
    "accepted-risk:warning",
    "reopened:high"
]

# Primary entity for VulnScan is the finding/vulnerability title,
# NOT the document type or report category.
FIELD_ALIASES = {
    "title": [
        "vulnerability/title", "vulnerability title", "finding title", "title",
        "vulnerability", "issue", "name", "cve title", "nuclei template id", "template id"
    ],
    "target": [
        "target/domain", "target", "domain", "host", "asset", "target domain",
        "hostname", "affected asset", "url"
    ],
    "ip_address": [
        "ip address", "ip", "ip_address", "ipaddr", "host ip", "ip address",
        "target ip", "source ip", "destination ip"
    ],
    "port": ["port", "port number"],
    "protocol": ["protocol", "proto"],
    "service": ["service"],
    "cve": [
        "cve or nuclei template id", "cve", "nuclei template id", "template id",
        "cve id", "nuclei template", "cve / nuclei template id"
    ],
    "severity": ["severity", "risk", "severity rating", "cvss severity", "severity level"],
    "cvss_score": ["cvss score", "cvss", "score", "cvss_score", "cvss v3 score"],
    "affected_url": [
        "affected url/resource", "affected url", "affected_resource",
        "affected resource", "resource", "affected endpoint", "vulnerable url"
    ],
    "evidence": [
        "evidence/description", "evidence", "description", "details",
        "finding description", "evidence description", "vulnerability description"
    ],
    "remediation": [
        "remediation/fix guidance", "remediation", "fix guidance", "fix",
        "solution", "recommendation", "remediation guidance", "mitigation"
    ],
    "status": ["status", "state", "finding status", "vulnerability status", "asset status"],
    "first_detected": [
        "first detected", "first_detected", "first seen", "first_seen",
        "detected date", "discovered", "first observed"
    ],
    "last_seen": [
        "last seen", "last_seen", "last_observed", "last seen date",
        "last observed", "last detected"
    ],
    "compliance_mappings": [
        "compliance mappings (pci/soc2/iso)", "compliance mappings", "compliance",
        "pci/soc2/iso", "pci", "soc2", "iso 27001", "compliance mapping",
        "compliance mappings (PCI/SOC2/ISO)"
    ],
    "scan_source": [
        "scan source (nuclei, nmap, uploaded report)", "scan source", "source",
        "scanner", "tool", "scan_source", "scan type",
        "scan source (nuclei, nmap, uploaded report)"
    ],
    "tags": [
        "tags/context", "tags", "context", "tag",
        "context (e.g., card data, pii, wordpress, shopify, stripe)",
        "tags/context (e.g., card data, pii, wordpress, shopify, stripe)",
        "context (e.g., card data, PII, WordPress, Shopify, Stripe)",
        "tags/context (e.g., card data, PII, WordPress, Shopify, Stripe)"
    ],
    "assignee": [
        "assignee/owner", "assignee", "owner", "assigned to",
        "assignee owner", "responsible", "owner/assignee"
    ],
    "due_date": ["due date", "due_date", "due", "deadline", "remediation due date"],
    "notes": ["notes", "note", "comments", "comment"],
    "client_project_group": [
        "client/project group", "client project group", "client", "project",
        "client_project_group", "group", "client/project", "client group",
        "project group"
    ]
}

ALIAS_TO_CANONICAL = {}
for canonical_field, aliases in FIELD_ALIASES.items():
    for alias in aliases:
        ALIAS_TO_CANONICAL[alias.lower()] = canonical_field


def _clean_cell(value):
    if value is None:
        return ""
    return str(value).strip()


def _normalize_header(value):
    value = str(value or "").strip().lower()
    value = re.sub(r"\s+", " ", value)
    value = value.strip(":")
    value = value.replace("_", " ")
    return value


def _map_header(value):
    return ALIAS_TO_CANONICAL.get(_normalize_header(value))


def _sanitize_custom_key(value, index):
    key = _normalize_header(value)
    key = re.sub(r"[^a-z0-9]+", "_", key)
    key = key.strip("_")
    if not key:
        return f"column_{index + 1}"
    if key[0].isdigit():
        key = f"col_{key}"
    return key


def _parse_date(value):
    value = str(value).strip()
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.date().isoformat()
    except Exception:
        pass
    for fmt in (
        "%Y-%m-%d",
        "%d/%m/%Y",
        "%m/%d/%Y",
        "%d-%m-%Y",
        "%m-%d-%Y",
        "%B %d, %Y",
        "%b %d, %Y",
        "%B %d %Y",
        "%b %d %Y",
        "%Y/%m/%d",
        "%d.%m.%Y",
    ):
        try:
            return datetime.strptime(value, fmt).date().isoformat()
        except Exception:
            continue
    return None


def normalize_status(raw_status, severity=""):
    status_str = str(raw_status or "").strip().lower()
    severity_str = str(severity or "").strip().lower()

    if status_str in STATUSES:
        return status_str
    if "false-positive" in status_str or "false positive" in status_str or "false" in status_str:
        return "false-positive:good"
    if "accepted" in status_str or "accept" in status_str or "accepted-risk" in status_str:
        return "accepted-risk:warning"
    if "resolved" in status_str or "closed" in status_str or "fixed" in status_str:
        return "resolved:good"
    if "reopen" in status_str:
        return "reopened:high"
    if "in-progress" in status_str or "progress" in status_str or "review" in status_str or "triaged" in status_str:
        return "in-progress:high"

    return "open:critical"


def _extract_rows(file_bytes: bytes):
    # 1) PDF via pdfplumber
    try:
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            rows = []
            for page in pdf.pages:
                table = page.extract_table()
                if table:
                    rows.extend(table)
                else:
                    text = page.extract_text() or ""
                    for line in text.splitlines():
                        line = line.strip()
                        if line:
                            rows.append([line])
            if rows:
                return rows
    except Exception:
        pass

    # 2) Excel via openpyxl
    try:
        workbook = openpyxl.load_workbook(io.BytesIO(file_bytes), data_only=True)
        rows = []
        for worksheet in workbook.worksheets:
            for row in worksheet.iter_rows(values_only=True):
                rows.append(list(row))
        if rows:
            return rows
    except Exception:
        pass

    # 3) UTF-8 text / CSV fallback
    text = file_bytes.decode("utf-8", errors="ignore")
    if not text.strip():
        return []

    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        reader = csv.reader(io.StringIO(text), dialect)
        rows = [row for row in reader]
        if rows:
            return rows
    except Exception:
        pass

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return []

    for delimiter in (",", "\t", ";", "|"):
        if delimiter in lines[0]:
            return [line.split(delimiter) for line in lines]

    return [[line] for line in lines]


def _build_record(row, header_map):
    title = None
    details: Dict[str, Any] = {}
    raw_status = None
    severity = None
    due_date_raw = None

    for index, canonical_field, custom_key in header_map:
        value = _clean_cell(row[index]) if index < len(row) else ""
        if canonical_field is None:
            if custom_key and value:
                details[custom_key] = value
            continue
        if canonical_field == "title":
            title = value
        elif canonical_field == "status":
            raw_status = value
        elif canonical_field == "severity":
            severity = value
            details["severity"] = value
        elif canonical_field == "due_date":
            due_date_raw = value
        else:
            if value:
                details[canonical_field] = value

    if not title:
        if details.get("cve"):
            title = details["cve"]
            if details.get("target"):
                title = f"{details['cve']} - {details['target']}"
        elif details.get("target"):
            title = details["target"]
        else:
            for cell in row:
                if str(cell).strip():
                    title = str(cell).strip()
                    break
            if not title:
                title = "Untitled"

    due_date = _parse_date(due_date_raw) if due_date_raw else None
    status = normalize_status(raw_status, severity)

    return {
        "title": title,
        "status": status,
        "details": details,
        "due_date": due_date,
    }


def process_file(file_bytes: bytes) -> List[Dict[str, Any]]:
    raw_rows = _extract_rows(file_bytes)

    cleaned_rows = []
    for row in raw_rows:
        row = [_clean_cell(cell) for cell in row]
        if any(str(cell).isprintable() and str(cell).strip() for cell in row):
            cleaned_rows.append(row)

    if not cleaned_rows:
        return []

    if len(cleaned_rows) >= 2:
        header_row = cleaned_rows[0]
        data_rows = cleaned_rows[1:]
    else:
        header_row = []
        data_rows = cleaned_rows

    if not header_row:
        records = []
        for row in data_rows:
            nonempty = [cell for cell in row if str(cell).strip()]
            title = nonempty[0] if nonempty else "Untitled"
            records.append({
                "title": title,
                "status": normalize_status(None, ""),
                "details": {"raw": row},
                "due_date": None,
            })
        return records

    header_map = []
    for idx, header in enumerate(header_row):
        canonical_field = _map_header(header)
        if canonical_field:
            header_map.append((idx, canonical_field, None))
        else:
            custom_key = _sanitize_custom_key(header, idx)
            header_map.append((idx, None, custom_key))

    records = []
    for row in data_rows:
        if not any(str(cell).isprintable() and str(cell).strip() for cell in row):
            continue
        records.append(_build_record(row, header_map))

    return records
