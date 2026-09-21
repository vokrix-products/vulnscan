import os
import time
import json
import traceback
import requests
from datetime import datetime, timezone

SUPABASE_URL = os.environ['SUPABASE_URL']
SUPABASE_SERVICE_KEY = os.environ['SUPABASE_SERVICE_KEY']
PRODUCT_ID = os.environ['PRODUCT_ID']
ANTHROPIC_API_KEY = os.environ['ANTHROPIC_API_KEY']

REST_URL = f"{SUPABASE_URL}/rest/v1"
SB_HEADERS = {
    "apikey": SUPABASE_SERVICE_KEY,
    "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}"
}

import processor

def download_file(bucket, file_path):
    if file_path.startswith(bucket + "/"):
        file_path = file_path[len(bucket) + 1:]
    url = f"{SUPABASE_URL}/storage/v1/object/{bucket}/{file_path}"
    resp = requests.get(url, headers={
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "apikey": SUPABASE_SERVICE_KEY
    })
    resp.raise_for_status()
    return resp.content

def upload_file(bucket, file_path, content, content_type="application/json"):
    url = f"{SUPABASE_URL}/storage/v1/object/{bucket}/{file_path}"
    resp = requests.post(url, headers={
        **SB_HEADERS,
        "Content-Type": content_type,
        "x-upsert": "true"
    }, data=content)
    resp.raise_for_status()
    return resp

def notify(customer_id, title, body, type_):
    try:
        requests.post(
            f"{REST_URL}/notifications",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=minimal"},
            json={
                "product_id": PRODUCT_ID,
                "customer_id": customer_id,
                "title": title,
                "body": body,
                "type": type_,
                "read": False
            }
        )
    except Exception:
        pass

def process_job(job):
    customer_id = job["customer_id"]
    input_file_path = job["input_file_path"]
    try:
        file_bytes = download_file("uploads", input_file_path)
        records = processor.process_file(file_bytes)
        for r in records:
            requests.post(
                f"{REST_URL}/records",
                headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=minimal"},
                json={
                    "product_id": PRODUCT_ID,
                    "customer_id": customer_id,
                    "title": r["title"],
                    "status": r["status"],
                    "details": r["details"],
                    "source_file_path": input_file_path,
                    "due_date": r.get("due_date")
                }
            )
        result_summary = f"Processed {len(records)} records from {input_file_path}"
        result_bytes = json.dumps(records, indent=2).encode("utf-8")
        result_file_path = "results/" + input_file_path.rsplit("/", 1)[-1].rsplit(".", 1)[0] + ".json"
        upload_file("results", result_file_path, result_bytes)
        requests.patch(
            f"{REST_URL}/jobs?id=eq.{job['id']}",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=minimal"},
            json={
                "status": "completed",
                "output_file_path": result_file_path,
                "result_summary": result_summary,
                "completed_at": datetime.now(timezone.utc).isoformat()
            }
        )
        notify(customer_id, "Processing complete", "Your upload has been processed successfully.", "success")
    except Exception as e:
        traceback.print_exc()
        requests.patch(
            f"{REST_URL}/jobs?id=eq.{job['id']}",
            headers={**SB_HEADERS, "Content-Type": "application/json", "Prefer": "return=minimal"},
            json={
                "status": "failed",
                "result_summary": str(e),
                "completed_at": datetime.now(timezone.utc).isoformat()
            }
        )
        notify(customer_id, "Processing failed", "There was an error processing your upload.", "error")

def poll():
    while True:
        try:
            resp = requests.get(
                f"{REST_URL}/jobs",
                headers=SB_HEADERS,
                params={
                    "status": "eq.pending",
                    "job_type": "eq.process_upload",
                    "product_id": f"eq.{PRODUCT_ID}",
                    "select": "*"
                }
            )
            resp.raise_for_status()
            jobs = resp.json()
            for job in jobs:
                process_job(job)
        except Exception:
            traceback.print_exc()
        time.sleep(60)

if __name__ == "__main__":
    print("Poller started")
    poll()
