import io
import unittest

from openpyxl import Workbook

from processor import process_file, STATUSES


class ProcessorTests(unittest.TestCase):
    def test_csv_vulnerability_record(self):
        data = b"target,ip_address,port,protocol,service,vulnerability,severity,cvss_score,affected_url,remediation,status,due_date\napi.acme.com,198.51.100.4,443,tcp,https,Exposed admin panel,high,8.1,https://api.acme.com/admin,Restrict access,open,2025-07-01"
        records = process_file(data)

        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(set(record.keys()), {"title", "status", "details", "due_date"})
        self.assertEqual(record["title"], "Exposed admin panel")
        self.assertEqual(record["status"], "open:critical")
        self.assertEqual(record["due_date"], "2025-07-01")
        self.assertEqual(record["details"]["target"], "api.acme.com")
        self.assertEqual(record["details"]["severity"], "high")
        self.assertIn(record["status"], STATUSES)

    def test_false_positive_status(self):
        data = b"vulnerability,severity,status\nOutdated library,medium,false-positive"
        records = process_file(data)
        self.assertEqual(records[0]["status"], "false-positive:good")

    def test_excel_extraction(self):
        workbook = Workbook()
        worksheet = workbook.active
        worksheet.append(["vulnerability", "target", "severity", "status"])
        worksheet.append(["SQLi", "example.com", "critical", "reopened"])
        bio = io.BytesIO()
        workbook.save(bio)

        records = process_file(bio.getvalue())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "reopened:high")
        self.assertEqual(records[0]["details"]["target"], "example.com")

    def test_invalid_bytes_returns_empty_list(self):
        self.assertEqual(process_file(b"\x00\x01"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
