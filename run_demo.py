from processor import process_file, STATUSES

SAMPLE_CSV = b"""target,ip_address,port,protocol,service,vulnerability,severity,cvss_score,affected_url,remediation,status,due_date,scan_source,compliance_mappings,tags,assignee,notes,client_project_group
vulnscan-demo.example.com,203.0.113.10,443,tcp,https,CVE-2024-1234 SQL Injection,critical,9.8,https://vulnscan-demo.example.com/login,Apply vendor patch,open,2025-06-01,Nuclei,PCI DSS,card data,alice@example.com,Limited scan finding,Acme Inc
"""


def main():
    results = process_file(SAMPLE_CSV)

    assert isinstance(results, list)
    assert len(results) == 1

    required_keys = {"title", "status", "details", "due_date"}
    for record in results:
        assert required_keys.issubset(record.keys())
        assert record["status"] in STATUSES

    print(f"Demo processed {len(results)} record(s)")
    for record in results:
        print(f"- {record['title']} | {record['status']} | due={record['due_date']}")
    print("run_demo passed")


if __name__ == "__main__":
    main()
