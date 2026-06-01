# IOC Enrichment Tool

## Overview

The IOC Enrichment Tool is a Python-based cybersecurity utility designed to automate the enrichment of Indicators of Compromise (IOCs) using multiple threat intelligence sources.

The tool accepts IP addresses, domains, URLs, and file hashes, automatically identifies the IOC type, queries external threat intelligence platforms, and generates a consolidated report containing reputation and threat information.

The goal of the project is to reduce the time required for manual IOC investigation during threat hunting, incident response, and SOC operations.

---

# Problem Statement

Security analysts frequently need to investigate large numbers of IOCs during:

* Incident Response
* Threat Hunting
* Malware Analysis
* SOC Monitoring
* Alert Triage

Performing these lookups manually across multiple platforms is time-consuming and inefficient.

This tool automates the enrichment process and centralizes results into a single report.

---

# Features

### IOC Type Detection

Automatically identifies:

* IPv4 Addresses
* Domains
* URLs
* MD5 Hashes
* SHA1 Hashes
* SHA256 Hashes

---

### VirusTotal Integration

Retrieves:

* Detection statistics
* Malicious engine count
* Suspicious engine count
* Overall reputation verdict

---

### AbuseIPDB Integration

For IP addresses, retrieves:

* Abuse Confidence Score
* Total Reports
* Country Code
* Reputation Verdict

---

### Flexible IOC Input

Supports:

1. Manual IOC entry
2. TXT file import

Example:

```txt
8.8.8.8
malicious-example.com
https://example.com
44d88612fea8a8f36de82e1278abb02f
```

---

### CSV Reporting

Generates a structured CSV report:

```csv
ioc,type,vt_verdict,vt_malicious,vt_total,ab_verdict
8.8.8.8,ip,CLEAN,0,94,CLEAN
```

<img width="1241" height="236" alt="Screenshot 2026-06-01 072746" src="https://github.com/user-attachments/assets/0b74a06d-a58c-40d9-b816-ebca7a38aa8d" />

---

# Technologies Used

| Technology     | Purpose                |
| -------------- | ---------------------- |
| Python         | Core development       |
| Requests       | API communication      |
| CSV Module     | Report generation      |
| VirusTotal API | Threat intelligence    |
| AbuseIPDB API  | IP reputation analysis |

---

# Workflow

```text
User Input
      │
      ▼
Detect IOC Type
      │
      ▼
VirusTotal Lookup
      │
      ▼
AbuseIPDB Lookup (IPs Only)
      │
      ▼
Merge Results
      │
      ▼
Generate CSV Report
```

<img width="652" height="515" alt="Screenshot 2026-06-01 073423" src="https://github.com/user-attachments/assets/df546a3d-6f30-42fc-8f08-724b39fccdfa" />

---

# Example Use Cases

### SOC Analyst

Investigate suspicious IPs detected by SIEM alerts.

### Threat Hunter

Enrich indicators collected during threat hunting activities.

### Incident Responder

Validate malicious infrastructure related to a security incident.

