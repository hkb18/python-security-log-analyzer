# Python Security Log Analyzer

A SOC-focused detection engineering project that parses Windows EVTX telemetry and identifies suspicious PowerShell execution and authentication abuse.

## Project Summary

This project was developed to demonstrate a practical detection workflow using real Windows event telemetry collected from a controlled virtual lab environment. The tool ingests exported EVTX files, parses raw XML records, normalizes event fields, and applies rule-based detection logic to identify potentially malicious PowerShell activity.

The current implementation includes:

- Windows Sysmon EVTX ingestion
- Windows Security EVTX ingestion
- XML namespace-aware event parsing
- EventData field extraction and normalization
- Suspicious PowerShell detection (Sysmon Event ID 1)
- Brute-force authentication detection (Security Event ID 4625)
- Threshold-based multi-event correlation
- False-positive reduction through rule tuning

## Detection Objective

The primary objective of the current detection logic is to identify suspicious PowerShell execution patterns commonly associated with adversary tradecraft, including:

- encoded PowerShell execution (`-enc`)
- in-memory execution via `IEX`
- remote content retrieval using `DownloadString`

## Detection Coverage

### PowerShell Abuse (MITRE T1059.001)
- Encoded commands (`-enc`)
- In-memory execution (`IEX`)
- Remote payload retrieval (`DownloadString`)

### Brute-Force Authentication (MITRE T1110)
- Event ID 4625 (failed logons)
- Grouping by TargetUserName and source IP
- Threshold-based detection (≥5 failures)
- Detection of both:
  - Local interactive logons (Type 2)
  - Network logons (Type 3)

## Lab Context

Telemetry used in this project was generated in a controlled lab consisting of:

- **Windows 11**: development environment and Git repository location
- **Windows 10 FLARE VM**: telemetry source and attack simulation target
- **Kali Linux VM**: attacker simulation platform for future detection scenarios

## Detection Status

### Implemented
- Sysmon process creation parsing
- Sysmon network connection parsing
- Suspicious PowerShell detection with tuning
- Security log parsing (Event ID 4625)
- Brute-force authentication detection
- Multi-event grouping and threshold-based detection

### Planned Improvements
- Time-based correlation of events
- Correlation of failed (4625) and successful (4624) logons
- Additional detection rules (persistence, lateral movement)
- Detection scoring and prioritization

## Repository Structure

```text
python-security-log-analyzer/
├── .gitignore
├── README.md
├── pyproject.toml
├── output/
├── rules/
├── sample_logs/
├── src/
│   └── loganalyzer/
│       ├── __init__.py
│       ├── cli.py
│       ├── parser.py
│       └── detectors.py
├── tests/
└── docs/
    ├── 01_project_overview.md
    ├── 02_lab_environment.md
    ├── 03_data_acquisition.md
    ├── 04_parser_pipeline.md
    ├── 05_detection_engine.md
    ├── 06_results_and_findings.md
    └── screenshots/
```

## Core Workflow
- Export EVTX logs from the Windows 10 FLARE VM
- Transfer logs to the Windows 11 development environment
- Parse raw EVTX XML records with Python
- Normalize telemetry fields into structured dictionaries
- Apply rule-based detection logic
- Review detection output and tune logic to reduce false positives

## Example Detection Output

### Suspicious PowerShell Detection

```json
{
  "EventID": "1",
  "TimeCreated": "...",
  "Computer": "...",
  "Image": "powershell.exe",
  "CommandLine": "... -enc ...",
  "User": "...",
  "MatchedKeywords": ["powershell", "-enc"]
}
```
### Brute-Force Detection

```json
{
  "DetectionType": "Brute Force Authentication Attempt",
  "TargetUserName": "testuser",
  "IpAddress": "192.168.56.103",
  "FailureCount": 20,
  "LogonType": "3"
}
```


## Key Findings So Far

The initial PowerShell detection logic produced a high false-positive rate due to Splunk service activity. Detection logic was subsequently refined to exclude service-generated events and require higher-signal indicators such as:

- `-enc`
- `iex`
- `downloadstring`

After tuning, the detector successfully identified true-positive suspicious PowerShell events generated in the FLARE VM.

## Screenshot Index
- docs/screenshots/01_pycharm_interpreter_setup.png
- docs/screenshots/02_editable_install_success.png
- docs/screenshots/03_cli_help_output.png
- docs/screenshots/04_project_structure_initialized.png
- docs/screenshots/05_flarevm_evtx_export_success.png
- docs/screenshots/06_sample_logs_imported_windows11.png
- docs/screenshots/07_evtx_ingestion_success.png
- docs/screenshots/08_namespace_parsing_fixed.png
- docs/screenshots/09_eventdata_extraction_success.png
- docs/screenshots/10_initial_powershell_detection_noisy.png
- docs/screenshots/11_tuned_powershell_detection_reduced_noise.png
- docs/screenshots/12_flarevm_suspicious_powershell_execution.png
- docs/screenshots/13_true_positive_powershell_detection.png
- docs/screenshots/14_bruteforce_audit_policy_enabled.png
- docs/screenshots/15_bruteforce_test_user_creation.png
- docs/screenshots/16_bruteforce_eventviewer_4625.png
- docs/screenshots/17_bruteforce_cli_detection_output.png

## Status

The detection pipeline is fully operational and demonstrates:

- EVTX ingestion and parsing
- Structured event normalization
- PowerShell abuse detection (Sysmon)
- Brute-force authentication detection (Security logs)
- Multi-event correlation using threshold-based logic
- Evidence-backed analysis and documentation

The project reflects a practical SOC detection engineering workflow using real telemetry and controlled attack simulation.

## SOC Relevance

This project demonstrates core detection engineering capabilities used in real Security Operations Centers (SOC):

- Parsing and normalizing raw telemetry
- Identifying suspicious behavior from process execution logs
- Detecting authentication abuse through repeated failed logons
- Reducing false positives through rule tuning
- Correlating multiple events into actionable detections

These workflows align with responsibilities of:

- SOC Analysts (Tier 1 / Tier 2)
- Detection Engineers
- Incident Responders

## MITRE ATT&CK Mapping

- T1059.001 – PowerShell
  - Detection via Sysmon Event ID 1
  - Encoded commands, IEX, remote downloads

- T1110 – Brute Force
  - Detection via Windows Security Event ID 4625
  - Identification of repeated failed authentication attempts
  - Threshold-based grouping by user and source IP
