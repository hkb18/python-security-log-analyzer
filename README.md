# Python Security Log Analyzer

A blue-team detection engineering project that parses Windows EVTX telemetry and identifies suspicious PowerShell execution from Sysmon process creation events.

## Project Summary

This project was developed to demonstrate a practical detection workflow using real Windows event telemetry collected from a controlled virtual lab environment. The tool ingests exported EVTX files, parses raw XML records, normalizes event fields, and applies rule-based detection logic to identify potentially malicious PowerShell activity.

The current implementation focuses on:

- Windows Sysmon EVTX ingestion
- Security EVTX ingestion
- XML namespace-aware event parsing
- EventData field extraction
- Suspicious PowerShell detection
- False-positive reduction through rule tuning

## Detection Objective

The primary objective of the current detection logic is to identify suspicious PowerShell execution patterns commonly associated with adversary tradecraft, including:

- encoded PowerShell execution (`-enc`)
- in-memory execution via `IEX`
- remote content retrieval using `DownloadString`

## Lab Context

Telemetry used in this project was generated in a controlled lab consisting of:

- **Windows 11**: development environment and Git repository location
- **Windows 10 FLARE VM**: telemetry source and attack simulation target
- **Kali Linux VM**: attacker simulation platform for future detection scenarios

## Current Detection Coverage

### Implemented
- Sysmon process creation parsing
- Sysmon network connection parsing
- Suspicious PowerShell detection with rule tuning

### In Progress
- Security log authentication parsing
- Brute-force detection from failed authentication events
- Additional rule-based detections

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
Core Workflow
Export EVTX logs from the Windows 10 FLARE VM
Transfer logs to the Windows 11 development environment
Parse raw EVTX XML records with Python
Normalize telemetry fields into structured dictionaries
Apply rule-based detection logic
Review detection output and tune logic to reduce false positives
Key Findings So Far

The initial PowerShell detection logic produced a high false-positive rate due to Splunk service activity. Detection logic was subsequently refined to exclude service-generated events and require higher-signal indicators such as:

-enc
iex
downloadstring

After tuning, the detector successfully identified true-positive suspicious PowerShell events generated in the FLARE VM.

Screenshot Index
docs/screenshots/01_pycharm_interpreter_setup.png
docs/screenshots/02_editable_install_success.png
docs/screenshots/03_cli_help_output.png
docs/screenshots/04_project_structure_initialized.png
docs/screenshots/05_flarevm_evtx_export_success.png
docs/screenshots/06_sample_logs_imported_windows11.png
docs/screenshots/07_evtx_ingestion_success.png
docs/screenshots/08_namespace_parsing_fixed.png
docs/screenshots/09_eventdata_extraction_success.png
docs/screenshots/10_initial_powershell_detection_noisy.png
docs/screenshots/11_tuned_powershell_detection_reduced_noise.png
docs/screenshots/12_flarevm_suspicious_powershell_execution.png
docs/screenshots/13_true_positive_powershell_detection.png
Status

Current repository status reflects an active build phase. The EVTX parsing pipeline and PowerShell detection workflow are operational. Authentication-focused detections and additional rule modules are planned for the next iteration.
