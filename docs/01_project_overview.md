\# Project Overview



\## Objective



The objective of this project is to develop a Python-based security analysis tool capable of ingesting and parsing exported Windows EVTX logs and applying rule-based detection logic to identify suspicious activity.



This work is framed as a detection engineering exercise rather than a generic log-processing script. The implementation focuses on practical telemetry handling, field extraction, signal validation, and false-positive reduction.



\## Problem Statement



Windows event telemetry is often stored in EVTX format and contains high-value forensic and detection-relevant data. However, working directly with EVTX files requires:



\- specialized parsing

\- XML handling

\- namespace-aware extraction

\- structured normalization

\- detection logic tuned to reduce operational noise



The project addresses this problem by building a lightweight, inspectable Python pipeline that transforms raw EVTX data into actionable security findings.



\## Scope



The current scope includes:



\- parsing exported Sysmon EVTX logs

\- parsing exported Windows Security EVTX logs

\- extracting system and EventData fields from XML

\- applying rule-based PowerShell detection logic

\- validating detections against controlled test activity



The current scope does not yet include:



\- SIEM integration

\- live log forwarding

\- alert enrichment

\- timeline correlation across multiple hosts

\- authentication attack detection from 4625 events



\## Why This Project Matters



This project demonstrates several capabilities directly relevant to SOC, threat hunting, and detection engineering roles:



\- working with raw Windows telemetry

\- parsing structured event data

\- distinguishing signal from noise

\- tuning detections to reduce false positives

\- validating detections through controlled attack simulation



Unlike static academic exercises, this implementation uses real EVTX files generated in a virtual lab environment and validates detections against executed suspicious commands.



\## Technical Approach



The workflow implemented in this project follows a simple but defensible detection pipeline:



1\. acquire EVTX evidence from a Windows telemetry source

2\. read records from EVTX format using Python

3\. convert XML records into structured event dictionaries

4\. extract high-value fields such as:

&#x20;  - EventID

&#x20;  - TimeCreated

&#x20;  - Computer

&#x20;  - Image

&#x20;  - CommandLine

&#x20;  - User

&#x20;  - SourceIp

&#x20;  - DestinationIp

5\. apply rule-based detection logic

6\. refine rule conditions based on observed false positives



\## Detection Engineering Focus



The primary implemented use case is suspicious PowerShell detection. The detection logic evolved through multiple stages:



\### Stage 1 — Broad match

Initial logic flagged any event containing `powershell`, which created a high false-positive count driven largely by Splunk internal processes.



\### Stage 2 — Filtering

Known noisy sources were excluded, including:

\- service accounts

\- Splunk-managed PowerShell-related binaries



\### Stage 3 — High-signal matching

Detection was refined to prioritize stronger indicators such as:

\- `-enc`

\- `iex`

\- `downloadstring`



This tuning process more accurately reflects real-world detection engineering work than a one-pass static rule.



\## Deliverables



The project currently produces:



\- a functional CLI-based EVTX analysis tool

\- a namespace-aware EVTX parser

\- structured extraction of EventData fields

\- a tuned suspicious PowerShell detector

\- a documented workflow with supporting evidence screenshots



\## Evidence References



\### Environment Setup

!\[Interpreter Setup](screenshots/01\_pycharm\_interpreter\_setup.png)



\### Project Initialization

!\[Editable Install Success](screenshots/02\_editable\_install\_success.png)



!\[CLI Help Output](screenshots/03\_cli\_help\_output.png)



!\[Project Structure](screenshots/04\_project\_structure\_initialized.png)



\### Data Acquisition

!\[EVTX Export Success](screenshots/05\_flarevm\_evtx\_export\_success.png)



!\[Sample Logs Imported](screenshots/06\_sample\_logs\_imported\_windows11.png)



\## Current State



At the current project stage, the parsing and PowerShell detection pipeline is operational and validated against controlled suspicious activity executed in the FLARE VM. The next major milestone is structured authentication analysis using Windows Security event data.

