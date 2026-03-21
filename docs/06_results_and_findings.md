\# Results and Findings



\## Overview



This section summarizes the outcomes of the parser and detection pipeline after processing real EVTX telemetry generated in the lab environment.



\---



\## Data Volume



\- Sysmon events: \~44,000+

\- Security events: \~33,000+



This dataset provided sufficient coverage for:



\- parser validation

\- detection tuning

\- behavior analysis



\---



\## Key Findings



\### 1. High Volume of PowerShell Activity



PowerShell execution occurs frequently even in a controlled lab due to:



\- system processes

\- Splunk services

\- background operations



\---



\### 2. Initial Detection Noise



Initial keyword-based detection generated high false positives.





\---



\### 3. Detection Tuning Improved Accuracy



Refining detection logic reduced noise and improved signal quality.





\---



\### 4. Successful Identification of Malicious Behavior



The system successfully detected:



\- encoded PowerShell execution

\- command injection patterns

\- remote payload execution



\---



\## Security Insight



Effective detection engineering requires continuous tuning to distinguish between normal system behavior and malicious activity.



\---



\## Limitations



\- No authentication attack coverage yet (e.g., Event ID 4625)

\- No event correlation across log sources

\- Single-event detection only



\---



\## Next Steps



\- Implement brute-force detection

\- Add multi-event correlation

\- Improve detection precision

\- Expand rule coverage



\---



\## Final Assessment



The project demonstrates:



\- EVTX parsing capability

\- structured log normalization

\- practical detection engineering

\- real-world attack simulation validation



This aligns with SOC analyst and detection engineering workflows.

