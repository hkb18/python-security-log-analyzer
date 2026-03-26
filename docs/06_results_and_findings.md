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



\- No time-based correlation across events (fixed threshold only)

\- Cannot detect distributed brute-force attacks (multiple IPs targeting one user)

\- No correlation between failed (4625) and successful (4624) logons

\- Limited detection coverage beyond PowerShell and authentication abuse



\---



\## Next Steps



\- Introduce time-window based correlation for authentication failures

\- Correlate failed (4625) and successful (4624) logons

\- Expand detection coverage (process injection, persistence, lateral movement)

\- Improve detection scoring and prioritization



\---



\## Final Assessment



The project demonstrates:



\- EVTX parsing capability

\- structured log normalization

\- practical detection engineering

\- real-world attack simulation validation



This aligns with SOC analyst and detection engineering workflows.



\---



\## Brute-Force Detection Results



\### Overview



Brute-force authentication detection was implemented using Windows Security Event ID \*\*4625 (failed logon attempts)\*\*.



The detection groups failed authentication events by user and source IP, identifying repeated login failures indicative of brute-force activity.



\---



\### Result 1: Network-Based Authentication Attempts



The detection identified repeated failed logon attempts targeting the account `testuser`.



\- \*\*Target User:\*\* testuser  

\- \*\*Source IP:\*\* 192.168.56.103  

\- \*\*Logon Type:\*\* 3 (Network)  

\- \*\*Failure Count:\*\* 20  



This pattern indicates repeated remote authentication attempts, consistent with brute-force login behavior from another machine in the lab environment.



\---



\### Result 2: Controlled Local Authentication Failures



Controlled testing generated repeated failed logon attempts for the account `bruteuser`.



\- \*\*Target User:\*\* bruteuser  

\- \*\*Source IP:\*\* 127.0.0.1  

\- \*\*Logon Type:\*\* 2 (Interactive)  

\- \*\*Failure Count:\*\* 7  



These events were intentionally generated using incorrect passwords to validate Security log telemetry and confirm detection accuracy.



\---



\### Event Evidence



Windows Security logs clearly recorded these events as Event ID 4625, including user, logon type, and failure reason.



!\[Event Viewer 4625 Evidence](./screenshots/16\_bruteforce\_eventviewer\_4625.png)



\---



\### Detection Output



The CLI output confirmed that the detection engine correctly grouped failed logon attempts and identified brute-force patterns.



!\[Brute-force CLI Detection Output](./screenshots/17\_bruteforce\_cli\_detection\_output.png)



\---



\### Analysis



The detection successfully:



\- identified repeated authentication failures

\- grouped events by user and source IP

\- distinguished between network and local authentication attempts

\- validated both real and simulated attack scenarios



This demonstrates multi-event correlation capability within the detection engine.



\---



\### Security Insight



Authentication logs provide critical visibility into account abuse attempts.



Monitoring failed logons (Event ID 4625) is essential for:



\- detecting brute-force attacks  

\- identifying account enumeration attempts  

\- monitoring lateral movement attempts  



\---



\### Conclusion



The addition of brute-force detection significantly enhances the detection engine by introducing authentication monitoring and multi-event analysis.



This brings the project closer to real-world SOC detection workflows.

