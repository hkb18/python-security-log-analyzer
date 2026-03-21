\# Data Acquisition



\## Objective



The objective of the acquisition phase was to collect real Windows telemetry from the Windows 10 FLARE VM and transfer that data into the Windows 11 development environment for offline analysis.



The project currently uses exported EVTX files as the source of truth for parser validation and rule development.



\## Logs Collected



Two EVTX log sources were exported:



\- `sysmon.evtx`

\- `security.evtx`



\### Sysmon

Used for:

\- process creation events

\- network connection events

\- command line telemetry

\- user context

\- parent process relationships



\### Security

Used for:

\- Windows Security event analysis

\- authentication-related telemetry

\- future brute-force detection development



\## Export Method



EVTX files were exported on the Windows 10 FLARE VM using native Windows tooling.



\### Evidence

!\[FLARE VM EVTX Export](screenshots/05\_flarevm\_evtx\_export\_success.png)



This export step confirmed that both Sysmon and Security logs were successfully written to disk.



\## Evidence Transfer



After export, the EVTX files were copied into the repository workspace on Windows 11.



\### Evidence

!\[Sample Logs Imported on Windows 11](screenshots/06\_sample\_logs\_imported\_windows11.png)



This established the offline input dataset used by the Python parser.



\## Acquisition Rationale



Using exported EVTX files instead of live log APIs provides several advantages during development:



\- repeatable testing against fixed evidence

\- simpler parser validation

\- easy comparison of behavior before and after code changes

\- low operational complexity



It also supports controlled re-export after new suspicious activity is generated in the FLARE VM.



\## Dataset Characteristics



The initial dataset contained substantial telemetry volume, which was sufficient for parser validation and detection tuning.



Later parser output confirmed successful ingestion of tens of thousands of records from both sources.



\## Acquisition Limitations



The current Security EVTX dataset does not yet provide the authentication event coverage needed for effective brute-force detection. This indicates that additional Windows audit policy configuration is required before authentication-focused analytics can be implemented with confidence.



\## Current Assessment



The acquisition phase was successful for Sysmon-based detection engineering and sufficient to support:



\- EVTX ingestion testing

\- XML parsing validation

\- EventData extraction

\- PowerShell detection development



The Security dataset remains useful for further work, but requires better authentication event coverage for the next detection phase.

