\# Lab Environment



\## Overview



The project was developed and validated using a small virtualized lab environment designed to separate development, telemetry generation, and attack simulation responsibilities.



This separation was intentional. It allows telemetry to be generated in a realistic Windows environment while keeping the development workflow isolated on the primary workstation.



\## Systems Used



\### Windows 11

Role:

\- primary development workstation

\- repository storage location

\- Python execution environment

\- screenshot and documentation management



Responsibilities:

\- stores the Git repository

\- runs the CLI tool

\- receives exported EVTX files from the FLARE VM

\- hosts the Python virtual environment and package dependencies



\### Windows 10 FLARE VM

Role:

\- telemetry source

\- Windows attack simulation target

\- Sysmon and Security log generation point



Responsibilities:

\- produces Windows EVTX logs

\- executes suspicious PowerShell commands for controlled testing

\- exports Sysmon and Security logs for offline analysis



\### Kali Linux VM

Role:

\- attacker simulation platform



Responsibilities:

\- reserved for future attack generation scenarios

\- intended for network- and authentication-based testing

\- not yet used in the final validated detection flow documented in this version



\## Development Environment



The Python environment was configured in PyCharm using a dedicated project virtual environment.



\### Evidence

!\[PyCharm Interpreter Setup](screenshots/01\_pycharm\_interpreter\_setup.png)



The project uses Python 3.14 with an isolated `.venv` interpreter attached to the repository.



\## Initial Project Setup



Project packaging and editable installation were validated before detection logic was developed.



\### Evidence

!\[Editable Install Success](screenshots/02\_editable\_install\_success.png)



!\[CLI Help Output](screenshots/03\_cli\_help\_output.png)



\## Repository Initialization State



The cleaned repository structure was established before implementing the parser and detection modules.



\### Evidence

!\[Project Structure Initialized](screenshots/04\_project\_structure\_initialized.png)



\## Telemetry Collection Method



Telemetry was exported from the Windows 10 FLARE VM as EVTX files using native Windows tooling. Exported files were then copied to the Windows 11 project directory for analysis.



This design supports repeatable offline analysis and avoids coupling the parser directly to live Windows event APIs.



\## Lab Design Rationale



The environment was intentionally divided into separate roles for the following reasons:



\- preserve a clean development environment on Windows 11

\- avoid placing personal GitHub credentials inside lab VMs

\- allow telemetry generation and attack execution to remain isolated

\- support repeatable acquisition of evidence for parser validation



\## Constraints



The project currently operates as an offline analysis workflow. As a result:



\- detections are evaluated against exported EVTX files rather than live event streams

\- evidence must be re-exported after new activity is generated

\- log coverage depends on auditing and Sysmon configuration present in the FLARE VM



\## Operational Value



Although simple in scale, the environment supports realistic detection engineering tasks:



\- telemetry acquisition

\- evidence transfer

\- parser validation

\- controlled execution of suspicious commands

\- iterative tuning of detection logic



This structure is sufficient for demonstrating practical SOC-aligned workflow in a portfolio setting.

