\# Parser Pipeline



\## Objective



The parser pipeline is responsible for ingesting Windows Event Log (EVTX) files and converting them into structured Python objects for downstream detection analysis.



The primary goal is to extract relevant security telemetry from Sysmon and Security logs while handling XML parsing complexities such as namespaces and nested fields.



\---



\## Architecture Overview



The pipeline consists of the following stages:



1\. EVTX File Ingestion

2\. XML Parsing

3\. Namespace Handling

4\. EventData Extraction

5\. Structuring into Python Dictionaries



\---



\## EVTX Ingestion



The parser reads `.evtx` files using the `python-evtx` library.



Each record is processed and converted into raw XML format.



\### Evidence



!\[EVTX ingestion showing successful log parsing](./screenshots/07\_evtx\_ingestion\_success.png)



\---



\## XML Parsing



Each EVTX record is parsed as XML to extract structured fields such as:



\- EventID

\- TimeCreated

\- Computer

\- EventData



The parser iterates through each record and safely handles parsing exceptions to avoid pipeline crashes.



\---



\## Namespace Handling



Windows Event Logs use XML namespaces, which can cause parsing failures if not handled correctly.



The parser implements namespace-aware extraction to ensure compatibility across different log formats.



\### Evidence



!\[Namespace parsing issue resolved during XML extraction](./screenshots/08\_namespace\_parsing\_fixed.png)



\---



\## EventData Extraction



EventData fields contain critical forensic attributes such as:



\- CommandLine

\- Image

\- User

\- ProcessId



The parser extracts these dynamically and maps them into structured key-value pairs.



\### Evidence



!\[Successful extraction of EventData fields from EVTX logs](./screenshots/09\_eventdata\_extraction\_success.png)



\---



\## Output Structure



Each event is normalized into a Python dictionary format:



```python

{

&#x20;   "EventID": "...",

&#x20;   "TimeCreated": "...",

&#x20;   "Computer": "...",

&#x20;   "Image": "...",

&#x20;   "CommandLine": "...",

&#x20;   "User": "..."

}



This structured format enables efficient filtering and detection logic implementation.



Challenges Encountered

XML Namespace Complexity



Initial parsing attempts failed due to namespace prefixes in EVTX XML.



This required explicit handling to correctly locate and extract EventData fields.



Inconsistent Event Structures



Different Event IDs contain varying field structures, requiring flexible parsing logic rather than rigid schemas.



Summary



The parser pipeline successfully converts raw EVTX logs into structured, analyzable data.



This forms the foundation for detection engineering, enabling the identification of suspicious activity such as encoded PowerShell execution and command injection patterns.

