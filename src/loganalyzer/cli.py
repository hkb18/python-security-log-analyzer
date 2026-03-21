import typer
from pathlib import Path
from loganalyzer.parser import read_evtx, extract_basic_fields
from loganalyzer.detectors import detect_suspicious_powershell

app = typer.Typer(help="Windows EVTX security log analyzer")


@app.command()
def analyze(
    sysmon: Path = typer.Argument(..., help="Path to Sysmon EVTX file"),
    security: Path = typer.Argument(..., help="Path to Security EVTX file"),
):
    print("Starting log analysis...\n")

    print("[+] Reading Sysmon logs...")
    sysmon_events = read_evtx(str(sysmon))
    parsed_sysmon = [extract_basic_fields(e) for e in sysmon_events]

    print(f"Loaded {len(sysmon_events)} Sysmon events")

    print("\n[+] Running suspicious PowerShell detection...")
    findings = detect_suspicious_powershell(parsed_sysmon)

    print(f"Detected {len(findings)} suspicious PowerShell events\n")

    for finding in findings[:10]:
        print(finding)

    print("\n[+] Reading Security logs...")
    security_events = read_evtx(str(security))
    print(f"Loaded {len(security_events)} Security events\n")
    print(extract_basic_fields(security_events[0]))

if __name__ == "__main__":
    app()