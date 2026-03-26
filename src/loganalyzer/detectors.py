def detect_suspicious_powershell(events):
    """
    Detect suspicious PowerShell executions from Sysmon Event ID 1 logs.
    """
    findings = []

    suspicious_keywords = [
        "powershell",
        "-enc",
        "-encodedcommand",
        "iex",
        "downloadstring",
        "invoke-expression",
        "invoke-webrequest",
        "wget",
        "curl"
    ]

    for event in events:
        event_id = event.get("EventID")
        image = (event.get("Image") or "").lower()
        command_line = (event.get("CommandLine") or "").lower()

        if event_id != "1":
            continue

        # Only real PowerShell
        if "powershell.exe" not in image:
            continue

        # Ignore service accounts (reduce noise)
        if event.get("User", "").lower().startswith("nt service"):
            continue

        matched_keywords = [
            kw for kw in suspicious_keywords
            if kw in command_line
        ]

        # Require at least 1 strong indicator (not just 'powershell')
        strong_keywords = ['-enc', 'iex', 'downloadstring']

        if not any(kw in matched_keywords for kw in strong_keywords):
            continue

        if matched_keywords:
            findings.append({
                "EventID": event.get("EventID"),
                "TimeCreated": event.get("TimeCreated"),
                "Computer": event.get("Computer"),
                "Image": event.get("Image"),
                "CommandLine": event.get("CommandLine"),
                "User": event.get("User"),
                "MatchedKeywords": matched_keywords
            })

    return findings

def detect_bruteforce_logons(events, threshold=5):
    """
    Detect repeated failed logon attempts from Windows Security Event ID 4625.
    Groups failures by (TargetUserName, IpAddress) and reports clusters that
    meet or exceed the threshold.
    """
    grouped_failures = {}

    for event in events:
        if event.get("EventID") != "4625":
            continue

        username = event.get("TargetUserName") or "UNKNOWN"
        ip_address = event.get("IpAddress") or "UNKNOWN"
        logon_type = event.get("LogonType") or "UNKNOWN"

        key = (username, ip_address)

        if key not in grouped_failures:
            grouped_failures[key] = {
                "TargetUserName": username,
                "IpAddress": ip_address,
                "LogonType": logon_type,
                "Count": 0,
                "FirstSeen": event.get("TimeCreated"),
                "LastSeen": event.get("TimeCreated"),
                "Events": []
            }

        grouped_failures[key]["Count"] += 1
        grouped_failures[key]["LastSeen"] = event.get("TimeCreated")
        grouped_failures[key]["Events"].append({
            "TimeCreated": event.get("TimeCreated"),
            "Computer": event.get("Computer"),
            "WorkstationName": event.get("WorkstationName"),
            "Status": event.get("Status"),
            "SubStatus": event.get("SubStatus"),
            "FailureReason": event.get("FailureReason"),
            "IpPort": event.get("IpPort")
        })

    findings = []

    for _, group in grouped_failures.items():
        if group["Count"] >= threshold:
            findings.append({
                "DetectionType": "Brute Force Authentication Attempt",
                "TargetUserName": group["TargetUserName"],
                "IpAddress": group["IpAddress"],
                "LogonType": group["LogonType"],
                "FailureCount": group["Count"],
                "FirstSeen": group["FirstSeen"],
                "LastSeen": group["LastSeen"],
                "SampleEvents": group["Events"][:5]
            })

    return findings