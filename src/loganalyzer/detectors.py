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