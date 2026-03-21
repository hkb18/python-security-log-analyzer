from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


def read_evtx(file_path):
    """
    Reads EVTX file and returns raw XML events.
    """
    events = []

    with Evtx(file_path) as log:
        for record in log.records():
            try:
                xml = record.xml()
                events.append(xml)
            except Exception:
                continue

    return events


def extract_basic_fields(xml_string):
    """
    Extract basic fields from EVTX XML.
    Handles Windows Event Log XML namespaces.
    """
    data = {}

    try:
        root = ET.fromstring(xml_string)

        ns = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}

        event_id = root.find(".//evt:EventID", ns)
        if event_id is not None:
            data["EventID"] = event_id.text

        time_created = root.find(".//evt:TimeCreated", ns)
        if time_created is not None:
            data["TimeCreated"] = time_created.attrib.get("SystemTime")

        computer = root.find(".//evt:Computer", ns)
        if computer is not None:
            data["Computer"] = computer.text

        # Extract EventData fields
        event_data = root.findall(".//evt:EventData/evt:Data", ns)

        for item in event_data:
            name = item.attrib.get("Name")
            if name:
                data[name] = item.text

    except Exception as e:
        data["ParseError"] = str(e)

    return data

