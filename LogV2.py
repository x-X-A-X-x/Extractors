import xml.etree.ElementTree as ET
from collections import Counter

def parse_eset_logs(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    logs = []
    for record in root.findall(".//RECORD"):
        time = record.find(".//COLUMN[@NAME='Time']").text
        threat = record.find(".//COLUMN[@NAME='Threat']").text if record.find(".//COLUMN[@NAME='Threat']") is not None else "No Threat"
        detected = int(record.find(".//COLUMN[@NAME='Detected']").text)
        cleaned = int(record.find(".//COLUMN[@NAME='Cleaned']").text)

        logs.append({
            "time": time,
            "threat": threat,
            "detected": detected,
            "cleaned": clea3ned
        })
    return logs

def analyze_threats(logs):
    total_detected = sum(log["detected"] for log in logs)
    total_cleaned = sum(log["cleaned"] for log in logs)
    threat_counter = Counter(log["threat"] for log in logs if log["threat"] != "No Threat")
    top_threats = threat_counter.most_common(5)

    return {
        "total_detected": total_detected,
        "total_cleaned": total_cleaned,
        "top_threats": top_threats
    }
