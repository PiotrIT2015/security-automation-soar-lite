import json
import time
import ipaddress

from datetime import datetime, timezone

from pathlib import Path

from src.analyzers.detection_engine import DetectionEngine

from src.collectors.log_collector import LogCollector
from src.parsers.linux_parser import LinuxParser
from src.analyzers.ioc_extractor import IOCExtractor

from src.integrations.virustotal import VirusTotalClient
from src.integrations.abuseipdb import AbuseIPDBClient


# ==================================================
# CONFIGURATION
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

LOG_PATH = PROJECT_ROOT / "data/raw/linux/auth.log"

REPORT_PATH = PROJECT_ROOT / "data/processed/parsed_logs.json"

VT_REQUEST_INTERVAL = 15


# ==================================================
# MAIN APPLICATION
# ==================================================

def main():

    print("\n================================")
    print("          SOAR LITE")
    print("================================\n")

    print("[+] Starting log analysis...\n")

    # ------------------------------------------------
    # 1. COLLECT LOGS
    # ------------------------------------------------

    collector = LogCollector(str(LOG_PATH))

    logs = collector.collect_all()

    print(f"[+] Collected logs: {len(logs)}")

    # ------------------------------------------------
    # 2. PARSE LOGS
    # ------------------------------------------------

    parser = LinuxParser()

    events = parser.parse_logs(logs)

    print(f"[+] Parsed events: {len(events)}")

    # ------------------------------------------------
    # 3. EXTRACT IOC
    # ------------------------------------------------

    extractor = IOCExtractor()

    iocs = extractor.extract_ips(events)

    print(f"[+] Unique IP addresses: {len(iocs)}")

    # ------------------------------------------------
    # 4. SECURITY STATISTICS
    # ------------------------------------------------

    failed = sum(
        event["event_type"] == "FAILED_LOGIN"
        for event in events
    )

    successful = sum(
        event["event_type"] == "SUCCESSFUL_LOGIN"
        for event in events
    )

    invalid_users = sum(
        event["event_type"] == "INVALID_USER"
        for event in events
    )

    print("\n[+] SECURITY STATISTICS")

    print(f"    Failed logins: {failed}")
    print(f"    Successful logins: {successful}")
    print(f"    Invalid users: {invalid_users}")

    # ------------------------------------------------
    # 5. THREAT INTELLIGENCE ENRICHMENT
    # ------------------------------------------------

    print("\n[+] Starting Threat Intelligence analysis...")

    enriched_iocs = []

    # Select only globally routable IP addresses.

    public_iocs = []

    for ioc in iocs:

        ip = ioc["ip"]

        try:

            address = ipaddress.ip_address(ip)

        except ValueError:

            print(f"[-] Invalid IP address: {ip}")

            continue

        if not address.is_global:

            print(f"[-] Skipping non-global IP: {ip}")

            enriched_iocs.append({
                "ip": ip,
                "status": "skipped_non_global"
            })

            continue

        public_iocs.append(ip)

    # ------------------------------------------------
    # 6. INITIALIZE API CLIENTS
    # ------------------------------------------------

    if public_iocs:

        try:

            vt_client = VirusTotalClient()

            abuse_client = AbuseIPDBClient()

        except ValueError as error:

            print(f"\n[!] API configuration error: {error}")

            return

        print(
            f"\n[+] Public IP addresses to analyze: "
            f"{len(public_iocs)}"
        )

        # --------------------------------------------
        # 7. QUERY EXTERNAL THREAT INTELLIGENCE
        # --------------------------------------------

        for index, ip in enumerate(public_iocs):

            print(f"\n[+] Analyzing IP: {ip}")

            # VirusTotal

            print("[*] Querying VirusTotal...")

            vt_result = vt_client.check_ip(ip)

            print(
                f"[+] VirusTotal status: "
                f"{vt_result.get('status')}"
            )

            # Rate limiting between VirusTotal requests.

            if index < len(public_iocs) - 1:

                print("[*] Waiting 15 seconds...")

                time.sleep(VT_REQUEST_INTERVAL)

            # AbuseIPDB

            print("[*] Querying AbuseIPDB...")

            abuse_result = abuse_client.check_ip(ip)

            print(
                f"[+] AbuseIPDB status: "
                f"{abuse_result.get('status')}"
            )

            # Store enriched IOC.

            enriched_iocs.append({

                "ip": ip,

                "virustotal": vt_result,

                "abuseipdb": abuse_result

            })

    else:

        print(
            "[-] No globally routable IP addresses found."
        )

        print(
            "[-] External API queries skipped."
        )

    # ------------------------------------------------
    # 8. THREAT DETECTION & SCORING
    # ------------------------------------------------

    print("\n[+] Starting Threat Detection Engine...")

    detection_engine = DetectionEngine()

    detections = detection_engine.analyze(
        events,
        enriched_iocs
    )

    print("\n[+] THREAT ANALYSIS RESULTS")

    for detection in detections:

        print("\n--------------------------------")

        print(f"IP: {detection['ip']}")

        print(
            f"Threat Score: "
            f"{detection['threat_score']}/100"
        )

        print(
            f"Severity: "
            f"{detection['severity']}"
        )

        if detection["triggered_rules"]:

            print("Triggered rules:")

            for rule in detection["triggered_rules"]:

                print(
                    f"  [+] {rule['rule']} "
                    f"(+{rule['score']})"
                )

        else:

            print("[-] No detection rules triggered")

    # ------------------------------------------------
    # 9. DETECTION SUMMARY
    # ------------------------------------------------

    summary = {

        "critical": sum(
            item["severity"] == "CRITICAL"
            for item in detections
        ),

        "high": sum(
            item["severity"] == "HIGH"
            for item in detections
        ),

        "medium": sum(
            item["severity"] == "MEDIUM"
            for item in detections
        ),

        "low": sum(
            item["severity"] == "LOW"
            for item in detections
        )

    }

    print("\n[+] DETECTION SUMMARY")

    for severity, count in summary.items():

        print(f"    {severity.upper()}: {count}")

    # ------------------------------------------------
    # 8. GENERATE JSON REPORT
    # ------------------------------------------------

    report = {

        "project": "SOAR Lite",

        "total_logs": len(logs),

        "total_events": len(events),

        "failed_logins": failed,

        "successful_logins": successful,

        "invalid_users": invalid_users,

        "total_iocs": len(iocs),

        "iocs": iocs,

        "enriched_iocs": enriched_iocs,
        
        "detections": detections,
        
        "detection_summary": summary,

        "events": events

    }

    REPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    REPORT_PATH.write_text(

        json.dumps(
            report,
            indent=4,
            ensure_ascii=False
        ),

        encoding="utf-8"

    )

    print("\n[+] REPORT GENERATED")

    print(f"[+] Report saved: {REPORT_PATH}")

    print("\n================================")
    print("      ANALYSIS COMPLETED")
    print("================================\n")


# ==================================================
# APPLICATION ENTRY POINT
# ==================================================

if __name__ == "__main__":

    main()