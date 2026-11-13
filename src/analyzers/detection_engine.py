import yaml

from pathlib import Path
from collections import defaultdict

from src.analyzers.threat_scoring import ThreatScorer


class DetectionEngine:

    def __init__(self, rules_path=None):

        if rules_path is None:

            project_root = Path(__file__).resolve().parents[2]

            rules_path = project_root / "config/detection_rules.yaml"

        self.rules_path = Path(rules_path)

        with self.rules_path.open(
            "r",
            encoding="utf-8"
        ) as file:

            self.rules = yaml.safe_load(file)

        self.detection_rules = self.rules["detection"]

        self.scorer = ThreatScorer(
            self.rules["severity"]
        )

    def analyze(self, events, enriched_iocs):

        # Group events by source IP.

        ip_events = defaultdict(list)

        for event in events:

            ip = event.get("source_ip")

            if ip:

                ip_events[ip].append(event)

        # Map Threat Intelligence results.

        intelligence = {
            item["ip"]: item
            for item in enriched_iocs
        }

        detections = []

        # Analyze each IP.

        for ip, ip_event_list in ip_events.items():

            triggered_rules = []

            failed_logins = [
                event for event in ip_event_list
                if event["event_type"] == "FAILED_LOGIN"
            ]

            usernames = {
                event["username"]
                for event in ip_event_list
                if event.get("username")
                and event["event_type"] in (
                    "FAILED_LOGIN",
                    "INVALID_USER"
                )
            }

            # --------------------------------------
            # RULE 1 - BRUTE FORCE
            # --------------------------------------

            rule = self.detection_rules["brute_force"]

            if (
                rule["enabled"]
                and len(failed_logins) >= rule["threshold"]
            ):

                triggered_rules.append({

                    "rule": "BRUTE_FORCE",

                    "score": rule["score"],

                    "description": rule["description"],

                    "evidence": {
                        "failed_attempts": len(failed_logins)
                    }

                })

            # --------------------------------------
            # RULE 2 - MULTIPLE ACCOUNTS
            # --------------------------------------

            rule = self.detection_rules["multiple_accounts"]

            if (
                rule["enabled"]
                and len(usernames) >= rule["threshold"]
            ):

                triggered_rules.append({

                    "rule": "MULTIPLE_ACCOUNTS",

                    "score": rule["score"],

                    "description": rule["description"],

                    "evidence": {
                        "unique_usernames": len(usernames)
                    }

                })

            # --------------------------------------
            # THREAT INTELLIGENCE
            # --------------------------------------

            intel = intelligence.get(ip, {})

            vt = intel.get("virustotal", {})

            abuse = intel.get("abuseipdb", {})

            # --------------------------------------
            # RULE 3 - ABUSEIPDB
            # --------------------------------------

            rule = self.detection_rules["abuseipdb"]

            abuse_score = abuse.get(
                "abuse_confidence_score"
            )

            if (
                rule["enabled"]
                and abuse.get("status") == "success"
                and isinstance(abuse_score, (int, float))
                and abuse_score >= rule["threshold"]
            ):

                triggered_rules.append({

                    "rule": "ABUSEIPDB_HIGH_CONFIDENCE",

                    "score": rule["score"],

                    "description": rule["description"],

                    "evidence": {
                        "abuse_confidence_score": abuse_score
                    }

                })

            # --------------------------------------
            # RULE 4 - VIRUSTOTAL
            # --------------------------------------

            rule = self.detection_rules["virustotal"]

            vt_stats = vt.get("analysis_stats", {})

            malicious = vt_stats.get("malicious", 0)

            if (
                rule["enabled"]
                and vt.get("status") == "success"
                and isinstance(malicious, int)
                and malicious >= rule["threshold"]
            ):

                triggered_rules.append({

                    "rule": "VIRUSTOTAL_MALICIOUS",

                    "score": rule["score"],

                    "description": rule["description"],

                    "evidence": {
                        "malicious_detections": malicious
                    }

                })

            # --------------------------------------
            # THREAT SCORING
            # --------------------------------------

            scoring_result = self.scorer.analyze(
                triggered_rules
            )

            # --------------------------------------
            # FINAL DETECTION
            # --------------------------------------

            detections.append({

                "ip": ip,

                "total_events": len(ip_event_list),

                "failed_logins": len(failed_logins),

                "unique_usernames": len(usernames),

                "threat_score": scoring_result["threat_score"],

                "severity": scoring_result["severity"],

                "triggered_rules": scoring_result["triggered_rules"],

                "threat_intelligence": intel

            })

        return detections