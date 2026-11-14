import json
import uuid

from pathlib import Path
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class IncidentManager:

    def __init__(self, storage_path=None):

        if storage_path is None:

            storage_path = (
                PROJECT_ROOT
                / "data/processed/incidents.json"
            )

        self.storage_path = Path(storage_path)

        self.storage_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

    def load_incidents(self):

        if not self.storage_path.exists():
            return []

        try:

            data = json.loads(
                self.storage_path.read_text(
                    encoding="utf-8"
                )
            )

            return data if isinstance(data, list) else []

        except (json.JSONDecodeError, OSError):

            return []

    def save_incidents(self, incidents):

        self.storage_path.write_text(

            json.dumps(
                incidents,
                indent=4,
                ensure_ascii=False
            ),

            encoding="utf-8"

        )

    def create_incident(self, detection):

        incident_id = str(uuid.uuid4())

        incident = {

            "incident_id": incident_id,

            "created_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "status": "OPEN",

            "ip": detection["ip"],

            "severity": detection["severity"],

            "threat_score": detection["threat_score"],

            "failed_logins": detection["failed_logins"],

            "triggered_rules": detection["triggered_rules"],

            "description": (
                f"Security incident involving IP "
                f"{detection['ip']}"
            ),

            "assigned_to": "SOC_ANALYST"

        }

        return incident

    def process_detections(
        self,
        detections,
        minimum_severity="MEDIUM"
    ):

        severity_order = {
            "LOW": 0,
            "MEDIUM": 1,
            "HIGH": 2,
            "CRITICAL": 3
        }

        minimum_level = severity_order.get(
            minimum_severity,
            1
        )

        incidents = self.load_incidents()

        new_incidents = []

        for detection in detections:

            severity = detection["severity"]

            level = severity_order.get(severity, 0)

            if level < minimum_level:
                continue

            incident = self.create_incident(detection)

            incidents.append(incident)

            new_incidents.append(incident)

        self.save_incidents(incidents)

        return new_incidents