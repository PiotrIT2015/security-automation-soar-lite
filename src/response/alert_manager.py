import json

from pathlib import Path
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class AlertManager:

    def __init__(self, storage_path=None):

        if storage_path is None:

            storage_path = (
                PROJECT_ROOT
                / "data/processed/alerts.json"
            )

        self.storage_path = Path(storage_path)

        self.storage_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

    def load_alerts(self):

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

    def create_alert(self, incident):

        return {

            "alert_id": incident["incident_id"],

            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "severity": incident["severity"],

            "ip": incident["ip"],

            "threat_score": incident["threat_score"],

            "status": "NEW",

            "message": (
                f"{incident['severity']} security alert: "
                f"suspicious activity from {incident['ip']}"
            )

        }

    def process_incidents(self, incidents):

        alerts = self.load_alerts()

        new_alerts = []

        for incident in incidents:

            alert = self.create_alert(incident)

            alerts.append(alert)

            new_alerts.append(alert)

            print("\n[!] SECURITY ALERT")

            print(
                f"    Severity: {alert['severity']}"
            )

            print(
                f"    IP: {alert['ip']}"
            )

            print(
                f"    Message: {alert['message']}"
            )

        self.storage_path.write_text(

            json.dumps(
                alerts,
                indent=4,
                ensure_ascii=False
            ),

            encoding="utf-8"

        )

        return new_alerts