import yaml

from pathlib import Path
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class ResponseEngine:

    def __init__(self, rules_path=None):

        if rules_path is None:

            rules_path = (
                PROJECT_ROOT
                / "config/response_rules.yaml"
            )

        self.rules_path = Path(rules_path)

        with self.rules_path.open(
            "r",
            encoding="utf-8"
        ) as file:

            self.rules = yaml.safe_load(file)

        self.response_config = self.rules["response"]

    def execute(self, incident):

        severity = incident["severity"]

        actions = self.response_config[
            "actions"
        ].get(severity, [])

        results = []

        for action in actions:

            result = self.simulate_action(
                action,
                incident
            )

            results.append(result)

        return {

            "incident_id": incident["incident_id"],

            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "simulation_mode": self.response_config[
                "simulation_mode"
            ],

            "results": results

        }

    def simulate_action(self, action, incident):

        ip = incident["ip"]

        simulation_mode = self.response_config[
            "simulation_mode"
        ]

        result = {

            "action": action,

            "target_ip": ip,

            "status": "SIMULATED",

            "timestamp": datetime.now(
                timezone.utc
            ).isoformat()

        }

        if action == "LOG_EVENT":

            result["message"] = (
                f"Security event logged for {ip}"
            )

        elif action == "CREATE_ALERT":

            result["message"] = (
                f"Alert generated for {ip}"
            )

        elif action == "COLLECT_EVIDENCE":

            result["message"] = (
                f"Evidence collection requested for {ip}"
            )

        elif action == "REQUEST_IP_BLOCK":

            result["message"] = (
                f"IP blocking requested for {ip}. "
                "Manual approval required."
            )

            result["approval_required"] = True

        elif action == "ESCALATE_TO_ANALYST":

            result["message"] = (
                f"Incident escalated to SOC analyst: {ip}"
            )

        else:

            result["status"] = "UNKNOWN_ACTION"

            result["message"] = (
                f"Unknown response action: {action}"
            )

        if not simulation_mode:

            result["status"] = "NOT_EXECUTED"

            result["message"] = (
                "Real response execution is not implemented."
            )

        print(
            f"[*] Response action: {action} "
            f"-> {result['status']}"
        )

        return result

    def process_incidents(self, incidents):

        responses = []

        if not self.response_config["enabled"]:

            print("[-] Response Engine disabled")

            return responses

        for incident in incidents:

            print(
                f"\n[+] Processing incident: "
                f"{incident['incident_id']}"
            )

            response = self.execute(incident)

            responses.append(response)

        return responses