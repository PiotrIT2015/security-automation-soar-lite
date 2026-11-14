import json

from pathlib import Path


# ==================================================
# PROJECT CONFIGURATION
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = PROJECT_ROOT / "data" / "processed"

REPORT_PATH = DATA_DIR / "parsed_logs.json"

INCIDENTS_PATH = DATA_DIR / "incidents.json"

ALERTS_PATH = DATA_DIR / "alerts.json"


# ==================================================
# JSON LOADER
# ==================================================

def load_json(path, default=None, errors=None):

    if default is None:
        default = {}

    if errors is None:
        errors = []

    path = Path(path)

    if not path.exists():

        errors.append(
            f"File not found: {path}"
        )

        return default

    try:

        with path.open(
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except json.JSONDecodeError as error:

        errors.append(
            f"Invalid JSON in {path.name}: {error}"
        )

        return default

    except OSError as error:

        errors.append(
            f"Cannot read {path.name}: {error}"
        )

        return default


# ==================================================
# REPORT LOADER
# ==================================================

def load_report(errors=None):

    if errors is None:
        errors = []

    report = load_json(
        REPORT_PATH,
        default={},
        errors=errors
    )

    if not isinstance(report, dict):

        errors.append(
            "Report JSON must contain an object."
        )

        return {}

    return report


# ==================================================
# INCIDENT LOADER
# ==================================================

def load_incidents(errors=None):

    if errors is None:
        errors = []

    incidents = load_json(
        INCIDENTS_PATH,
        default=None,
        errors=errors
    )

    # Fallback to the main report if the
    # standalone incidents file does not exist.

    if incidents is None:

        report = load_report(errors)

        incidents = report.get(
            "incident_management",
            {}
        ).get(
            "incidents",
            []
        )

    if not isinstance(incidents, list):

        errors.append(
            "Incidents data must be a JSON list."
        )

        return []

    return incidents


# ==================================================
# ALERT LOADER
# ==================================================

def load_alerts(errors=None):

    if errors is None:
        errors = []

    alerts = load_json(
        ALERTS_PATH,
        default=None,
        errors=errors
    )

    # Fallback to the main report if the
    # standalone alerts file does not exist.

    if alerts is None:

        report = load_report(errors)

        alerts = report.get(
            "alerts",
            []
        )

    if not isinstance(alerts, list):

        errors.append(
            "Alerts data must be a JSON list."
        )

        return []

    return alerts


# ==================================================
# DASHBOARD DATA LOADER
# ==================================================

def load_dashboard_data():

    errors = []

    report = load_report(errors)

    incidents = load_incidents(errors)

    alerts = load_alerts(errors)

    detections = report.get(
        "detections",
        []
    )

    if not isinstance(detections, list):

        errors.append(
            "Detections data must be a JSON list."
        )

        detections = []

    events = report.get(
        "events",
        []
    )

    if not isinstance(events, list):

        errors.append(
            "Events data must be a JSON list."
        )

        events = []

    return {

        "report": report,

        "incidents": incidents,

        "alerts": alerts,

        "detections": detections,

        "events": events,

        "errors": errors

    }