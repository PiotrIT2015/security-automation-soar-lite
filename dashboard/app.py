import streamlit as st

from dashboard.data_loader import load_dashboard_data

from dashboard.components import (
    render_incident_overview,
    render_threat_visualization,
    render_incident_management,
    render_response_monitoring
)


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="SOAR Lite Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# --------------------------------------------------
# APPLICATION HEADER
# --------------------------------------------------

st.title("🛡️ SOAR Lite Security Dashboard")

st.caption(
    "Security Orchestration, Automation and Response - "
    "Security Operations Center"
)

st.divider()


# --------------------------------------------------
# LOAD DASHBOARD DATA
# --------------------------------------------------

dashboard_data = load_dashboard_data()

report = dashboard_data["report"]
incidents = dashboard_data["incidents"]
alerts = dashboard_data["alerts"]
detections = dashboard_data["detections"]
events = dashboard_data["events"]
errors = dashboard_data["errors"]


# --------------------------------------------------
# SIDEBAR NAVIGATION
# --------------------------------------------------

st.sidebar.title("SOAR Lite")

st.sidebar.caption("Security Operations Center")

st.sidebar.divider()

pages = [
    "Overview",
    "Incidents",
    "Incident Management",
    "Alerts",
    "Threat Intelligence",
    "Threat Visualization",
    "SOC Response Monitoring"
]

page = st.sidebar.radio(
    "Navigation",
    pages
)

st.sidebar.divider()

if st.sidebar.button("Refresh Data", use_container_width=True):
    st.rerun()


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def render_incidents_page(incidents):
    st.header("Incident Management")

    if not incidents:
        st.info("No incidents available.")
        return

    st.metric(
        "Total Incidents",
        len(incidents)
    )

    st.subheader("Incident History")

    st.dataframe(
        incidents,
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    st.subheader("Incident Details")

    incident_options = {
        f"{incident.get('incident_id', 'Unknown')} - "
        f"{incident.get('title', incident.get('description', 'Incident'))}":
        incident
        for incident in incidents
    }

    selected_incident = st.selectbox(
        "Select an incident",
        list(incident_options.keys())
    )

    incident = incident_options[selected_incident]

    st.json(incident)


def render_alerts_page(alerts):
    st.header("Alert Management")

    if not alerts:
        st.info("No alerts available.")
        return

    st.metric(
        "Total Alerts",
        len(alerts)
    )

    st.subheader("Alert History")

    st.dataframe(
        alerts,
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    st.subheader("Alert Details")

    alert_options = {
        f"{alert.get('alert_id', 'Unknown')} - "
        f"{alert.get('title', alert.get('description', 'Alert'))}":
        alert
        for alert in alerts
    }

    selected_alert = st.selectbox(
        "Select an alert",
        list(alert_options.keys())
    )

    st.json(alert_options[selected_alert])


def render_threat_intelligence_page(report):
    st.header("Threat Intelligence")

    enriched_iocs = report.get("enriched_iocs", [])

    if not enriched_iocs:
        st.info("No enriched IOC data available.")
        return

    st.metric(
        "Enriched Indicators of Compromise",
        len(enriched_iocs)
    )

    st.subheader("Enriched IOC Records")

    st.dataframe(
        enriched_iocs,
        use_container_width=True,
        hide_index=True
    )


def render_response_status(report):
    st.subheader("Automated Response Status")

    responses = report.get("automated_responses", [])

    if not responses:
        st.info("No automated response actions available.")
        return

    st.dataframe(
        responses,
        use_container_width=True,
        hide_index=True
    )


# --------------------------------------------------
# MAIN PAGE ROUTING
# --------------------------------------------------

if page == "Overview":

    render_incident_overview(
        incidents=incidents,
        alerts=alerts,
        detections=detections
    )

    st.divider()

    render_response_status(report)


elif page == "Incidents":

    render_incidents_page(incidents)

elif page == "Incident Management":

    render_incident_management(
        incidents=incidents,
        alerts=alerts,
        report=report
    )

elif page == "Alerts":

    render_alerts_page(alerts)


elif page == "Threat Intelligence":

    render_threat_intelligence_page(report)


elif page == "Threat Visualization":

    render_threat_visualization(
        detections=detections,
        incidents=incidents
    )

elif page == "SOC Response Monitoring":

    render_response_monitoring(
        incidents=incidents,
        report=report
    )

# --------------------------------------------------
# DATA SOURCE INFORMATION
# --------------------------------------------------

with st.sidebar.expander("Data Source Information"):

    st.write("Project:", report.get("project", "SOAR Lite"))

    st.write(
        "Total Events:",
        report.get("total_events", len(events))
    )

    st.write(
        "Total Detections:",
        len(detections)
    )

    st.write(
        "Total Incidents:",
        len(incidents)
    )

    st.write(
        "Total Alerts:",
        len(alerts)
    )


# --------------------------------------------------
# DATA LOADING WARNINGS
# --------------------------------------------------

if errors:

    with st.expander(
        "⚠️ Data Loading Warnings",
        expanded=True
    ):

        for error in errors:
            st.warning(error)


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "SOAR Lite | Security Monitoring and Incident Response | "
    "Dashboard Version 0.1"
)