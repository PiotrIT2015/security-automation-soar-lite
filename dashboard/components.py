import streamlit as st
import pandas as pd
import plotly.express as px


def render_kpi(title, value, help_text=None):
    st.metric(
        label=title,
        value=value,
        help=help_text
    )


def render_incident_overview(incidents, alerts, detections):
    st.header("Security Overview")

    total_incidents = len(incidents)

    active_incidents = sum(
        incident.get("status", "").upper() in ("OPEN", "IN_PROGRESS")
        for incident in incidents
    )

    resolved_incidents = sum(
        incident.get("status", "").upper() in ("RESOLVED", "CLOSED")
        for incident in incidents
    )

    total_alerts = len(alerts)
    total_detections = len(detections)

    st.subheader("Incident Statistics")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        render_kpi("Total Incidents", total_incidents)

    with col2:
        render_kpi("Active Incidents", active_incidents)

    with col3:
        render_kpi("Total Alerts", total_alerts)

    with col4:
        render_kpi("Total Detections", total_detections)

    st.divider()

    st.subheader("Threat Severity Distribution")

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for detection in detections:
        severity = detection.get("severity", "LOW").upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

    col1, col2, col3, col4 = st.columns(4)

    for column, (severity, count) in zip(
        [col1, col2, col3, col4],
        severity_counts.items()
    ):
        with column:
            render_kpi(severity, count)

    st.divider()

    st.subheader("Threat Score Overview")

    scores = [
        detection.get("threat_score", 0)
        for detection in detections
        if isinstance(detection.get("threat_score", 0), (int, float))
    ]

    maximum_score = max(scores) if scores else 0

    average_score = (
        round(sum(scores) / len(scores), 2)
        if scores else 0
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        render_kpi("Maximum Threat Score", f"{maximum_score}/100")

    with col2:
        render_kpi("Average Threat Score", average_score)

    with col3:
        render_kpi("Resolved Incidents", resolved_incidents)

    st.divider()

    st.subheader("Security Summary")

    st.write(f"Currently registered incidents: **{total_incidents}**")
    st.write(f"Incidents requiring attention: **{active_incidents}**")

    highest_severity = (
        max(severity_counts, key=severity_counts.get)
        if any(severity_counts.values())
        else "NONE"
    )

    st.write(f"Highest detected severity: **{highest_severity}**")


# --------------------------------------------------
# THREAT VISUALIZATION
# --------------------------------------------------

def render_severity_chart(detections):
    st.subheader("Severity Distribution")

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for detection in detections:
        severity = str(detection.get("severity", "LOW")).upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

    df = pd.DataFrame(
        list(severity_counts.items()),
        columns=["Severity", "Count"]
    )

    fig = px.pie(
        df,
        names="Severity",
        values="Count",
        title="Detected Threats by Severity",
        hole=0.4
    )

    st.plotly_chart(fig, use_container_width=True)


def render_threat_score_chart(detections):
    st.subheader("Threat Score per IP")

    rows = []

    for detection in detections:
        score = detection.get("threat_score", 0)

        if not isinstance(score, (int, float)):
            continue

        rows.append({
            "IP Address": detection.get("ip", "Unknown"),
            "Threat Score": score,
            "Severity": detection.get("severity", "LOW")
        })

    if not rows:
        st.info("No Threat Score data available.")
        return

    df = pd.DataFrame(rows)

    fig = px.bar(
        df,
        x="IP Address",
        y="Threat Score",
        color="Severity",
        title="Threat Score by IP Address",
        hover_data=["Severity"]
    )

    fig.update_layout(
        xaxis_title="IP Address",
        yaxis_title="Threat Score",
        yaxis_range=[0, 100]
    )

    st.plotly_chart(fig, use_container_width=True)


def render_score_distribution(detections):
    st.subheader("Threat Score Distribution")

    scores = [
        detection.get("threat_score")
        for detection in detections
        if isinstance(detection.get("threat_score"), (int, float))
    ]

    if not scores:
        st.info("No Threat Score data available.")
        return

    df = pd.DataFrame({
        "Threat Score": scores
    })

    fig = px.histogram(
        df,
        x="Threat Score",
        nbins=10,
        title="Distribution of Threat Scores"
    )

    fig.update_layout(
        xaxis_title="Threat Score",
        yaxis_title="Number of Detections"
    )

    st.plotly_chart(fig, use_container_width=True)


def render_incidents_by_severity(incidents):
    st.subheader("Incidents by Severity")

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for incident in incidents:
        severity = str(incident.get("severity", "LOW")).upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

    df = pd.DataFrame(
        list(severity_counts.items()),
        columns=["Severity", "Incidents"]
    )

    fig = px.bar(
        df,
        x="Severity",
        y="Incidents",
        title="Incidents by Severity",
        text="Incidents"
    )

    st.plotly_chart(fig, use_container_width=True)


def render_threat_visualization(detections, incidents):
    st.header("Threat Visualization")

    col1, col2 = st.columns(2)

    with col1:
        render_severity_chart(detections)

    with col2:
        render_incidents_by_severity(incidents)

    st.divider()

    render_threat_score_chart(detections)

    st.divider()

    render_score_distribution(detections)
    
# --------------------------------------------------
# INCIDENT MANAGEMENT VIEW
# --------------------------------------------------

def render_incident_management(incidents, alerts, report):

    st.header("Incident Management Center")

    if not incidents:
        st.info("No incidents available.")
        return

    # ----------------------------------------------
    # FILTERS
    # ----------------------------------------------

    st.subheader("Incident Filters")

    col1, col2 = st.columns(2)

    severities = sorted({
        str(incident.get("severity", "UNKNOWN")).upper()
        for incident in incidents
    })

    statuses = sorted({
        str(incident.get("status", "UNKNOWN")).upper()
        for incident in incidents
    })

    with col1:
        selected_severity = st.selectbox(
            "Filter by Severity",
            ["ALL"] + severities
        )

    with col2:
        selected_status = st.selectbox(
            "Filter by Status",
            ["ALL"] + statuses
        )

    filtered_incidents = incidents

    if selected_severity != "ALL":
        filtered_incidents = [
            incident for incident in filtered_incidents
            if str(incident.get("severity", "UNKNOWN")).upper()
            == selected_severity
        ]

    if selected_status != "ALL":
        filtered_incidents = [
            incident for incident in filtered_incidents
            if str(incident.get("status", "UNKNOWN")).upper()
            == selected_status
        ]

    st.divider()

    # ----------------------------------------------
    # INCIDENT TABLE
    # ----------------------------------------------

    st.subheader("Incident Registry")

    st.metric(
        "Filtered Incidents",
        len(filtered_incidents)
    )

    if not filtered_incidents:
        st.info("No incidents match the selected filters.")
        return

    st.dataframe(
        filtered_incidents,
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    # ----------------------------------------------
    # INCIDENT SELECTION
    # ----------------------------------------------

    st.subheader("Incident Investigation")

    incident_options = {
        (
            f"{incident.get('incident_id', 'Unknown')} | "
            f"{incident.get('severity', 'Unknown')} | "
            f"{incident.get('status', 'Unknown')}"
        ): incident
        for incident in filtered_incidents
    }

    selected_incident_name = st.selectbox(
        "Select incident to investigate",
        list(incident_options.keys())
    )

    selected_incident = incident_options[selected_incident_name]

    incident_id = selected_incident.get("incident_id")

    # ----------------------------------------------
    # INCIDENT DETAILS
    # ----------------------------------------------

    st.subheader("Incident Details")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Severity",
            selected_incident.get("severity", "Unknown")
        )

    with col2:
        st.metric(
            "Status",
            selected_incident.get("status", "Unknown")
        )

    with col3:
        st.metric(
            "Threat Score",
            selected_incident.get("threat_score", "N/A")
        )

    st.write(
        "**Incident ID:**",
        incident_id or "Unknown"
    )

    st.write(
        "**Title:**",
        selected_incident.get("title", "N/A")
    )

    st.write(
        "**Description:**",
        selected_incident.get("description", "N/A")
    )

    st.write(
        "**Source IP:**",
        selected_incident.get("ip", "N/A")
    )

    st.write(
        "**Created At:**",
        selected_incident.get(
            "created_at",
            selected_incident.get("timestamp", "N/A")
        )
    )

    with st.expander("Complete Incident Record"):
        st.json(selected_incident)

    st.divider()

    # ----------------------------------------------
    # RELATED ALERTS
    # ----------------------------------------------

    st.subheader("Related Alerts")

    related_alerts = [
        alert for alert in alerts
        if (
            alert.get("incident_id") == incident_id
            and incident_id is not None
        )
    ]

    if related_alerts:
        st.dataframe(
            related_alerts,
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No alerts linked to this incident.")

    st.divider()

    # ----------------------------------------------
    # AUTOMATED RESPONSE STATUS
    # ----------------------------------------------

    st.subheader("Automated Response Status")

    responses = report.get("automated_responses", [])

    related_responses = [
        response for response in responses
        if (
            response.get("incident_id") == incident_id
            and incident_id is not None
        )
    ]

    if related_responses:
        st.dataframe(
            related_responses,
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info(
            "No automated response actions linked to this incident."
        )

    st.caption(
        "Response actions are displayed for monitoring only. "
        "No real network blocking is performed by this dashboard."
    )
    
# --------------------------------------------------
# SOC RESPONSE MONITORING
# --------------------------------------------------

def render_response_monitoring(incidents, report):

    st.header("SOC Response Monitoring")

    responses = report.get("automated_responses", [])

    if not isinstance(responses, list):
        st.error("Invalid automated_responses data format.")
        return

    if not responses:
        st.info("No automated response actions available.")
        st.caption(
            "Response actions will appear here after "
            "the backend processes security incidents."
        )
        return

    # ----------------------------------------------
    # NORMALIZE RESPONSE DATA
    # ----------------------------------------------

    valid_responses = [
        response
        for response in responses
        if isinstance(response, dict)
    ]

    if not valid_responses:
        st.info("No valid response records found.")
        return

    def get_value(record, *keys, default="N/A"):
        for key in keys:
            value = record.get(key)

            if value is not None:
                return value

        return default

    def normalize_status(response):

        status = str(
            get_value(
                response,
                "status",
                "response_status",
                "state",
                default="UNKNOWN"
            )
        ).upper()

        if status in ("SUCCESS", "COMPLETED", "EXECUTED"):
            return "COMPLETED"

        if status in ("PENDING", "AWAITING_APPROVAL"):
            return "PENDING"

        if status in ("FAILED", "ERROR"):
            return "FAILED"

        if status in ("SIMULATED", "SIMULATION"):
            return "SIMULATED"

        return status

    normalized_responses = []

    for response in valid_responses:

        normalized_responses.append({
            "Incident ID": get_value(
                response,
                "incident_id"
            ),
            "Action": get_value(
                response,
                "action",
                "response_action",
                "action_name"
            ),
            "Status": normalize_status(response),
            "Severity": get_value(
                response,
                "severity"
            ),
            "Timestamp": get_value(
                response,
                "timestamp",
                "created_at",
                "executed_at"
            ),
            "Simulation Mode": get_value(
                response,
                "simulation_mode",
                default="Unknown"
            ),
            "Approval Required": get_value(
                response,
                "approval_required",
                "require_approval",
                default="Unknown"
            )
        })

    # ----------------------------------------------
    # RESPONSE KPI
    # ----------------------------------------------

    total_responses = len(normalized_responses)

    completed = sum(
        response["Status"] == "COMPLETED"
        for response in normalized_responses
    )

    pending = sum(
        response["Status"] == "PENDING"
        for response in normalized_responses
    )

    failed = sum(
        response["Status"] == "FAILED"
        for response in normalized_responses
    )

    simulated = sum(
        response["Status"] == "SIMULATED"
        for response in normalized_responses
    )

    st.subheader("Response Statistics")

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric("Total Actions", total_responses)

    with col2:
        st.metric("Completed", completed)

    with col3:
        st.metric("Pending Approval", pending)

    with col4:
        st.metric("Failed", failed)

    with col5:
        st.metric("Simulated", simulated)

    st.divider()

    # ----------------------------------------------
    # RESPONSE FILTERS
    # ----------------------------------------------

    st.subheader("Response Filters")

    col1, col2 = st.columns(2)

    statuses = sorted({
        response["Status"]
        for response in normalized_responses
    })

    actions = sorted({
        str(response["Action"])
        for response in normalized_responses
    })

    with col1:
        selected_status = st.selectbox(
            "Filter by Status",
            ["ALL"] + statuses
        )

    with col2:
        selected_action = st.selectbox(
            "Filter by Action",
            ["ALL"] + actions
        )

    filtered_responses = normalized_responses

    if selected_status != "ALL":
        filtered_responses = [
            response
            for response in filtered_responses
            if response["Status"] == selected_status
        ]

    if selected_action != "ALL":
        filtered_responses = [
            response
            for response in filtered_responses
            if str(response["Action"]) == selected_action
        ]

    st.divider()

    # ----------------------------------------------
    # RESPONSE HISTORY
    # ----------------------------------------------

    st.subheader("Response History")

    if filtered_responses:

        st.dataframe(
            filtered_responses,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No response actions match the selected filters.")

    st.divider()

    # ----------------------------------------------
    # RESPONSE DETAILS
    # ----------------------------------------------

    st.subheader("Response Investigation")

    if not filtered_responses:
        st.info("No response details available.")
        return

    response_options = {}

    for index, response in enumerate(filtered_responses):

        label = (
            f"{response['Incident ID']} | "
            f"{response['Action']} | "
            f"{response['Status']} | "
            f"Record {index + 1}"
        )

        response_options[label] = response

    selected_response_name = st.selectbox(
        "Select response action",
        list(response_options.keys())
    )

    selected_response = response_options[selected_response_name]

    st.write("### Selected Response")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Action",
            selected_response["Action"]
        )

    with col2:
        st.metric(
            "Status",
            selected_response["Status"]
        )

    with col3:
        st.metric(
            "Incident ID",
            selected_response["Incident ID"]
        )

    st.write(
        "**Timestamp:**",
        selected_response["Timestamp"]
    )

    st.write(
        "**Simulation Mode:**",
        selected_response["Simulation Mode"]
    )

    st.write(
        "**Approval Required:**",
        selected_response["Approval Required"]
    )

    # ----------------------------------------------
    # RELATED INCIDENT
    # ----------------------------------------------

    incident_id = selected_response["Incident ID"]

    related_incident = next(
        (
            incident
            for incident in incidents
            if incident.get("incident_id") == incident_id
        ),
        None
    )

    st.divider()

    st.subheader("Related Incident")

    if related_incident:

        st.json(related_incident)

    else:

        st.info(
            "No incident record linked to this response action."
        )

    # ----------------------------------------------
    # COMPLETE RESPONSE RECORD
    # ----------------------------------------------

    with st.expander("Complete Response Record"):

        st.json(
            valid_responses[
                normalized_responses.index(selected_response)
            ]
        )

    st.divider()

    st.warning(
        "Monitoring mode: response actions are displayed for "
        "analysis only. This dashboard does not execute IP blocking "
        "or other real system changes."
    )