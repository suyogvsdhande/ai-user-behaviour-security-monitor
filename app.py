import json
import os

from flask import Flask, abort, jsonify, render_template, request
from audit_db import count_audit_events, initialize_database, read_recent_audit_events, write_audit_event

app = Flask(__name__)
app.config["DATABASE"] = os.environ.get("SECURITY_MONITOR_DATABASE", os.path.join(app.root_path, "data", "security_monitor.db"))
DEMO_USER_ID = "DEMO-USER-001"
SUPPORTED_CLIENT_ACTIONS = {"PAGE_ENTER", "PAGE_EXIT", "SEARCH", "PROFILE_VIEW", "COPY_ATTEMPT"}

MEMBERS = [
    {
        "member_id": f"DEMO-{1000 + number}",
        "name": name,
        "profession": profession,
        "city": city,
        "email": email,
        "phone": f"+91 90000 {1000 + number:05d}",
    }
    for number, (name, profession, city, email) in enumerate(
        [
            ("Aarav Mehta", "Security Analyst", "Pune", "aarav.mehta@example.test"),
            ("Diya Sharma", "Data Engineer", "Bengaluru", "diya.sharma@example.test"),
            ("Kabir Rao", "Product Designer", "Hyderabad", "kabir.rao@example.test"),
            ("Meera Nair", "Cloud Architect", "Kochi", "meera.nair@example.test"),
            ("Ishaan Kapoor", "Legal Consultant", "New Delhi", "ishaan.kapoor@example.test"),
            ("Ananya Iyer", "Research Scientist", "Chennai", "ananya.iyer@example.test"),
            ("Rohan Desai", "Financial Advisor", "Mumbai", "rohan.desai@example.test"),
            ("Sana Khan", "UX Researcher", "Jaipur", "sana.khan@example.test"),
            ("Vikram Singh", "Operations Manager", "Chandigarh", "vikram.singh@example.test"),
            ("Tara Bose", "Software Developer", "Kolkata", "tara.bose@example.test"),
        ],
        start=1,
    )
]


def clean_text(value, maximum_length):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("Text fields must contain strings.")
    return value.strip()[:maximum_length] or None


def request_context(payload):
    return {"user_id": DEMO_USER_ID, "session_id": clean_text(payload.get("session_id"), 80),
            "device_id": clean_text(payload.get("device_id"), 80), "ip_address": request.remote_addr,
            "browser": request.user_agent.string[:300]}


def log_api_request(context, endpoint):
    write_audit_event(app.config["DATABASE"], **context, action="API_REQUEST", screen_name="API",
                      api_endpoint=endpoint, api_request_count=1, details={"method": request.method})


initialize_database(app.config["DATABASE"])


@app.get("/")
def member_directory():
    return render_template("index.html", members=MEMBERS)


@app.get("/admin")
def admin_dashboard():
    events = read_recent_audit_events(app.config["DATABASE"], 40)
    for event in events:
        try:
            details = json.loads(event["details"]) if event["details"] else None
            event["details_display"] = ", ".join(f"{key}: {value}" for key, value in details.items()) if details else "—"
        except (json.JSONDecodeError, AttributeError):
            event["details_display"] = event["details"]
    metrics = {"copy_attempts": count_audit_events(app.config["DATABASE"], "COPY_ATTEMPT"),
               "downloads": count_audit_events(app.config["DATABASE"], "DOWNLOAD"),
               "api_requests": count_audit_events(app.config["DATABASE"], "API_REQUEST")}
    return render_template("admin.html", metrics=metrics, recent_events=events)


@app.post("/api/events")
def record_event():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="A JSON object is required."), 400
    action = payload.get("action")
    if action not in SUPPORTED_CLIENT_ACTIONS:
        return jsonify(error="Unsupported event action."), 400
    try:
        context = request_context(payload)
        event = {**context, "action": action, "screen_name": clean_text(payload.get("screen_name"), 80)}
        if action == "SEARCH":
            event["search_query"] = clean_text(payload.get("search_query"), 120)
        elif action == "PROFILE_VIEW":
            profile_id = clean_text(payload.get("profile_id"), 40)
            if profile_id not in {member["member_id"] for member in MEMBERS}:
                return jsonify(error="Unknown demo profile."), 400
            event["profile_id"] = profile_id
        elif action == "COPY_ATTEMPT":
            event["copy_attempt"] = True
        elif action == "PAGE_EXIT":
            duration = payload.get("duration_seconds")
            if not isinstance(duration, (int, float)) or isinstance(duration, bool):
                return jsonify(error="duration_seconds must be numeric."), 400
            event["details"] = {"duration_seconds": max(0, min(round(duration, 1), 86400))}
        event_id = write_audit_event(app.config["DATABASE"], **event)
        log_api_request(context, "/api/events")
    except ValueError as error:
        return jsonify(error=str(error)), 400
    return jsonify(status="recorded", event_id=event_id), 201


@app.get("/api/profiles/<profile_id>/download")
def download_demo_profile(profile_id):
    member = next((item for item in MEMBERS if item["member_id"] == profile_id), None)
    if member is None:
        abort(404)
    body = json.dumps({"notice": "Fictional demonstration profile", "profile": member}, indent=2).encode()
    context = request_context(request.args)
    write_audit_event(app.config["DATABASE"], **context, action="DOWNLOAD", screen_name="Member Profile",
                      profile_id=profile_id, download_attempt=True, download_size=len(body),
                      api_endpoint=request.path, details={"format": "json"})
    log_api_request(context, request.path)
    response = app.response_class(body, mimetype="application/json")
    response.headers["Content-Disposition"] = f'attachment; filename="{profile_id}.json"'
    return response


if __name__ == "__main__":
    app.run(debug=True)
