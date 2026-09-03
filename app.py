import json
import os
from datetime import datetime, timedelta, timezone

from flask import Flask, abort, jsonify, render_template, request
from audit_db import (count_audit_events, count_high_risk_sessions, initialize_database,
                      read_audit_user_ids, read_recent_audit_events, read_user_events, read_user_risks,
                      save_user_risk, write_audit_event)
from risk_engine import calculate_risk

app = Flask(__name__)
app.config["DATABASE"] = os.environ.get("SECURITY_MONITOR_DATABASE", os.path.join(app.root_path, "data", "security_monitor.db"))
DEMO_USER_ID = "DEMO-USER-001"
SUPPORTED_CLIENT_ACTIONS = {"PAGE_ENTER", "PAGE_EXIT", "SEARCH", "PROFILE_VIEW", "COPY_ATTEMPT"}
SENSITIVE_ACTIONS = {"COPY_ATTEMPT", "PROFILE_VIEW", "DOWNLOAD"}
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMITS = {"COPY_ATTEMPT": 10, "PROFILE_VIEW": 30, "DOWNLOAD": 5}
_rate_limit_state = {}

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


def recalculate_user_risk(user_id):
    now = datetime.now(timezone.utc)
    since = (now - timedelta(minutes=60)).isoformat(timespec="seconds")
    events = read_user_events(app.config["DATABASE"], user_id, since)
    assessment = calculate_risk(events, now=now)
    assessment["last_activity"] = events[-1]["timestamp"] if events else None
    save_user_risk(app.config["DATABASE"], user_id, assessment, now.isoformat(timespec="seconds"))
    return assessment


def current_user_risk(user_id):
    return recalculate_user_risk(user_id)


def risk_rank(assessment):
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(assessment["risk_level"], 0)


def record_security_event(context, action, details):
    return write_audit_event(app.config["DATABASE"], **context, action=action,
                             screen_name="Security Policy", details=details)


def rate_limit_exceeded(user_id, action):
    limit = RATE_LIMITS.get(action)
    if not limit:
        return False
    now = datetime.now(timezone.utc).timestamp()
    key = (app.config["DATABASE"], user_id, action)
    recent = [timestamp for timestamp in _rate_limit_state.get(key, [])
              if now - timestamp < RATE_LIMIT_WINDOW_SECONDS]
    exceeded = len(recent) >= limit
    if not exceeded:
        recent.append(now)
    _rate_limit_state[key] = recent
    return exceeded


def enforce_sensitive_action(context, action):
    if rate_limit_exceeded(context["user_id"], action):
        record_security_event(context, "RATE_LIMITED", {"action": action, "window_seconds": RATE_LIMIT_WINDOW_SECONDS,
                                                          "limit": RATE_LIMITS[action]})
        return jsonify(error="Rate limit exceeded for this action. Please try again later.",
                       enforcement="RATE_LIMITED"), 429
    risk = current_user_risk(context["user_id"])
    if risk["risk_level"] in {"HIGH", "CRITICAL"}:
        enforcement = "ACTION_BLOCKED" if risk["risk_level"] == "CRITICAL" else "ACTION_RESTRICTED"
        record_security_event(context, enforcement, {"action": action, "risk_score": risk["risk_score"],
                                                     "risk_level": risk["risk_level"]})
        return jsonify(error="This sensitive action is blocked by the current security policy.",
                       enforcement=enforcement, risk_level=risk["risk_level"]), 403
    return None


initialize_database(app.config["DATABASE"])


@app.get("/")
def member_directory():
    if DEMO_USER_ID in read_audit_user_ids(app.config["DATABASE"]):
        recalculate_user_risk(DEMO_USER_ID)
    risks = {item["user_id"]: item for item in read_user_risks(app.config["DATABASE"])}
    risk = risks.get(DEMO_USER_ID, {"risk_score": 0, "risk_level": "LOW", "status": "NORMAL"})
    return render_template("index.html", members=MEMBERS, risk=risk)


@app.get("/admin")
def admin_dashboard():
    for user_id in read_audit_user_ids(app.config["DATABASE"]):
        recalculate_user_risk(user_id)
    events = read_recent_audit_events(app.config["DATABASE"], 40)
    for event in events:
        try:
            details = json.loads(event["details"]) if event["details"] else None
            event["details_display"] = ", ".join(f"{key}: {value}" for key, value in details.items()) if details else "—"
        except (json.JSONDecodeError, AttributeError):
            event["details_display"] = event["details"]
    metrics = {"copy_attempts": count_audit_events(app.config["DATABASE"], "COPY_ATTEMPT"),
               "downloads": count_audit_events(app.config["DATABASE"], "DOWNLOAD"),
               "api_requests": count_audit_events(app.config["DATABASE"], "API_REQUEST"),
               "restricted_actions": count_audit_events(app.config["DATABASE"], "ACTION_RESTRICTED"),
               "blocked_actions": count_audit_events(app.config["DATABASE"], "ACTION_BLOCKED")}
    risks = read_user_risks(app.config["DATABASE"])
    since = (datetime.now(timezone.utc) - timedelta(minutes=60)).isoformat(timespec="seconds")
    metrics.update(monitored_users=len(risks),
                   suspicious_users=sum(item["risk_score"] >= 31 for item in risks),
                   high_risk_sessions=count_high_risk_sessions(app.config["DATABASE"], since))
    return render_template("admin.html", metrics=metrics, recent_events=events, user_risks=risks)


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
        previous_risk = current_user_risk(context["user_id"])
        enforcement_response = enforce_sensitive_action(context, action) if action in SENSITIVE_ACTIONS else None
        if enforcement_response:
            return enforcement_response
        event_id = write_audit_event(app.config["DATABASE"], **event)
        log_api_request(context, "/api/events")
        recalculate_user_risk(context["user_id"])
        updated_risk = current_user_risk(context["user_id"])
        if risk_rank(updated_risk) > risk_rank(previous_risk):
            record_security_event(context, "RISK_ESCALATED", {"risk_score": updated_risk["risk_score"],
                                                               "risk_level": updated_risk["risk_level"]})
    except ValueError as error:
        return jsonify(error=str(error)), 400
    return jsonify(status="recorded", event_id=event_id), 201


@app.get("/api/profiles/<profile_id>/download")
def download_demo_profile(profile_id):
    member = next((item for item in MEMBERS if item["member_id"] == profile_id), None)
    if member is None:
        abort(404)
    context = request_context(request.args)
    previous_risk = current_user_risk(context["user_id"])
    enforcement_response = enforce_sensitive_action(context, "DOWNLOAD")
    if enforcement_response:
        return enforcement_response
    body = json.dumps({"notice": "Fictional demonstration profile", "profile": member}, indent=2).encode()
    write_audit_event(app.config["DATABASE"], **context, action="DOWNLOAD", screen_name="Member Profile",
                      profile_id=profile_id, download_attempt=True, download_size=len(body),
                      api_endpoint=request.path, details={"format": "json"})
    log_api_request(context, request.path)
    updated_risk = current_user_risk(context["user_id"])
    if risk_rank(updated_risk) > risk_rank(previous_risk):
        record_security_event(context, "RISK_ESCALATED", {"risk_score": updated_risk["risk_score"],
                                                           "risk_level": updated_risk["risk_level"]})
    response = app.response_class(body, mimetype="application/json")
    response.headers["Content-Disposition"] = f'attachment; filename="{profile_id}.json"'
    return response


if __name__ == "__main__":
    app.run(debug=True)
