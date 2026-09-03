from datetime import datetime, timedelta, timezone

RISK_CONFIG = {
    "levels": ((30, "LOW", "NORMAL"), (60, "MEDIUM", "MONITOR"),
               (80, "HIGH", "RESTRICTED"), (100, "CRITICAL", "TEMP_BLOCKED")),
    "windows": {"velocity_minutes": 10, "activity_minutes": 60},
    "rapid_action_seconds": 3,
    "rules": {
        "profile_views": ((6, 4), (12, 8), (20, 13), (35, 18)),
        "profile_velocity": ((5, 5), (10, 10), (18, 16), (30, 22)),
        "distinct_profiles": ((5, 3), (8, 7), (10, 11)),
        "copy_attempts": ((2, 3), (4, 8), (8, 14), (15, 20)),
        "downloads": ((2, 3), (4, 8), (8, 14), (15, 32)),
        "api_requests": ((15, 3), (30, 7), (55, 12), (90, 18)),
        "searches": ((8, 2), (15, 5), (30, 8)),
        "action_frequency": ((25, 4), (45, 8), (75, 13), (120, 18)),
        "rapid_actions": ((5, 4), (12, 8), (25, 13), (45, 18)),
    },
}
RELEVANT_ACTIONS = {"PROFILE_VIEW", "COPY_ATTEMPT", "DOWNLOAD", "API_REQUEST", "SEARCH"}


def _parse_timestamp(value):
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _rule_points(value, thresholds):
    points = 0
    for minimum, rule_points in thresholds:
        if value >= minimum:
            points = rule_points
    return points


def classify_risk(score, config=RISK_CONFIG):
    score = max(0, min(100, int(score)))
    for maximum, level, status in config["levels"]:
        if score <= maximum:
            return level, status
    return "CRITICAL", "TEMP_BLOCKED"


def calculate_risk(events, now=None, config=RISK_CONFIG):
    """Return an explainable assessment from recent audit event dictionaries."""
    now = _parse_timestamp(now) if now is not None else datetime.now(timezone.utc)
    activity_start = now - timedelta(minutes=config["windows"]["activity_minutes"])
    velocity_start = now - timedelta(minutes=config["windows"]["velocity_minutes"])
    recent = []
    for event in events:
        timestamp = _parse_timestamp(event.get("timestamp"))
        if timestamp and activity_start <= timestamp <= now:
            recent.append((timestamp, event))
    recent.sort(key=lambda item: item[0])
    counts = {action: 0 for action in RELEVANT_ACTIONS}
    velocity_views, profiles = 0, set()
    for timestamp, event in recent:
        action = event.get("action")
        if action in counts:
            counts[action] += 1
        if action == "PROFILE_VIEW":
            if event.get("profile_id"):
                profiles.add(event["profile_id"])
            if timestamp >= velocity_start:
                velocity_views += 1
    rapid_actions = sum(1 for previous, current in zip(recent, recent[1:])
                        if (current[0] - previous[0]).total_seconds() <= config["rapid_action_seconds"])
    signals = (("Profile views", counts["PROFILE_VIEW"], "profile_views"),
               ("Profile velocity", velocity_views, "profile_velocity"),
               ("Distinct profiles", len(profiles), "distinct_profiles"),
               ("Repeated copies", counts["COPY_ATTEMPT"], "copy_attempts"),
               ("Downloads", counts["DOWNLOAD"], "downloads"),
               ("API volume", counts["API_REQUEST"], "api_requests"),
               ("Search volume", counts["SEARCH"], "searches"),
               ("Action frequency", len(recent), "action_frequency"),
               ("Rapid actions", rapid_actions, "rapid_actions"))
    breakdown = []
    for label, value, rule_name in signals:
        points = _rule_points(value, config["rules"][rule_name])
        if points:
            breakdown.append({"signal": label, "points": points, "value": value})
    score = max(0, min(100, sum(item["points"] for item in breakdown)))
    level, status = classify_risk(score, config)
    return {"risk_score": score, "risk_level": level, "status": status,
            "breakdown": breakdown,
            "counts": {"profile_views": counts["PROFILE_VIEW"],
                       "copy_attempts": counts["COPY_ATTEMPT"], "downloads": counts["DOWNLOAD"],
                       "api_requests": counts["API_REQUEST"], "searches": counts["SEARCH"],
                       "distinct_profiles": len(profiles), "rapid_actions": rapid_actions}}
