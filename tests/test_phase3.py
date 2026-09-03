from datetime import datetime, timedelta, timezone
import unittest

from risk_engine import calculate_risk

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_events(action, count, seconds_apart=20, profile_cycle=10):
    return [{"action": action,
             "timestamp": (NOW - timedelta(seconds=index * seconds_apart)).isoformat(),
             "profile_id": f"DEMO-{index % profile_cycle}" if action == "PROFILE_VIEW" else None}
            for index in range(count)]


def test_normal_user_is_low_risk():
    activity = make_events("PROFILE_VIEW", 3, 120) + make_events("API_REQUEST", 6, 120)
    assert calculate_risk(activity, NOW)["risk_level"] == "LOW"


def test_one_copy_remains_low_risk():
    result = calculate_risk(make_events("COPY_ATTEMPT", 1), NOW)
    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW"


def test_repeated_copy_behaviour_increases_risk():
    assert calculate_risk(make_events("COPY_ATTEMPT", 8), NOW)["risk_score"] > \
           calculate_risk(make_events("COPY_ATTEMPT", 1), NOW)["risk_score"]


def test_heavy_profile_viewing_increases_risk():
    assert calculate_risk(make_events("PROFILE_VIEW", 25), NOW)["risk_score"] >= 31


def test_heavy_downloading_increases_risk():
    assert calculate_risk(make_events("DOWNLOAD", 15), NOW)["risk_score"] >= 31


def test_scraping_pattern_is_high_or_critical():
    activity = (make_events("PROFILE_VIEW", 40, 2) + make_events("COPY_ATTEMPT", 16, 2)
                + make_events("DOWNLOAD", 16, 2) + make_events("API_REQUEST", 100, 2))
    result = calculate_risk(activity, NOW)
    assert result["risk_level"] == "CRITICAL"
    assert result["risk_score"] > 80


def test_score_is_always_clamped():
    result = calculate_risk(make_events("PROFILE_VIEW", 500, 1), NOW)
    assert isinstance(result["risk_score"], int)
    assert 0 <= result["risk_score"] <= 100


class PhaseThreeTests(unittest.TestCase):
    def test_normal(self): test_normal_user_is_low_risk()
    def test_one_copy(self): test_one_copy_remains_low_risk()
    def test_repeated_copy(self): test_repeated_copy_behaviour_increases_risk()
    def test_profile_views(self): test_heavy_profile_viewing_increases_risk()
    def test_downloads(self): test_heavy_downloading_increases_risk()
    def test_scraping(self): test_scraping_pattern_is_high_or_critical()
    def test_clamping(self): test_score_is_always_clamped()
