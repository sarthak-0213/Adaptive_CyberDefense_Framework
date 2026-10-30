"""
Tests for the Threat Correlation Service — verifies that each signal source
correctly feeds the right event_type into the Risk Engine.
"""
import pytest
from app.models.threat_event import ThreatEvent, ThreatScore
from app.models.threat_block import ThreatBlock
from app.services.threat_correlation import ThreatCorrelationService


def fresh_svc():
    return ThreatCorrelationService()


# ── 1. on_failed_login persists a failed_login event ─────────────────────────

def test_failed_login_event_recorded(client, db_session):
    svc = fresh_svc()
    svc.on_failed_login(db=db_session, ip_address="10.1.0.1", email="a@b.com")

    event = db_session.query(ThreatEvent).filter(
        ThreatEvent.ip_address == "10.1.0.1",
        ThreatEvent.event_type == "failed_login",
    ).first()
    assert event is not None
    assert event.source == "auth"
    assert event.score == 10.0


# ── 2. on_honeypot_hit persists a honeypot_hit event ─────────────────────────

def test_honeypot_hit_event_recorded(client, db_session):
    svc = fresh_svc()
    svc.on_honeypot_hit(db=db_session, ip_address="10.1.0.2", path="/api/v1/admin/debug")

    event = db_session.query(ThreatEvent).filter(
        ThreatEvent.ip_address == "10.1.0.2",
        ThreatEvent.event_type == "honeypot_hit",
    ).first()
    assert event is not None
    assert event.score == 40.0


# ── 3. on_direct_protected_path persists correct event ───────────────────────

def test_direct_protected_path_event(client, db_session):
    svc = fresh_svc()
    svc.on_direct_protected_path(db=db_session, ip_address="10.1.0.3", path="/api/v1/auth/me")

    event = db_session.query(ThreatEvent).filter(
        ThreatEvent.ip_address == "10.1.0.3",
        ThreatEvent.event_type == "direct_protected_path",
    ).first()
    assert event is not None
    assert event.score == 30.0


# ── 4. on_blacklisted_token escalates to HIGH + creates block ────────────────

def test_blacklisted_token_triggers_high_block(client, db_session):
    svc = fresh_svc()
    ip = "10.1.0.4"
    svc.on_blacklisted_token(db=db_session, ip_address=ip, token_prefix="abc123")

    score_rec = db_session.query(ThreatScore).filter(ThreatScore.ip_address == ip).first()
    assert score_rec is not None
    assert score_rec.threat_level == "HIGH"

    block = db_session.query(ThreatBlock).filter(ThreatBlock.ip_address == ip).first()
    assert block is not None
    assert block.status == "blocked"


# ── 5. Multiple correlated events from different sources ─────────────────────

def test_multi_source_correlation(client, db_session):
    svc = fresh_svc()
    ip = "10.1.0.5"
    svc.on_failed_login(db=db_session, ip_address=ip, email="x@y.com")          # +10
    svc.on_honeypot_hit(db=db_session, ip_address=ip, path="/api/v1/system/env") # +40
    svc.on_expired_alias_access(db=db_session, ip_address=ip, alias="/api/v1/d/old") # +15

    score_rec = db_session.query(ThreatScore).filter(ThreatScore.ip_address == ip).first()
    assert score_rec.current_score >= 60.0
    assert score_rec.threat_level == "HIGH"


# ── 6. on_invalid_refresh_token event ────────────────────────────────────────

def test_invalid_refresh_token_event(client, db_session):
    svc = fresh_svc()
    svc.on_invalid_refresh_token(db=db_session, ip_address="10.1.0.6")

    event = db_session.query(ThreatEvent).filter(
        ThreatEvent.ip_address == "10.1.0.6",
        ThreatEvent.event_type == "invalid_refresh_token",
    ).first()
    assert event is not None
    assert event.score == 15.0


# ── 7. on_mtd_alias_enumeration event ────────────────────────────────────────

def test_mtd_alias_enumeration_event(client, db_session):
    svc = fresh_svc()
    svc.on_mtd_alias_enumeration(db=db_session, ip_address="10.1.0.8", aliases_tried=5)

    event = db_session.query(ThreatEvent).filter(
        ThreatEvent.ip_address == "10.1.0.8",
        ThreatEvent.event_type == "mtd_alias_enumeration",
    ).first()
    assert event is not None
    assert event.score == 20.0


# ── 9. Critical escalation: two honeypot hits → CRITICAL block ───────────────

def test_critical_escalation_30_min_block(client, db_session):
    svc = fresh_svc()
    ip = "10.1.0.9"
    # blacklisted_token (50) → HIGH; honeypot_hit (40) pushes score to 90 → CRITICAL
    svc.on_blacklisted_token(db=db_session, ip_address=ip, token_prefix="tok123")
    svc.on_honeypot_hit(db=db_session, ip_address=ip, path="/api/v1/admin/debug")

    block = db_session.query(ThreatBlock).filter(ThreatBlock.ip_address == ip).first()
    assert block is not None
    diff = (block.expires_at - block.blocked_at).total_seconds()
    assert diff == pytest.approx(1800, abs=10)


# ── 10. Security analytics API endpoints ─────────────────────────────────────

def test_security_analytics_api(client, db_session):
    svc = fresh_svc()
    ip = "10.1.0.10"

    # Create a user and get auth token
    client.post("/api/v1/auth/register", json={
        "email": "sec@test.com", "password": "secpassword", "role": "admin"
    })
    login_resp = client.post("/api/v1/auth/login", json={
        "email": "sec@test.com", "password": "secpassword"
    })
    token = login_resp.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    # Record some events
    svc.on_failed_login(db=db_session, ip_address=ip, email="hack@evil.com")
    svc.on_honeypot_hit(db=db_session, ip_address=ip, path="/api/v1/admin/debug")

    # GET /security/threats
    resp = client.get("/api/v1/security/threats", headers=auth_headers)
    assert resp.status_code == 200
    threats = resp.json()
    assert isinstance(threats, list)
    assert any(t["ip_address"] == ip for t in threats)

    # GET /security/threats/{ip}
    resp = client.get(f"/api/v1/security/threats/{ip}", headers=auth_headers)
    assert resp.status_code == 200
    detail = resp.json()
    assert detail["score"]["ip_address"] == ip
    assert len(detail["events"]) >= 2

    # GET /security/metrics
    resp = client.get("/api/v1/security/metrics", headers=auth_headers)
    assert resp.status_code == 200
    metrics = resp.json()
    assert metrics["honeypot_hits_24h"] >= 1
    assert metrics["failed_logins_24h"] >= 1

    # POST /security/recalculate (admin)
    resp = client.post("/api/v1/security/recalculate", headers=auth_headers)
    assert resp.status_code == 200
    assert "recalculated" in resp.json()
