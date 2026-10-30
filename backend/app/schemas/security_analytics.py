"""
Schemas for the Security Analytics endpoints.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel


# ─── ThreatEvent ──────────────────────────────────────────────────────────────

class ThreatEventOut(BaseModel):
    id: int
    ip_address: str
    event_type: str
    source: str
    severity: str
    score: float
    metadata_json: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


# ─── ThreatScore ──────────────────────────────────────────────────────────────

class ThreatScoreOut(BaseModel):
    ip_address: str
    current_score: float
    threat_level: str
    last_updated: datetime
    active_block_id: Optional[int] = None

    class Config:
        from_attributes = True


# ─── Threat detail (score + event timeline) ────────────────────────────────────

class ThreatDetail(BaseModel):
    score: ThreatScoreOut
    events: List[ThreatEventOut]


# ─── Dashboard metrics ─────────────────────────────────────────────────────────

# ─── Gateway Request Log ──────────────────────────────────────────────────────

class GatewayLogOut(BaseModel):
    id: int
    timestamp: datetime
    ip_address: str
    method: str
    endpoint: str
    status_code: int
    response_time_ms: float
    classification: str
    detection_result: Optional[str] = None
    risk_score: Optional[float] = 0.0
    mitigation_action: Optional[str] = "none"

    class Config:
        from_attributes = True


class SecurityMetrics(BaseModel):
    active_blocks: int
    critical_threats: int
    honeypot_hits_24h: int
    failed_logins_24h: int
    average_threat_score: float
    top_offending_ips: List[Dict[str, Any]]

    # Real Gateway and Defense telemetry fields
    total_gateway_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    suspicious_requests: int = 0
    threat_events_recorded: int = 0
    requests_blocked: int = 0
    current_system_risk_level: str = "LOW"
    current_highest_risk_score: float = 0.0
    mtd_rotations_count: int = 0
    avg_gateway_latency_ms: float = 0.0
    recent_gateway_logs: List[GatewayLogOut] = []


# ─── Recalculate response ──────────────────────────────────────────────────────

class RecalculateResponse(BaseModel):
    recalculated: int
    message: str


# ─── Block Management ──────────────────────────────────────────────────────────

class ThreatBlockOut(BaseModel):
    id: int
    ip_address: str
    reason: Optional[str] = None
    threat_score: int
    hit_count: int
    first_seen: datetime
    last_seen: datetime
    blocked_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    status: str

    class Config:
        from_attributes = True

class ManualBlockRequest(BaseModel):
    reason: Optional[str] = "Manual admin block"
    duration_minutes: Optional[int] = 60


class ExternalSecurityEvent(BaseModel):
    ip_address: str
    event_type: str
    source: str = "external_website"
    metadata: Optional[Dict[str, Any]] = None

class ExternalSecurityEventResponse(BaseModel):
    status: str
    ip_address: str
    current_score: float
    threat_level: str
    active_block: bool
