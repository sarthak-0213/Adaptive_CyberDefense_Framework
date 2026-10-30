"""
Security Analytics Router — exposes threat data and risk metrics.

Endpoints:
  GET  /api/v1/security/threats          — active threats ordered by score
  GET  /api/v1/security/threats/{ip}     — full event timeline for an IP
  GET  /api/v1/security/metrics          — dashboard summary metrics
  POST /api/v1/security/recalculate      — admin-only manual recalculation
"""
from datetime import datetime, timedelta
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.threat_block import ThreatBlock
from app.models.threat_event import ThreatEvent, ThreatScore
from app.models.gateway_log import GatewayRequestLog
from app.services.mtd_service import mtd_service
from app.schemas.security_analytics import GatewayLogOut
from app.schemas.security_analytics import (
    RecalculateResponse,
    SecurityMetrics,
    ThreatDetail,
    ThreatEventOut,
    ThreatScoreOut,
    ThreatBlockOut,
    ManualBlockRequest,
    ExternalSecurityEvent,
    ExternalSecurityEventResponse,
)
from app.services.risk_engine import risk_engine
from app.services.audit_service import audit_service
from app.utils.deps import get_current_user, get_db, RequirePermission
from app.models.user import User

router = APIRouter(prefix="/security", tags=["Security Analytics"])

require_security_monitoring = RequirePermission("security_monitoring")
require_threat_management = RequirePermission("threat_management")
require_ip_blocking = RequirePermission("ip_blocking")


# ── GET /security/threats ──────────────────────────────────────────────────────

@router.get("/threats", response_model=List[ThreatScoreOut])
def list_active_threats(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_monitoring),
):
    """Return all tracked IPs ordered by current risk score (descending)."""
    scores = (
        db.query(ThreatScore)
        .order_by(ThreatScore.current_score.desc())
        .all()
    )
    return scores


# ── GET /security/threats/{ip} ─────────────────────────────────────────────────

@router.get("/threats/{ip_address}", response_model=ThreatDetail)
def get_threat_detail(
    ip_address: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_monitoring),
):
    """Return the risk score and full event timeline for a specific IP."""
    score_rec = db.query(ThreatScore).filter(
        ThreatScore.ip_address == ip_address
    ).first()
    if not score_rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No threat data found for IP {ip_address}",
        )

    events = (
        db.query(ThreatEvent)
        .filter(ThreatEvent.ip_address == ip_address)
        .order_by(ThreatEvent.created_at.desc())
        .all()
    )

    return ThreatDetail(score=score_rec, events=events)


# ── GET /security/metrics ──────────────────────────────────────────────────────

@router.get("/metrics", response_model=SecurityMetrics)
def get_security_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_monitoring),
):
    """Return aggregated dashboard metrics."""
    now = datetime.utcnow()
    window_24h = now - timedelta(hours=24)

    # Active blocks
    active_blocks = db.query(ThreatBlock).filter(
        ThreatBlock.status == "blocked"
    ).count()

    # Critical threats
    critical_threats = db.query(ThreatScore).filter(
        ThreatScore.threat_level == "CRITICAL"
    ).count()

    # Honeypot hits in last 24 h
    honeypot_hits_24h = db.query(ThreatEvent).filter(
        ThreatEvent.event_type == "honeypot_hit",
        ThreatEvent.created_at >= window_24h,
    ).count()

    # Failed logins in last 24 h
    failed_logins_24h = db.query(ThreatEvent).filter(
        ThreatEvent.event_type == "failed_login",
        ThreatEvent.created_at >= window_24h,
    ).count()

    # Average threat score
    avg_result = db.query(func.avg(ThreatScore.current_score)).scalar()
    average_threat_score = round(float(avg_result or 0.0), 2)

    # Top 10 offending IPs
    top_ips_query = (
        db.query(ThreatScore)
        .order_by(ThreatScore.current_score.desc())
        .limit(10)
        .all()
    )
    top_offending_ips = [
        {
            "ip_address": s.ip_address,
            "current_score": round(s.current_score, 2),
            "threat_level": s.threat_level,
        }
        for s in top_ips_query
    ]

    # Gateway telemetry metrics
    total_gateway_requests = db.query(GatewayRequestLog).count()
    successful_requests = db.query(GatewayRequestLog).filter(GatewayRequestLog.status_code < 400).count()
    failed_requests = db.query(GatewayRequestLog).filter(GatewayRequestLog.status_code >= 400).count()
    suspicious_requests = db.query(GatewayRequestLog).filter(
        GatewayRequestLog.classification.in_(["suspicious", "attack", "honeypot", "blocked"])
    ).count()
    threat_events_recorded = db.query(ThreatEvent).count()
    requests_blocked = db.query(GatewayRequestLog).filter(
        (GatewayRequestLog.status_code == 403) | (GatewayRequestLog.mitigation_action == "blocked_403")
    ).count()
    
    max_score = db.query(func.max(ThreatScore.current_score)).scalar() or 0.0
    current_highest_risk_score = round(float(max_score), 2)

    if critical_threats > 0:
        current_system_risk_level = "CRITICAL"
    elif active_blocks > 0 or current_highest_risk_score >= 50.0:
        current_system_risk_level = "HIGH"
    elif current_highest_risk_score >= 25.0 or suspicious_requests > 0:
        current_system_risk_level = "MEDIUM"
    else:
        current_system_risk_level = "LOW"

    avg_latency = db.query(func.avg(GatewayRequestLog.response_time_ms)).scalar()
    avg_gateway_latency_ms = round(float(avg_latency or 0.0), 2)
    mtd_rotations_count = len(mtd_service.history)

    recent_gateway_logs = (
        db.query(GatewayRequestLog)
        .order_by(GatewayRequestLog.timestamp.desc())
        .limit(10)
        .all()
    )

    return SecurityMetrics(
        active_blocks=active_blocks,
        critical_threats=critical_threats,
        honeypot_hits_24h=honeypot_hits_24h,
        failed_logins_24h=failed_logins_24h,
        average_threat_score=average_threat_score,
        top_offending_ips=top_offending_ips,
        total_gateway_requests=total_gateway_requests,
        successful_requests=successful_requests,
        failed_requests=failed_requests,
        suspicious_requests=suspicious_requests,
        threat_events_recorded=threat_events_recorded,
        requests_blocked=requests_blocked,
        current_system_risk_level=current_system_risk_level,
        current_highest_risk_score=current_highest_risk_score,
        mtd_rotations_count=mtd_rotations_count,
        avg_gateway_latency_ms=avg_gateway_latency_ms,
        recent_gateway_logs=recent_gateway_logs,
    )


# ── GET /security/gateway-logs ─────────────────────────────────────────────────

@router.get("/gateway-logs", response_model=List[GatewayLogOut])
def list_gateway_logs(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_monitoring),
):
    """Return raw gateway request logs recorded by the perimeter gateway."""
    return (
        db.query(GatewayRequestLog)
        .order_by(GatewayRequestLog.timestamp.desc())
        .limit(limit)
        .all()
    )


# ── POST /security/recalculate ─────────────────────────────────────────────────

@router.post("/recalculate", response_model=RecalculateResponse)
def recalculate_scores(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_threat_management),
):
    """Admin only — manually trigger score recalculation with decay applied."""
    updated = risk_engine.recalculate_all(db)
    
    audit_service.log_action(
        db=db,
        user_id=current_user.id,
        action="recalculate_scores",
        resource="risk_engine",
        result="success",
        metadata={"updated_count": updated}
    )
    
    return RecalculateResponse(
        recalculated=updated,
        message=f"Recalculated {updated} threat scores with decay applied.",
    )


# ── GET /security/blocks ───────────────────────────────────────────────────────

@router.get("/blocks", response_model=List[ThreatBlockOut])
def list_blocks(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_monitoring),
):
    """Return all threat block history."""
    blocks = db.query(ThreatBlock).order_by(ThreatBlock.last_seen.desc()).all()
    return blocks


# ── POST /security/blocks/{ip}/block ───────────────────────────────────────────

@router.post("/blocks/{ip_address}/block", response_model=ThreatBlockOut)
def manual_block_ip(
    ip_address: str,
    req: ManualBlockRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_ip_blocking),
):
    """Admin only — manually block an IP address."""
    from datetime import timezone
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    expires_at = now + timedelta(minutes=req.duration_minutes)

    block = db.query(ThreatBlock).filter(ThreatBlock.ip_address == ip_address).first()
    if not block:
        block = ThreatBlock(
            ip_address=ip_address,
            reason=req.reason,
            threat_score=100,
            hit_count=1,
            status="blocked",
            first_seen=now,
            last_seen=now,
            blocked_at=now,
            expires_at=expires_at,
        )
        db.add(block)
    else:
        block.status = "blocked"
        block.reason = req.reason
        block.last_seen = now
        block.blocked_at = now
        block.expires_at = expires_at

    # Check if a ThreatScore exists and link it
    score_rec = db.query(ThreatScore).filter(ThreatScore.ip_address == ip_address).first()
    if score_rec:
        score_rec.threat_level = "CRITICAL"
        score_rec.current_score = max(score_rec.current_score, 100.0)
        
    db.flush()
    if score_rec:
        score_rec.active_block_id = block.id

    from app.services.threat_mitigation import threat_mitigation_service
    threat_mitigation_service._blocked_cache[ip_address] = expires_at

    db.commit()
    db.refresh(block)
    
    audit_service.log_action(
        db=db,
        user_id=current_user.id,
        action="block_ip",
        resource=f"ip:{ip_address}",
        result="success",
        metadata={"reason": req.reason, "duration_minutes": req.duration_minutes}
    )
    
    return block


# ── POST /security/blocks/{ip}/unblock ─────────────────────────────────────────

@router.post("/blocks/{ip_address}/unblock", response_model=ThreatBlockOut)
def manual_unblock_ip(
    ip_address: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_ip_blocking),
):
    """Admin only — manually unblock an IP address."""
    block = db.query(ThreatBlock).filter(ThreatBlock.ip_address == ip_address).first()
    if not block:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No block record found for IP {ip_address}",
        )

    block.status = "unblocked"
    # Do not reset expires_at so history remains clear

    score_rec = db.query(ThreatScore).filter(ThreatScore.ip_address == ip_address).first()
    if score_rec:
        score_rec.active_block_id = None
        # Maybe lower score slightly or leave it to decay

    from app.services.threat_mitigation import threat_mitigation_service
    if ip_address in threat_mitigation_service._blocked_cache:
        del threat_mitigation_service._blocked_cache[ip_address]

    db.commit()
    db.refresh(block)
    
    audit_service.log_action(
        db=db,
        user_id=current_user.id,
        action="unblock_ip",
        resource=f"ip:{ip_address}",
        result="success"
    )
    
    return block

# ── POST /security/events ──────────────────────────────────────────────────────

@router.post("/events", response_model=ExternalSecurityEventResponse, status_code=status.HTTP_201_CREATED)
def record_external_event(
    event_data: ExternalSecurityEvent,
    db: Session = Depends(get_db),
):
    """
    Ingest a security event from an integrated external application (like SecureShop).
    Enriches with risk score calculation and triggers automated adaptive responses.
    """
    score_rec, level = risk_engine.record_event(
        db=db,
        ip_address=event_data.ip_address,
        event_type=event_data.event_type,
        source=event_data.source,
        metadata=event_data.metadata,
    )
    return ExternalSecurityEventResponse(
        status="recorded",
        ip_address=event_data.ip_address,
        current_score=round(score_rec.current_score, 2),
        threat_level=level,
        active_block=bool(score_rec.active_block_id),
    )
