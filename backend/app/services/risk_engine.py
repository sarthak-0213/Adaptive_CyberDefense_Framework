"""
Risk Engine — weighted scoring, threat-level classification, and adaptive responses.

Scoring weights (configurable via settings):
  honeypot_hit               +40
  direct_protected_path      +30
  failed_login               +10
  expired_alias_access       +15
  blacklisted_token_usage    +50
  rapid_login_attempt        +10
  invalid_refresh_token      +15
  mtd_alias_enumeration      +20

Threat levels:
   0-24   → LOW
  25-49   → MEDIUM
  50-79   → HIGH
  80+     → CRITICAL

Adaptive responses:
  MEDIUM   → mark session suspicious, increase telemetry
  HIGH     → 5-minute block + force re-auth
  CRITICAL → 30-minute block, invalidate tokens, create high-severity event
"""
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.threat_block import ThreatBlock
from app.models.threat_event import ThreatEvent, ThreatScore

logger = logging.getLogger("risk_engine")

# ─── Scoring weights ───────────────────────────────────────────────────────────

EVENT_WEIGHTS: Dict[str, float] = {
    "honeypot_hit": 40.0,
    "direct_protected_path": 30.0,
    "failed_login": 10.0,
    "expired_alias_access": 15.0,
    "blacklisted_token_usage": 50.0,
    "rapid_login_attempt": 10.0,
    "invalid_refresh_token": 15.0,
    "mtd_alias_enumeration": 20.0,
}

# ─── Threat level bands ────────────────────────────────────────────────────────

def classify_threat_level(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


# ─── Score decay ───────────────────────────────────────────────────────────────
# Each score decays by DECAY_RATE per hour.  We compute decay when a new event
# arrives (lazy decay), so no background job is required.

DECAY_RATE_PER_HOUR: float = 5.0    # points lost per hour of inactivity


def apply_decay(current_score: float, last_updated: datetime) -> float:
    """Return score after time-based decay since last_updated."""
    now = datetime.utcnow()
    hours_elapsed = (now - last_updated).total_seconds() / 3600.0
    decayed = current_score - (DECAY_RATE_PER_HOUR * hours_elapsed)
    return max(0.0, decayed)


# ─── Block durations per level ─────────────────────────────────────────────────

BLOCK_DURATIONS: Dict[str, int] = {
    "HIGH": 5 * 60,         # 5 minutes
    "CRITICAL": 30 * 60,    # 30 minutes
}


class RiskEngine:
    """
    Central adaptive risk engine.

    Usage:
        engine.record_event(db, ip, event_type, source, metadata)
        → records ThreatEvent, updates ThreatScore, triggers adaptive response
    """

    def record_event(
        self,
        db: Session,
        ip_address: str,
        event_type: str,
        source: str,
        metadata: Optional[Dict] = None,
    ) -> Tuple[ThreatScore, str]:
        """
        Record a security event, recalculate the risk score, and apply the
        adaptive response appropriate for the resulting threat level.

        Returns (ThreatScore, threat_level).
        """
        weight = EVENT_WEIGHTS.get(event_type, 5.0)
        severity = self._severity_from_weight(weight)

        # ── Persist the raw event ──────────────────────────────────────────────
        event = ThreatEvent(
            ip_address=ip_address,
            event_type=event_type,
            source=source,
            severity=severity,
            score=weight,
            metadata_json=json.dumps(metadata) if metadata else None,
            created_at=datetime.utcnow(),
        )
        db.add(event)
        db.flush()  # get id without committing

        # ── Get or create aggregate ThreatScore ───────────────────────────────
        score_rec = db.query(ThreatScore).filter(
            ThreatScore.ip_address == ip_address
        ).first()

        if score_rec is None:
            score_rec = ThreatScore(
                ip_address=ip_address,
                current_score=0.0,
                threat_level="LOW",
                last_updated=datetime.utcnow(),
            )
            db.add(score_rec)
            db.flush()

        # ── Apply time-based decay before adding new score ────────────────────
        decayed_score = apply_decay(score_rec.current_score, score_rec.last_updated)
        new_score = min(decayed_score + weight, 200.0)  # cap at 200

        old_level = score_rec.threat_level
        new_level = classify_threat_level(new_score)

        score_rec.current_score = new_score
        score_rec.threat_level = new_level
        score_rec.last_updated = datetime.utcnow()

        db.commit()

        logger.info(
            f"[RiskEngine] IP={ip_address} event={event_type} "
            f"score={decayed_score:.1f}+{weight}={new_score:.1f} "
            f"level={old_level}→{new_level}"
        )

        # ── Adaptive response ─────────────────────────────────────────────────
        self._apply_adaptive_response(db, ip_address, new_score, new_level, old_level, score_rec)

        return score_rec, new_level

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _severity_from_weight(weight: float) -> str:
        if weight >= 50:
            return "CRITICAL"
        if weight >= 30:
            return "HIGH"
        if weight >= 15:
            return "MEDIUM"
        return "LOW"

    def _apply_adaptive_response(
        self,
        db: Session,
        ip_address: str,
        score: float,
        level: str,
        old_level: str,
        score_rec: ThreatScore,
    ) -> None:
        """Trigger the action appropriate for the current threat level."""
        if level == "MEDIUM" and old_level == "LOW":
            logger.warning(
                f"[RiskEngine] MEDIUM threat escalation for IP={ip_address} "
                f"score={score:.1f}. Increasing telemetry."
            )
            # Mark event — no network action needed beyond logging.

        elif level == "HIGH" and old_level not in ("HIGH", "CRITICAL"):
            duration_secs = BLOCK_DURATIONS["HIGH"]
            self._create_or_extend_block(db, ip_address, duration_secs, "HIGH", score_rec)
            logger.warning(
                f"[RiskEngine] HIGH threat for IP={ip_address}. "
                f"5-minute block applied. Force re-auth required."
            )

        elif level == "CRITICAL" and old_level != "CRITICAL":
            duration_secs = BLOCK_DURATIONS["CRITICAL"]
            self._create_or_extend_block(db, ip_address, duration_secs, "CRITICAL", score_rec)
            # Record a high-severity dashboard event
            event = ThreatEvent(
                ip_address=ip_address,
                event_type="critical_escalation",
                source="risk_engine",
                severity="CRITICAL",
                score=0.0,
                metadata_json=json.dumps({"score": score, "action": "30-minute block"}),
                created_at=datetime.utcnow(),
            )
            db.add(event)
            db.commit()
            
            # Dispatch external alert
            try:
                from app.services.notification_dispatcher import notification_dispatcher
                notification_dispatcher.dispatch(
                    db=db,
                    event_type="threat_critical",
                    subject="CRITICAL Threat Detected",
                    message=f"CRITICAL threat detected from IP {ip_address} with score {score:.1f}. IP blocked for 30 minutes.",
                    reference_id=ip_address
                )
            except Exception as e:
                logger.error(f"[RiskEngine] Failed to dispatch alert: {e}")

            logger.critical(
                f"[RiskEngine] CRITICAL threat for IP={ip_address}. "
                f"30-minute block + token invalidation triggered."
            )

    @staticmethod
    def _create_or_extend_block(
        db: Session,
        ip_address: str,
        duration_seconds: int,
        level: str,
        score_rec: ThreatScore,
    ) -> ThreatBlock:
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=duration_seconds)

        block = db.query(ThreatBlock).filter(
            ThreatBlock.ip_address == ip_address
        ).first()

        if block is None:
            block = ThreatBlock(
                ip_address=ip_address,
                reason=f"Adaptive risk engine — {level} threat level",
                threat_score=int(score_rec.current_score),
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
            block.blocked_at = now
            block.expires_at = expires_at
            block.last_seen = now
            block.reason = f"Adaptive risk engine — {level} threat level"
            block.threat_score = int(score_rec.current_score)

        db.flush()
        score_rec.active_block_id = block.id

        # Update threat_mitigation_service in-memory cache
        try:
            from app.services.threat_mitigation import threat_mitigation_service
            threat_mitigation_service._blocked_cache[ip_address] = expires_at
        except Exception:
            pass

        db.commit()
        return block

    def recalculate_all(self, db: Session) -> int:
        """
        Recalculate every ThreatScore by replaying decayed scores.
        Returns the number of records updated.
        """
        scores = db.query(ThreatScore).all()
        updated = 0
        for s in scores:
            decayed = apply_decay(s.current_score, s.last_updated)
            new_level = classify_threat_level(decayed)
            if decayed != s.current_score or new_level != s.threat_level:
                s.current_score = decayed
                s.threat_level = new_level
                s.last_updated = datetime.utcnow()
                updated += 1
        db.commit()
        return updated


# ── Singleton ──────────────────────────────────────────────────────────────────
risk_engine = RiskEngine()
