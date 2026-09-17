"""
Threat Correlation Service — bridges raw security signal sources to the Risk Engine.

Each source (auth, MTD) calls the relevant method here.
This service normalises the event, enriches it with metadata, then delegates
to risk_engine.record_event().
"""
import logging
from typing import Dict, Optional

from sqlalchemy.orm import Session

from app.services.risk_engine import risk_engine

logger = logging.getLogger("threat_correlation")


class ThreatCorrelationService:

    # ── Auth anomalies ─────────────────────────────────────────────────────────

    def on_failed_login(self, db: Session, ip_address: str, email: str) -> None:
        """Record a failed login attempt."""
        risk_engine.record_event(
            db=db,
            ip_address=ip_address,
            event_type="failed_login",
            source="auth",
            metadata={"email": email},
        )
        logger.info(f"[Correlation] failed_login from IP={ip_address} email={email}")

    def on_rapid_login_attempt(self, db: Session, ip_address: str) -> None:
        """Record rapid / brute-force login attempt."""
        risk_engine.record_event(
            db=db,
            ip_address=ip_address,
            event_type="rapid_login_attempt",
            source="auth",
            metadata={},
        )

    def on_invalid_refresh_token(self, db: Session, ip_address: str) -> None:
        """Record use of an invalid or tampered refresh token."""
        risk_engine.record_event(
            db=db,
            ip_address=ip_address,
            event_type="invalid_refresh_token",
            source="auth",
            metadata={},
        )

    def on_blacklisted_token(self, db: Session, ip_address: str, token_prefix: str) -> None:
        """Record a request made with a blacklisted token."""
        risk_engine.record_event(
            db=db,
            ip_address=ip_address,
            event_type="blacklisted_token_usage",
            source="auth",
            metadata={"token_prefix": token_prefix},
        )

    # ── MTD anomalies ──────────────────────────────────────────────────────────

    def on_honeypot_hit(self, db: Session, ip_address: str, path: str) -> None:
        """Record a hit on a honeypot / decoy endpoint."""
        risk_engine.record_event(
            db=db,
            ip_address=ip_address,
            event_type="honeypot_hit",
            source="mtd",
            metadata={"path": path},
        )

    def on_direct_protected_path(self, db: Session, ip_address: str, path: str) -> None:
        """Record direct access attempt to a protected (MTD-shielded) path."""
        risk_engine.record_event(
            db=db,
            ip_address=ip_address,
            event_type="direct_protected_path",
            source="mtd",
            metadata={"path": path},
        )

    def on_expired_alias_access(self, db: Session, ip_address: str, alias: str) -> None:
        """Record access via a stale / deprecated MTD alias."""
        risk_engine.record_event(
            db=db,
            ip_address=ip_address,
            event_type="expired_alias_access",
            source="mtd",
            metadata={"alias": alias},
        )

    def on_mtd_alias_enumeration(self, db: Session, ip_address: str, aliases_tried: int) -> None:
        """Record potential enumeration of multiple dynamic aliases."""
        risk_engine.record_event(
            db=db,
            ip_address=ip_address,
            event_type="mtd_alias_enumeration",
            source="mtd",
            metadata={"aliases_tried": aliases_tried},
        )


# ── Singleton ──────────────────────────────────────────────────────────────────
threat_correlation = ThreatCorrelationService()
