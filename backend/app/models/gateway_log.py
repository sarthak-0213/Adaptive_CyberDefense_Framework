from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from app.core.database import Base


class GatewayRequestLog(Base):
    """
    Persists real-time HTTP request telemetry captured by the ACDF Security Gateway
    proxying upstream applications (SecureShop).
    """
    __tablename__ = "gateway_request_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True, nullable=False)
    ip_address = Column(String, index=True, nullable=False)
    method = Column(String(10), nullable=False)
    endpoint = Column(String, index=True, nullable=False)
    status_code = Column(Integer, index=True, nullable=False)
    response_time_ms = Column(Float, nullable=False, default=0.0)
    classification = Column(String(32), index=True, nullable=False, default="legitimate")
    # classification: "legitimate", "suspicious", "attack", "blocked", "honeypot"
    detection_result = Column(String(64), nullable=True)
    # detection_result: "sql_injection", "cross_site_scripting", "directory_traversal", "honeypot_hit", "brute_force", "direct_protected_path", "none"
    risk_score = Column(Float, nullable=True, default=0.0)
    mitigation_action = Column(String(64), nullable=True, default="none")
    # mitigation_action: "none", "waf_rejected_400", "decoy_404", "blocked_403", "deprecated_410"
