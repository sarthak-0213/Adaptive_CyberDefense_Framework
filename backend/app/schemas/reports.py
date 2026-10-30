from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class ReportSummary(BaseModel):
    total_events: int
    honeypot_hits_24h: int
    blocked_ips_count: int
    active_alerts_count: int
    mtd_rotations_count: int
    total_audit_logs: int
    last_generated: Optional[str] = None


class ReportItem(BaseModel):
    id: str
    title: str
    type: str  # "Security Audit", "Incident Log", "MTD Analytics", "System Audit Log"
    generatedAt: str
    size: str
    format: str  # "PDF", "CSV", "JSON"
    description: str
    download_url: Optional[str] = None


class ReportGenerateRequest(BaseModel):
    report_type: str  # "security_audit", "incident_log", "mtd_analytics", "audit_log"
    format: str = "JSON"  # "JSON", "CSV", "PDF"
    date_range: Optional[str] = "24h"  # "24h", "7d", "30d", "all"


class ReportGenerateResponse(BaseModel):
    id: str
    title: str
    type: str
    generatedAt: str
    size: str
    format: str
    description: str
    summary: Dict[str, Any]
    data: List[Dict[str, Any]]


class AuditLogOut(BaseModel):
    id: int
    user_email: str
    action: str
    resource: str
    details: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: datetime

    class Config:
        from_attributes = True
