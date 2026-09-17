import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.honeypot import HoneypotLog
from app.models.threat_block import ThreatBlock
from app.models.threat_event import ThreatEvent, ThreatScore
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.reports import (
    ReportSummary,
    ReportItem,
    ReportGenerateRequest,
    ReportGenerateResponse,
)
from app.services.mtd_service import mtd_service

logger = logging.getLogger("reports")


class ReportService:
    def create_audit_log(
        self,
        db: Session,
        user: User,
        action: str,
        resource: str,
        details: str,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        """Helper to create and save an audit log entry."""
        from app.services.audit_service import audit_service
        meta = {"details": details, "user_email": user.email if user else "system"}
        if ip_address:
            meta["ip_address"] = ip_address
        return audit_service.log_action(
            db=db,
            user_id=user.id if user else None,
            action=action,
            resource=resource,
            result="success",
            metadata=meta
        )

    def get_telemetry_summary(self, db: Session) -> ReportSummary:
        """Collects real aggregate telemetry stats across all security modules."""
        now = datetime.now(timezone.utc)
        window_24h = now - timedelta(hours=24)

        total_events = db.query(ThreatEvent).count()
        honeypot_hits_24h = db.query(ThreatEvent).filter(
            ThreatEvent.event_type == "honeypot_hit",
            ThreatEvent.created_at >= window_24h.replace(tzinfo=None)
        ).count()
        blocked_ips_count = db.query(ThreatBlock).filter(ThreatBlock.status == "blocked").count()
        active_alerts_count = db.query(Alert).filter(Alert.status == "active").count()
        total_audit_logs = db.query(AuditLog).count()
        mtd_rotations_count = len(mtd_service.history)

        last_audit = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).first()
        last_gen_str = last_audit.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if last_audit else "N/A"

        return ReportSummary(
            total_events=total_events,
            honeypot_hits_24h=honeypot_hits_24h,
            blocked_ips_count=blocked_ips_count,
            active_alerts_count=active_alerts_count,
            mtd_rotations_count=mtd_rotations_count,
            total_audit_logs=total_audit_logs,
            last_generated=last_gen_str,
        )

    def list_available_reports(self, db: Session) -> List[ReportItem]:
        """Lists standard compilable report categories available in the system."""
        summary = self.get_telemetry_summary(db)
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        return [
            ReportItem(
                id="security_audit",
                title="Full Security Audit Report",
                type="Security Audit",
                generatedAt=now_str,
                size=f"{max(1, summary.total_events * 2)} KB",
                format="JSON",
                description="Comprehensive threat scores, IP blocklists, and risk event timeline compiled from database telemetry.",
                download_url="/api/v1/reports/export/security_audit",
            ),
            ReportItem(
                id="incident_log",
                title="Incident & Threat Log",
                type="Incident Log",
                generatedAt=now_str,
                size=f"{max(1, (summary.honeypot_hits_24h + summary.active_alerts_count) * 2)} KB",
                format="JSON",
                description="Detailed list of active security violation alerts, honeypot trigger events, and suspicious activity logs.",
                download_url="/api/v1/reports/export/incident_log",
            ),
            ReportItem(
                id="mtd_analytics",
                title="Moving Target Defense Analytics",
                type="MTD Analytics",
                generatedAt=now_str,
                size=f"{max(1, summary.mtd_rotations_count * 2)} KB",
                format="JSON",
                description="Dynamic route shuffle history, decoy path configurations, and honeypot alarm telemetry.",
                download_url="/api/v1/reports/export/mtd_analytics",
            ),
            ReportItem(
                id="audit_log",
                title="System Audit & Administrative Trail",
                type="System Audit Log",
                generatedAt=now_str,
                size=f"{max(1, summary.total_audit_logs * 2)} KB",
                format="JSON",
                description="Complete administrative action history, sensitive configuration updates, and report exports.",
                download_url="/api/v1/reports/export/audit_log",
            ),
        ]

    def generate_report(
        self,
        db: Session,
        user: User,
        request: ReportGenerateRequest,
        ip_address: Optional[str] = None,
    ) -> ReportGenerateResponse:
        """Generates a real report snapshot by querying existing database records."""
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        report_type = request.report_type
        fmt = request.format.upper()

        data: List[Dict[str, Any]] = []
        summary_info: Dict[str, Any] = {}
        title = "Compiled Telemetry Report"
        description = "Framework security report compiled from database telemetry."

        if report_type == "security_audit":
            title = "Full Security Audit Report"
            description = "Audit of threat scores, IP block records, and threat events."
            
            blocks = db.query(ThreatBlock).all()
            scores = db.query(ThreatScore).all()
            events = db.query(ThreatEvent).order_by(ThreatEvent.created_at.desc()).limit(100).all()

            summary_info = {
                "total_blocked_ips": len(blocks),
                "total_tracked_scores": len(scores),
                "recent_threat_events_count": len(events),
            }

            for b in blocks:
                data.append({
                    "category": "ThreatBlock",
                    "ip_address": b.ip_address,
                    "reason": b.reason,
                    "hit_count": b.hit_count,
                    "threat_score": b.threat_score,
                    "status": b.status,
                    "last_seen": b.last_seen.isoformat() if b.last_seen else None,
                })
            for e in events:
                data.append({
                    "category": "ThreatEvent",
                    "id": e.id,
                    "ip_address": e.ip_address,
                    "event_type": e.event_type,
                    "source": e.source,
                    "severity": e.severity,
                    "score": e.score,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                })

        elif report_type == "incident_log":
            title = "Incident & Threat Log"
            description = "Log of safety alerts, honeypot hits, and security events."

            alerts = db.query(Alert).order_by(Alert.timestamp.desc()).all()
            honeypots = db.query(HoneypotLog).order_by(HoneypotLog.timestamp.desc()).all()

            summary_info = {
                "total_alerts": len(alerts),
                "active_alerts": sum(1 for a in alerts if a.status == "active"),
                "total_honeypot_hits": len(honeypots),
            }

            for a in alerts:
                data.append({
                    "category": "SecurityAlert",
                    "id": a.id,
                    "title": a.title,
                    "violation_type": a.violation_type,
                    "severity": a.severity,
                    "status": a.status,
                    "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                })
            for h in honeypots:
                data.append({
                    "category": "HoneypotHit",
                    "id": h.id,
                    "decoy_path": h.decoy_path_triggered,
                    "ip_address": h.ip_address,
                    "user_agent": h.user_agent,
                    "timestamp": h.timestamp.isoformat() if h.timestamp else None,
                })

        elif report_type == "mtd_analytics":
            title = "Moving Target Defense Analytics"
            description = "Dynamic route rotation history, active dynamic paths, and decoy paths."

            mtd_status = mtd_service.get_status()
            summary_info = {
                "mtd_enabled": mtd_status.mtd_enabled,
                "rotation_interval_seconds": mtd_status.rotation_interval_seconds,
                "active_dynamic_routes_count": len(mtd_status.active_routes),
                "decoy_paths_count": len(mtd_status.decoy_paths),
                "total_rotation_history": len(mtd_status.rotation_history),
            }

            for route in mtd_status.rotation_history:
                data.append({
                    "category": "PathRotation",
                    "dynamic_path": route.dynamic_path,
                    "target_handler": route.target_handler,
                    "created_at": route.created_at.isoformat() if route.created_at else None,
                    "status": route.status,
                })

        elif report_type == "audit_log":
            title = "System Audit & Administrative Trail"
            description = "Log of admin actions, settings updates, and report generations."

            logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(200).all()
            summary_info = {
                "total_audit_records": len(logs),
            }

            for l in logs:
                meta = json.loads(l.metadata_json) if l.metadata_json else {}
                data.append({
                    "category": "AuditLog",
                    "id": l.id,
                    "user_email": meta.get("user_email", l.user.email if l.user else "system"),
                    "action": l.action,
                    "resource": l.resource,
                    "details": meta.get("details"),
                    "ip_address": meta.get("ip_address"),
                    "timestamp": l.timestamp.isoformat() if l.timestamp else None,
                })
        else:
            # Fallback report compilation from all tables
            title = "Custom Telemetry Report"
            summary_info = {"record_count": 0}

        size_kb = max(1, len(json.dumps(data)) // 1024)

        # Audit this sensitive report generation action
        self.create_audit_log(
            db=db,
            user=user,
            action="REPORT_GENERATED",
            resource=f"reports:{report_type}",
            details=f"Generated '{title}' in {fmt} format ({len(data)} items, {size_kb} KB)",
            ip_address=ip_address,
        )

        return ReportGenerateResponse(
            id=report_type,
            title=title,
            type=report_type.replace("_", " ").title(),
            generatedAt=now_str,
            size=f"{size_kb} KB",
            format=fmt,
            description=description,
            summary=summary_info,
            data=data,
        )

    def get_audit_logs(self, db: Session, limit: int = 100) -> List[AuditLog]:
        """Returns recent audit logs."""
        return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()


report_service = ReportService()
