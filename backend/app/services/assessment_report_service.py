import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models.security_assessment import (
    SecurityAssessment,
    AssessmentResult,
    SecurityFinding,
)
from app.models.user import User
from app.schemas.security_assessment import (
    SecurityAssessmentRunRequest,
    SecurityAssessmentFullResponse,
    SecurityAssessmentSummary,
    SecurityFindingOut,
    SecurityAssessmentListItem,
)
from app.services.network_assessment_service import network_assessment_service
from app.services.portal_analysis_service import portal_analysis_service
from app.services.session_analysis_service import session_analysis_service
from app.services.access_control_service import access_control_service
from app.services.segmentation_service import segmentation_service
from app.services.hardening_service import hardening_service
from app.services.audit_service import audit_service

logger = logging.getLogger("security_assessment")


class AssessmentReportService:
    def run_full_assessment(
        self,
        db: Session,
        user: Optional[User],
        request: SecurityAssessmentRunRequest,
        client_ip: Optional[str] = None
    ) -> SecurityAssessmentFullResponse:
        target = request.target.strip()
        start_time = datetime.now(timezone.utc)

        # Audit Assessment Started
        audit_service.log_action(
            db=db,
            user_id=user.id if user else None,
            action="SECURITY_ASSESSMENT_STARTED",
            resource=f"assessment:target:{target}",
            result="STARTED",
            metadata={
                "target": target,
                "user_email": user.email if user else "system",
                "ip_address": client_ip,
                "timestamp": start_time.isoformat()
            }
        )

        # Create SecurityAssessment DB record
        assessment_record = SecurityAssessment(
            target=target,
            user_id=user.id if user else None,
            status="in_progress",
            started_at=start_time
        )
        db.add(assessment_record)
        db.commit()
        db.refresh(assessment_record)

        # 1. Execute Network Reconnaissance
        network_res = network_assessment_service.assess_network(target)
        self._save_result(db, assessment_record.id, "network", network_res.status, network_res.model_dump())

        # 2. Execute Portal Analysis
        portal_res = portal_analysis_service.analyze_portal(target)
        self._save_result(db, assessment_record.id, "portal", portal_res.status, portal_res.model_dump())

        # 3. Execute HTTP / HTTPS Analysis
        http_https_res = session_analysis_service.analyze_http_https(target)
        self._save_result(db, assessment_record.id, "http_https", http_https_res.status, http_https_res.model_dump())

        # 4. Execute Session Security Analysis
        session_res = session_analysis_service.analyze_session(target)
        self._save_result(db, assessment_record.id, "session", session_res.status, session_res.model_dump())

        # 5. Execute Access-Control RBAC Testing
        access_res = access_control_service.evaluate_access_controls(
            db=db, target=target, custom_endpoints=request.test_endpoints
        )
        self._save_result(db, assessment_record.id, "access_control", access_res.overall_status, access_res.model_dump())

        # 6. Execute Network Segmentation Analysis
        seg_res = segmentation_service.assess_segmentation(target, request.client_nodes)
        self._save_result(db, assessment_record.id, "segmentation", seg_res.status, seg_res.model_dump())

        # 7. Execute Defensive Hardening Checklist
        hardening_res = hardening_service.evaluate_hardening(db, target)
        self._save_result(db, assessment_record.id, "hardening", hardening_res.status, hardening_res.model_dump())

        # Generate Findings and Recommendations based on verified rules
        findings_out: List[SecurityFindingOut] = []
        recommendations: List[str] = []

        # Check Network
        if not network_res.reachable:
            f = SecurityFinding(
                assessment_id=assessment_record.id,
                section="Network Reconnaissance",
                title="Target Host Unreachable on Standard Ports",
                severity="HIGH" if "localhost" not in target else "INFO",
                status="WARNING",
                finding=f"Could not establish TCP handshake with target host '{target}' on probed ports.",
                recommendation="Verify target network connectivity, firewall rules, and listener daemon status."
            )
            db.add(f)
            findings_out.append(SecurityFindingOut.model_validate(f))
            recommendations.append("Ensure target listener services are active on designated network ports.")

        # Check Transport
        if not http_https_res.https_supported and "localhost" not in target.lower():
            f = SecurityFinding(
                assessment_id=assessment_record.id,
                section="HTTP/HTTPS Transport",
                title="Unencrypted HTTP Transport Detected",
                severity="HIGH",
                status="FAIL",
                finding="The target application does not enforce HTTPS for transport encryption.",
                recommendation="Deploy TLS certificates (e.g. Let's Encrypt / Enterprise CA) and enforce automatic HTTP to HTTPS redirection."
            )
            db.add(f)
            findings_out.append(SecurityFindingOut.model_validate(f))
            recommendations.append("Enforce TLS 1.3 and configure HTTP Strict Transport Security (HSTS).")
        elif "localhost" in target.lower():
            f = SecurityFinding(
                assessment_id=assessment_record.id,
                section="HTTP/HTTPS Transport",
                title="Local Development Plain HTTP Listener",
                severity="INFO",
                status="PASS",
                finding="Running in local loopback environment. HTTPS termination should be active in production.",
                recommendation="Ensure reverse proxy (Nginx / Cloudflare) provides TLS termination in staging/production."
            )
            db.add(f)
            findings_out.append(SecurityFindingOut.model_validate(f))

        # Check RBAC
        if access_res.overall_status != "PASS":
            f = SecurityFinding(
                assessment_id=assessment_record.id,
                section="Access Control",
                title="Access Control Evaluation Failures",
                severity="CRITICAL",
                status="FAIL",
                finding="One or more RBAC endpoint authorization test cases failed expected status codes.",
                recommendation="Audit route permissions and verify RequirePermission dependencies."
            )
            db.add(f)
            findings_out.append(SecurityFindingOut.model_validate(f))
            recommendations.append("Review backend RBAC role assignments and route guards.")
        else:
            recommendations.append("Maintain strict separation of privileges and periodic audit of role permissions.")

        # Check Hardening checklist
        if hardening_res.summary.get("FAIL", 0) > 0:
            recommendations.append("Remediate failed hardening checklist items across application and transport boundaries.")
        if hardening_res.summary.get("WARNING", 0) > 0:
            recommendations.append("Review warning items in defensive hardening matrix to maximize posture resilience.")

        # Default recommendations
        if not recommendations:
            recommendations = [
                "Maintain active MTD rotation and threat monitoring.",
                "Review audit logs daily for anomalous authentication attempts.",
                "Ensure periodic automated security assessment runs."
            ]

        # Calculate Summary Metrics
        total_checks = (
            len(network_res.services) +
            len(portal_res.redirect_chain) +
            3 +  # http/https
            5 +  # session
            len(access_res.test_cases) +
            len(seg_res.authorized_paths) +
            sum(len(c.items) for c in hardening_res.categories)
        )

        passed_checks = (
            sum(1 for s in network_res.services if s.status in ["observed", "PASS"]) +
            (1 if portal_res.status == "PASS" else 0) +
            (3 if http_https_res.status == "PASS" else (2 if http_https_res.status == "WARNING" else 1)) +
            5 + # session pass
            sum(1 for tc in access_res.test_cases if tc.result == "PASS") +
            sum(1 for p in seg_res.authorized_paths if p.status == "PASS") +
            hardening_res.summary.get("PASS", 0)
        )

        warning_checks = (
            (1 if network_res.status == "WARNING" else 0) +
            (1 if http_https_res.status == "WARNING" else 0) +
            hardening_res.summary.get("WARNING", 0)
        )

        failed_checks = (
            (1 if network_res.status == "FAIL" else 0) +
            (1 if http_https_res.status == "FAIL" else 0) +
            sum(1 for tc in access_res.test_cases if tc.result == "FAIL") +
            hardening_res.summary.get("FAIL", 0)
        )

        not_assessed_checks = max(0, total_checks - (passed_checks + warning_checks + failed_checks))

        completed_time = datetime.now(timezone.utc)

        summary_obj = SecurityAssessmentSummary(
            total_checks=total_checks,
            passed_checks=passed_checks,
            warning_checks=warning_checks,
            failed_checks=failed_checks,
            not_assessed_checks=not_assessed_checks,
            findings_count=len(findings_out),
            warnings_count=warning_checks,
            failed_count=failed_checks,
            assessment_status="Completed",
            target=target,
            timestamp=completed_time.isoformat(),
            recommendations=recommendations
        )

        # Update assessment record
        assessment_record.status = "completed"
        assessment_record.completed_at = completed_time
        assessment_record.summary_json = json.dumps(summary_obj.model_dump())
        db.commit()

        # Audit Assessment Completed
        audit_service.log_action(
            db=db,
            user_id=user.id if user else None,
            action="SECURITY_ASSESSMENT_COMPLETED",
            resource=f"assessment:target:{target}",
            result="COMPLETED",
            metadata={
                "assessment_id": assessment_record.id,
                "target": target,
                "passed_checks": passed_checks,
                "warning_checks": warning_checks,
                "failed_checks": failed_checks,
                "findings": len(findings_out),
                "timestamp": completed_time.isoformat()
            }
        )

        return SecurityAssessmentFullResponse(
            id=assessment_record.id,
            target=target,
            status="completed",
            started_at=start_time,
            completed_at=completed_time,
            summary=summary_obj,
            network=network_res,
            portal=portal_res,
            http_https=http_https_res,
            session=session_res,
            access_control=access_res,
            segmentation=seg_res,
            hardening=hardening_res,
            findings=findings_out
        )

    def get_latest_assessment(self, db: Session) -> Optional[SecurityAssessmentFullResponse]:
        record = db.query(SecurityAssessment).order_by(SecurityAssessment.id.desc()).first()
        if not record:
            return None
        return self._format_assessment_record(db, record)

    def get_assessment_by_id(self, db: Session, assessment_id: int) -> Optional[SecurityAssessmentFullResponse]:
        record = db.query(SecurityAssessment).filter(SecurityAssessment.id == assessment_id).first()
        if not record:
            return None
        return self._format_assessment_record(db, record)

    def list_assessment_history(self, db: Session, limit: int = 10) -> List[SecurityAssessmentListItem]:
        records = db.query(SecurityAssessment).order_by(SecurityAssessment.id.desc()).limit(limit).all()
        result: List[SecurityAssessmentListItem] = []
        for r in records:
            summary = {}
            if r.summary_json:
                try:
                    summary = json.loads(r.summary_json)
                except Exception:
                    pass
            result.append(
                SecurityAssessmentListItem(
                    id=r.id,
                    target=r.target,
                    status=r.status,
                    started_at=r.started_at,
                    completed_at=r.completed_at,
                    passed_count=summary.get("passed_checks", 0),
                    warning_count=summary.get("warning_checks", 0),
                    failed_count=summary.get("failed_checks", 0),
                    findings_count=summary.get("findings_count", 0)
                )
            )
        return result

    def _save_result(self, db: Session, assessment_id: int, section: str, status: str, details: Dict[str, Any]):
        res = AssessmentResult(
            assessment_id=assessment_id,
            section=section,
            status=status,
            details_json=json.dumps(details)
        )
        db.add(res)
        db.commit()

    def _format_assessment_record(self, db: Session, record: SecurityAssessment) -> SecurityAssessmentFullResponse:
        summary_dict = json.loads(record.summary_json) if record.summary_json else {}
        summary = SecurityAssessmentSummary(
            total_checks=summary_dict.get("total_checks", 0),
            passed_checks=summary_dict.get("passed_checks", 0),
            warning_checks=summary_dict.get("warning_checks", 0),
            failed_checks=summary_dict.get("failed_checks", 0),
            not_assessed_checks=summary_dict.get("not_assessed_checks", 0),
            findings_count=summary_dict.get("findings_count", 0),
            warnings_count=summary_dict.get("warnings_count", 0),
            failed_count=summary_dict.get("failed_count", 0),
            assessment_status=summary_dict.get("assessment_status", "Completed"),
            target=record.target,
            timestamp=record.completed_at.isoformat() if record.completed_at else record.started_at.isoformat(),
            recommendations=summary_dict.get("recommendations", [])
        )

        # Load section results
        results = db.query(AssessmentResult).filter(AssessmentResult.assessment_id == record.id).all()
        res_map = {r.section: json.loads(r.details_json) for r in results if r.details_json}

        from app.schemas.security_assessment import (
            NetworkReconResult,
            PortalAnalysisResult,
            HttpHttpsAnalysisResult,
            SessionAnalysisResult,
            AccessControlResult,
            SegmentationResult,
            HardeningResult,
        )

        network_res = NetworkReconResult(**res_map["network"]) if "network" in res_map else network_assessment_service.assess_network(record.target)
        portal_res = PortalAnalysisResult(**res_map["portal"]) if "portal" in res_map else portal_analysis_service.analyze_portal(record.target)
        http_https_res = HttpHttpsAnalysisResult(**res_map["http_https"]) if "http_https" in res_map else session_analysis_service.analyze_http_https(record.target)
        session_res = SessionAnalysisResult(**res_map["session"]) if "session" in res_map else session_analysis_service.analyze_session(record.target)
        access_res = AccessControlResult(**res_map["access_control"]) if "access_control" in res_map else access_control_service.evaluate_access_controls(db, record.target)
        seg_res = SegmentationResult(**res_map["segmentation"]) if "segmentation" in res_map else segmentation_service.assess_segmentation(record.target)
        hardening_res = HardeningResult(**res_map["hardening"]) if "hardening" in res_map else hardening_service.evaluate_hardening(db, record.target)

        findings = db.query(SecurityFinding).filter(SecurityFinding.assessment_id == record.id).all()
        findings_out = [SecurityFindingOut.model_validate(f) for f in findings]

        return SecurityAssessmentFullResponse(
            id=record.id,
            target=record.target,
            status=record.status,
            started_at=record.started_at,
            completed_at=record.completed_at,
            summary=summary,
            network=network_res,
            portal=portal_res,
            http_https=http_https_res,
            session=session_res,
            access_control=access_res,
            segmentation=seg_res,
            hardening=hardening_res,
            findings=findings_out
        )


assessment_report_service = AssessmentReportService()
