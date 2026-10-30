import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.models.user import User
from app.utils.deps import get_db, get_current_user, RequirePermission
from app.schemas.security_assessment import (
    SecurityAssessmentRunRequest,
    SecurityAssessmentFullResponse,
    SecurityAssessmentSummary,
    SecurityAssessmentListItem,
    NetworkReconResult,
    PortalAnalysisResult,
    HttpHttpsAnalysisResult,
    SessionAnalysisResult,
    AccessControlResult,
    SegmentationResult,
    HardeningResult,
)
from app.services.network_assessment_service import network_assessment_service
from app.services.portal_analysis_service import portal_analysis_service
from app.services.session_analysis_service import session_analysis_service
from app.services.access_control_service import access_control_service
from app.services.segmentation_service import segmentation_service
from app.services.hardening_service import hardening_service
from app.services.assessment_report_service import assessment_report_service

logger = logging.getLogger("security_assessment")

router = APIRouter(prefix="/security-assessment", tags=["Security Assessment"])

# Require security_assessment permission (granted to admin and analyst)
require_assessment_permission = RequirePermission("security_assessment")


def get_client_ip(request: Request) -> str:
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/run", response_model=SecurityAssessmentFullResponse)
def run_assessment(
    req_body: SecurityAssessmentRunRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_assessment_permission)
):
    """
    Execute an authorized defensive security assessment against a configured target.
    Requires 'security_assessment' permission.
    """
    if not req_body.authorized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Assessment must be explicitly confirmed as authorized."
        )
    
    client_ip = get_client_ip(request)
    return assessment_report_service.run_full_assessment(
        db=db,
        user=current_user,
        request=req_body,
        client_ip=client_ip
    )


@router.get("/latest", response_model=Optional[SecurityAssessmentFullResponse])
def get_latest_assessment(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve the most recent security assessment results.
    Requires authenticated user.
    """
    latest = assessment_report_service.get_latest_assessment(db)
    if not latest:
        # If no assessment run yet, generate a baseline against localhost
        return assessment_report_service.run_full_assessment(
            db=db,
            user=current_user,
            request=SecurityAssessmentRunRequest(target="localhost:8000", authorized=True),
            client_ip="127.0.0.1"
        )
    return latest


@router.get("/history", response_model=List[SecurityAssessmentListItem])
def get_assessment_history(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve history of previous security assessments.
    """
    return assessment_report_service.list_assessment_history(db, limit=limit)


@router.get("/network", response_model=NetworkReconResult)
def get_network_recon(
    target: str = Query("localhost:8000", description="Authorized target host or URL"),
    current_user: User = Depends(get_current_user)
):
    """
    Execute or retrieve safe defensive network reconnaissance for authorized target.
    """
    return network_assessment_service.assess_network(target)


@router.get("/portal", response_model=PortalAnalysisResult)
def get_portal_analysis(
    target: str = Query("localhost:8000", description="Authorized portal host or URL"),
    current_user: User = Depends(get_current_user)
):
    """
    Execute or retrieve web portal and redirect flow analysis.
    """
    return portal_analysis_service.analyze_portal(target)


@router.get("/http-https", response_model=HttpHttpsAnalysisResult)
def get_http_https_analysis(
    target: str = Query("localhost:8000", description="Authorized target host or URL"),
    current_user: User = Depends(get_current_user)
):
    """
    Evaluate HTTP vs HTTPS transport encryption security.
    """
    return session_analysis_service.analyze_http_https(target)


@router.get("/session", response_model=SessionAnalysisResult)
def get_session_analysis(
    target: str = Query("localhost:8000", description="Authorized target host or URL"),
    current_user: User = Depends(get_current_user)
):
    """
    Evaluate session token mechanics and cookie security flags.
    """
    return session_analysis_service.analyze_session(target)


@router.get("/access-control", response_model=AccessControlResult)
def get_access_control_analysis(
    target: str = Query("localhost:8000", description="Authorized target host or URL"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Evaluate live RBAC test cases and endpoint authorization barriers.
    """
    return access_control_service.evaluate_access_controls(db, target=target)


@router.get("/segmentation", response_model=SegmentationResult)
def get_segmentation_analysis(
    target: str = Query("localhost:8000", description="Authorized target host or URL"),
    current_user: User = Depends(get_current_user)
):
    """
    Evaluate defensive network segmentation and client isolation status.
    """
    return segmentation_service.assess_segmentation(target)


@router.get("/hardening", response_model=HardeningResult)
def get_hardening_analysis(
    target: str = Query("localhost:8000", description="Authorized target host or URL"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Evaluate defensive hardening checklist across 5 security pillars.
    """
    return hardening_service.evaluate_hardening(db, target)


@router.get("/{assessment_id}", response_model=SecurityAssessmentFullResponse)
def get_assessment_by_id(
    assessment_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve specific historical security assessment details.
    """
    res = assessment_report_service.get_assessment_by_id(db, assessment_id)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment not found"
        )
    return res
