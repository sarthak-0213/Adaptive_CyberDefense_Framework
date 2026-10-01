from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SecurityAssessmentRunRequest(BaseModel):
    target: str = Field(..., description="Authorized target host, IP, or URL")
    authorized: bool = Field(True, description="Explicit authorization confirmation")
    test_endpoints: Optional[List[str]] = Field(None, description="Custom authorized endpoints to assess")
    client_nodes: Optional[List[str]] = Field(None, description="Configured network nodes for segmentation analysis")


class NetworkServiceObservation(BaseModel):
    port: int
    protocol: str = "TCP"
    service: str
    status: str = "observed"  # observed, filtered, closed, not_assessed
    timestamp: str


class NetworkReconResult(BaseModel):
    target: str
    reachable: bool
    host_info: Dict[str, Any]
    interfaces: List[Dict[str, Any]] = []
    dns: Dict[str, Any]
    dhcp: Dict[str, Any]
    services: List[NetworkServiceObservation] = []
    timestamp: str
    status: str = "PASS"  # PASS, WARNING, FAIL, NOT_ASSESSED


class RedirectStep(BaseModel):
    step: int
    url: str
    status_code: int
    label: str


class PortalAnalysisResult(BaseModel):
    target: str
    http_status: Optional[int] = None
    https_available: bool = False
    redirect_chain: List[RedirectStep] = []
    login_url: Optional[str] = None
    auth_endpoint: Optional[str] = None
    redirect_after_auth: Optional[str] = None
    logout_behavior: Optional[str] = None
    status: str = "PASS"  # PASS, WARNING, FAIL, NOT_ASSESSED
    timestamp: str


class HttpHttpsAnalysisResult(BaseModel):
    target: str
    https_supported: bool
    https_status: str  # SECURE / WARNING / FAIL
    redirect_status: str  # PASS / FAIL / NOT_ASSESSED
    login_transport: str  # SECURE / WARNING / FAIL / NOT_ASSESSED
    hsts_enabled: bool = False
    explanation: str = "HTTPS protects credentials and session traffic from being transmitted as readable HTTP traffic."
    status: str = "PASS"  # PASS, WARNING, FAIL
    timestamp: str


class SessionAnalysisResult(BaseModel):
    auth_mechanism: str  # "JWT" or "Cookie Session"
    expiration_configured: str  # "Configured" / "Not configured"
    logout_invalidation: str  # "PASS" / "FAIL" / "NOT_ASSESSED"
    cookie_secure: str  # "PASS" / "WARNING" / "FAIL" / "N/A"
    cookie_httponly: str  # "PASS" / "WARNING" / "FAIL" / "N/A"
    cookie_samesite: str  # "PASS" / "WARNING" / "FAIL" / "N/A"
    refresh_behavior: str = "Single-use refresh token with rotation & reuse detection"
    status: str = "PASS"
    timestamp: str


class AccessControlCase(BaseModel):
    endpoint: str
    test_role: str  # "UNAUTHENTICATED", "USER", "ADMIN"
    expected: int
    actual: int
    result: str  # "PASS" / "FAIL"
    details: Optional[str] = None


class AccessControlResult(BaseModel):
    test_cases: List[AccessControlCase] = []
    overall_status: str = "PASS"
    timestamp: str


class SegmentationPath(BaseModel):
    source: str
    destination: str
    protocol: str = "TCP"
    port: Optional[int] = None
    allowed: bool
    status: str = "PASS"  # PASS / WARNING / NOT_ASSESSED
    assessed: bool = True
    notes: Optional[str] = None


class SegmentationResult(BaseModel):
    client_isolation: str = "PASS"  # PASS / WARNING / NOT_ASSESSED
    authorized_paths: List[SegmentationPath] = []
    timestamp: str
    status: str = "PASS"


class HardeningItem(BaseModel):
    id: str
    category: str
    name: str
    description: str
    status: str  # PASS, WARNING, FAIL, NOT_ASSESSED
    details: str


class HardeningCategory(BaseModel):
    category: str
    items: List[HardeningItem]
    pass_count: int = 0
    warning_count: int = 0
    fail_count: int = 0
    not_assessed_count: int = 0


class HardeningResult(BaseModel):
    categories: List[HardeningCategory] = []
    summary: Dict[str, int] = {}
    status: str = "PASS"
    timestamp: str


class SecurityFindingOut(BaseModel):
    id: Optional[int] = None
    section: str
    title: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    status: str  # PASS, WARNING, FAIL, NOT_ASSESSED
    finding: str
    recommendation: str

    class Config:
        from_attributes = True


class SecurityAssessmentSummary(BaseModel):
    total_checks: int
    passed_checks: int
    warning_checks: int
    failed_checks: int
    not_assessed_checks: int
    findings_count: int
    warnings_count: int
    failed_count: int
    assessment_status: str  # Completed / In Progress / Failed
    target: str
    timestamp: str
    recommendations: List[str] = []


class SecurityAssessmentFullResponse(BaseModel):
    id: int
    target: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    summary: SecurityAssessmentSummary
    network: NetworkReconResult
    portal: PortalAnalysisResult
    http_https: HttpHttpsAnalysisResult
    session: SessionAnalysisResult
    access_control: AccessControlResult
    segmentation: SegmentationResult
    hardening: HardeningResult
    findings: List[SecurityFindingOut] = []


class SecurityAssessmentListItem(BaseModel):
    id: int
    target: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    passed_count: int = 0
    warning_count: int = 0
    failed_count: int = 0
    findings_count: int = 0
