import api from "./client";

export interface SecurityAssessmentRunRequest {
  target: string;
  authorized: boolean;
  test_endpoints?: string[];
  client_nodes?: string[];
}

export interface NetworkServiceObservation {
  port: number;
  protocol: string;
  service: string;
  status: string;
  timestamp: string;
}

export interface NetworkReconResult {
  target: string;
  reachable: boolean;
  host_info: Record<string, any>;
  interfaces: Array<Record<string, any>>;
  dns: Record<string, any>;
  dhcp: Record<string, any>;
  services: NetworkServiceObservation[];
  timestamp: string;
  status: string;
}

export interface RedirectStep {
  step: number;
  url: string;
  status_code: number;
  label: string;
}

export interface PortalAnalysisResult {
  target: string;
  http_status?: number;
  https_available: boolean;
  redirect_chain: RedirectStep[];
  login_url?: string;
  auth_endpoint?: string;
  redirect_after_auth?: string;
  logout_behavior?: string;
  status: string;
  timestamp: string;
}

export interface HttpHttpsAnalysisResult {
  target: string;
  https_supported: boolean;
  https_status: string;
  redirect_status: string;
  login_transport: string;
  hsts_enabled: boolean;
  explanation: string;
  status: string;
  timestamp: string;
}

export interface SessionAnalysisResult {
  auth_mechanism: string;
  expiration_configured: string;
  logout_invalidation: string;
  cookie_secure: string;
  cookie_httponly: string;
  cookie_samesite: string;
  refresh_behavior: string;
  status: string;
  timestamp: string;
}

export interface AccessControlCase {
  endpoint: string;
  test_role: string;
  expected: number;
  actual: number;
  result: string;
  details?: string;
}

export interface AccessControlResult {
  test_cases: AccessControlCase[];
  overall_status: string;
  timestamp: string;
}

export interface SegmentationPath {
  source: string;
  destination: string;
  protocol: string;
  port?: number;
  allowed: boolean;
  status: string;
  assessed: boolean;
  notes?: string;
}

export interface SegmentationResult {
  client_isolation: string;
  authorized_paths: SegmentationPath[];
  timestamp: string;
  status: string;
}

export interface HardeningItem {
  id: string;
  category: string;
  name: string;
  description: string;
  status: string;
  details: string;
}

export interface HardeningCategory {
  category: string;
  items: HardeningItem[];
  pass_count: number;
  warning_count: number;
  fail_count: number;
  not_assessed_count: number;
}

export interface HardeningResult {
  categories: HardeningCategory[];
  summary: Record<string, number>;
  status: string;
  timestamp: string;
}

export interface SecurityFindingOut {
  id?: number;
  section: string;
  title: string;
  severity: string;
  status: string;
  finding: string;
  recommendation: string;
}

export interface SecurityAssessmentSummary {
  total_checks: number;
  passed_checks: number;
  warning_checks: number;
  failed_checks: number;
  not_assessed_checks: number;
  findings_count: number;
  warnings_count: number;
  failed_count: number;
  assessment_status: string;
  target: string;
  timestamp: string;
  recommendations: string[];
}

export interface SecurityAssessmentFullResponse {
  id: number;
  target: string;
  status: string;
  started_at: string;
  completed_at?: string;
  summary: SecurityAssessmentSummary;
  network: NetworkReconResult;
  portal: PortalAnalysisResult;
  http_https: HttpHttpsAnalysisResult;
  session: SessionAnalysisResult;
  access_control: AccessControlResult;
  segmentation: SegmentationResult;
  hardening: HardeningResult;
  findings: SecurityFindingOut[];
}

export interface SecurityAssessmentListItem {
  id: number;
  target: string;
  status: string;
  started_at: string;
  completed_at?: string;
  passed_count: number;
  warning_count: number;
  failed_count: number;
  findings_count: number;
}

export const runSecurityAssessment = async (
  data: SecurityAssessmentRunRequest
): Promise<SecurityAssessmentFullResponse> => {
  const response = await api.post("/api/v1/security-assessment/run", data);
  return response.data;
};

export const getLatestAssessment = async (): Promise<SecurityAssessmentFullResponse> => {
  const response = await api.get("/api/v1/security-assessment/latest");
  return response.data;
};

export const getAssessmentHistory = async (
  limit = 10
): Promise<SecurityAssessmentListItem[]> => {
  const response = await api.get("/api/v1/security-assessment/history", {
    params: { limit },
  });
  return response.data;
};

export const getNetworkRecon = async (
  target = "localhost:8000"
): Promise<NetworkReconResult> => {
  const response = await api.get("/api/v1/security-assessment/network", {
    params: { target },
  });
  return response.data;
};

export const getPortalAnalysis = async (
  target = "localhost:8000"
): Promise<PortalAnalysisResult> => {
  const response = await api.get("/api/v1/security-assessment/portal", {
    params: { target },
  });
  return response.data;
};

export const getHttpHttpsAnalysis = async (
  target = "localhost:8000"
): Promise<HttpHttpsAnalysisResult> => {
  const response = await api.get("/api/v1/security-assessment/http-https", {
    params: { target },
  });
  return response.data;
};

export const getSessionAnalysis = async (
  target = "localhost:8000"
): Promise<SessionAnalysisResult> => {
  const response = await api.get("/api/v1/security-assessment/session", {
    params: { target },
  });
  return response.data;
};

export const getAccessControlAnalysis = async (
  target = "localhost:8000"
): Promise<AccessControlResult> => {
  const response = await api.get("/api/v1/security-assessment/access-control", {
    params: { target },
  });
  return response.data;
};

export const getSegmentationAnalysis = async (
  target = "localhost:8000"
): Promise<SegmentationResult> => {
  const response = await api.get("/api/v1/security-assessment/segmentation", {
    params: { target },
  });
  return response.data;
};

export const getHardeningAnalysis = async (
  target = "localhost:8000"
): Promise<HardeningResult> => {
  const response = await api.get("/api/v1/security-assessment/hardening", {
    params: { target },
  });
  return response.data;
};

export const getAssessmentById = async (
  id: number
): Promise<SecurityAssessmentFullResponse> => {
  const response = await api.get(`/api/v1/security-assessment/${id}`);
  return response.data;
};
