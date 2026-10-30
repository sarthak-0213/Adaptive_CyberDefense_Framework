import api from "./client";

export interface ReportSummary {
  total_events: number;
  honeypot_hits_24h: number;
  blocked_ips_count: number;
  active_alerts_count: number;
  mtd_rotations_count: number;
  total_audit_logs: number;
  last_generated?: string;
}

export interface ReportItem {
  id: string;
  title: string;
  type: string;
  generatedAt: string;
  size: string;
  format: string;
  description: string;
  download_url?: string;
}

export interface ReportGenerateRequest {
  report_type: string;
  format?: string;
  date_range?: string;
}

export interface ReportGenerateResponse {
  id: string;
  title: string;
  type: string;
  generatedAt: string;
  size: string;
  format: string;
  description: string;
  summary: Record<string, any>;
  data: Array<Record<string, any>>;
}

export interface AuditLogOut {
  id: number;
  user_email: string;
  action: string;
  resource: string;
  details?: string;
  ip_address?: string;
  timestamp: string;
}

export const getReports = async (): Promise<ReportItem[]> => {
  const response = await api.get("/api/v1/reports");
  return response.data;
};

export const getReportSummary = async (): Promise<ReportSummary> => {
  const response = await api.get("/api/v1/reports/summary");
  return response.data;
};

export const generateReport = async (
  request: ReportGenerateRequest
): Promise<ReportGenerateResponse> => {
  const response = await api.post("/api/v1/reports/generate", request);
  return response.data;
};

export const getAuditLogs = async (): Promise<AuditLogOut[]> => {
  const response = await api.get("/api/v1/reports/audit-logs");
  return response.data;
};
