export type AlertSeverity = "critical" | "high" | "medium" | "low";
export type AlertStatus = "active" | "investigating" | "resolved";

export interface Alert {
  id: string;
  title: string;
  timestamp: string;
  rawTimestamp: number;
  severity: AlertSeverity;
  status: AlertStatus;
  description: string;
}

export interface SystemHealthSummary {
  overallScore: number;
  cpuUsage: number;
  memoryUsage: number;
  bandwidthMbps: number;
  storageUsage: number;
  mtdStatus: "Active" | "Optimizing" | "Standby";
  mtdRotations24h: number;
  lastMtdRotation: string;
  uptime: string;
  status: "Healthy" | "Degraded" | "Critical";
}

export interface ActivityItem {
  id: string;
  timestamp: string;
  title: string;
  category: "security" | "system" | "user";
  severity: "info" | "warning" | "critical";
  details: string;
}

export interface QuickActionItem {
  id: string;
  label: string;
  description: string;
  iconName: string;
  variant: "primary" | "warning" | "danger" | "secondary";
}

export interface SecurityOverview {
  threatLevel: "LOW" | "ELEVATED" | "HIGH" | "CRITICAL";
  securityScore: number; // 0 - 100
  systemHealthScore: number; // 0 - 100
  mtdStatus: string;
  mtdRotationsCount: number;
  lastRotationTime: string;
  threatSummary: {
    vector: string;
    blockedCount: number;
    riskLevel: "Low" | "Medium" | "High";
  }[];
}

export interface ReportItem {
  id: string;
  title: string;
  type: "Security Audit" | "Incident Log" | "MTD Analytics";
  generatedAt: string;
  size: string;
  format: "PDF" | "CSV" | "JSON";
  description: string;
}

export interface UserSettingsData {
  profile: {
    name: string;
    email: string;
    role: string;
    department: string;
    phone: string;
  };
  appearance: {
    theme: "Dark" | "Cyberpunk" | "High Contrast";
    compactView: boolean;
    autoRefresh: boolean;
    refreshIntervalSec: number;
  };
  notifications: {
    emailAlerts: boolean;
    pushAlerts: boolean;
    smsAlerts: boolean;
    criticalOnly: boolean;
  };
  api: {
    apiKey: string;
    endpoint: string;
    rateLimit: string;
  };
  app: {
    version: string;
    build: string;
    environment: string;
    uptime: string;
  };
}
