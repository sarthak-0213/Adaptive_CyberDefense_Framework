/**
 * @deprecated TEMPORARY MOCK DATA
 * 
 * NOTE: The application has been converted to real backend integration.
 * The variables below represent legacy fallback mock objects for components
 * whose backend endpoints (e.g. video streams, alerts) are still pending deployment.
 * 
 * Do NOT use these mock values to present fake real-time telemetry.
 */

import type {
  Alert,
  SystemHealthSummary,
  ActivityItem,
  QuickActionItem,
  SecurityOverview,
  ReportItem,
  UserSettingsData,
} from "../types/dashboard";

/** @deprecated Temporary Mock Data Fallback */
export const MOCK_ALERTS: Alert[] = [];

/** @deprecated Temporary Mock Data Fallback */
export const MOCK_SYSTEM_HEALTH: SystemHealthSummary = {
  overallScore: 0,
  cpuUsage: 0,
  memoryUsage: 0,
  bandwidthMbps: 0,
  storageUsage: 0,
  mtdStatus: "Standby",
  mtdRotations24h: 0,
  lastMtdRotation: "N/A",
  uptime: "N/A",
  status: "Healthy",
};

/** @deprecated Temporary Mock Data Fallback */
export const MOCK_ACTIVITIES: ActivityItem[] = [];

/** @deprecated Temporary Mock Data Fallback */
export const MOCK_QUICK_ACTIONS: QuickActionItem[] = [];

/** @deprecated Temporary Mock Data Fallback */
export const MOCK_SECURITY_OVERVIEW: SecurityOverview = {
  threatLevel: "LOW",
  securityScore: 0,
  systemHealthScore: 0,
  mtdStatus: "Standby",
  mtdRotationsCount: 0,
  lastRotationTime: "N/A",
  threatSummary: [],
};

/** @deprecated Temporary Mock Data Fallback */
export const MOCK_REPORTS: ReportItem[] = [];

/** @deprecated Temporary Mock Data Fallback */
export const MOCK_USER_SETTINGS: UserSettingsData = {
  profile: {
    name: "",
    email: "",
    role: "",
    department: "",
    phone: "",
  },
  appearance: {
    theme: "Dark",
    compactView: false,
    autoRefresh: false,
    refreshIntervalSec: 5,
  },
  notifications: {
    emailAlerts: false,
    pushAlerts: false,
    smsAlerts: false,
    criticalOnly: false,
  },
  api: {
    apiKey: "",
    endpoint: "",
    rateLimit: "",
  },
  app: {
    version: "v1.0.0",
    build: "production",
    environment: "Production",
    uptime: "N/A",
  },
};
