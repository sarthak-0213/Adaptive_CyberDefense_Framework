import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Shield,
  RefreshCw,
  ShieldAlert,
  ShieldBan,
  ShieldCheck,
  AlertTriangle,
  ArrowUpRight,
  ArrowRight,
  WifiOff,
  Activity,
  CheckCircle2,
  Globe,
} from "lucide-react";

import StatCard from "../components/dashboard/StatCard";
import DashboardHeader from "../components/dashboard/DashboardHeader";
import RecentAlerts from "../components/dashboard/RecentAlerts";
import { AnimatedCard } from "../components/AnimatedCard";
import { getMTDStatus, type MTDStatusResponse } from "../api/mtd";
import {
  getSecurityMetrics,
  getThreats,
  getBlocks,
  type SecurityMetrics,
  type ThreatScore,
  type ThreatBlock,
  type GatewayLog,
} from "../api/securityAnalytics";
import { getAlerts } from "../api/alerts";
import { getLatestAssessment, type SecurityAssessmentFullResponse } from "../api/securityAssessment";
import type { Alert } from "../types/dashboard";

export default function Dashboard() {
  const [mtdStatus, setMtdStatus] = useState<MTDStatusResponse | null>(null);
  const [metrics, setMetrics] = useState<SecurityMetrics | null>(null);
  const [threats, setThreats] = useState<ThreatScore[]>([]);
  const [blocks, setBlocks] = useState<ThreatBlock[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [assessment, setAssessment] = useState<SecurityAssessmentFullResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const apiBaseUrl = import.meta.env.VITE_API_URL || "(Relative / same-origin)";

  const fetchDashboardData = async () => {
    try {
      setError(null);
      const [statusData, metricsData, threatsData, blocksData, alertData, assessmentData] = await Promise.all([
        getMTDStatus().catch(() => null),
        getSecurityMetrics().catch(() => null),
        getThreats().catch(() => []),
        getBlocks().catch(() => []),
        getAlerts().catch(() => []),
        getLatestAssessment().catch(() => null),
      ]);

      if (!statusData && !metricsData) {
        setError(`Unable to connect to backend API at ${apiBaseUrl}`);
      } else {
        setMtdStatus(statusData);
        setMetrics(metricsData);
        setThreats(threatsData || []);
        setBlocks(blocksData || []);
        setAlerts(alertData || []);
        setAssessment(assessmentData);
      }
    } catch (err: any) {
      console.error("Dashboard fetch error:", err);
      setError(`Backend connection error: ${err.message || "Failed to reach server"}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 4000);
    return () => clearInterval(interval);
  }, []);

  const getThreatBadge = (level?: string) => {
    switch (level?.toUpperCase()) {
      case "CRITICAL":
        return "bg-rose-50 text-rose-700 border-rose-200";
      case "HIGH":
        return "bg-amber-50 text-amber-700 border-amber-200";
      case "MEDIUM":
        return "bg-yellow-50 text-yellow-700 border-yellow-200";
      default:
        return "bg-emerald-50 text-emerald-700 border-emerald-200";
    }
  };

  const getLogBadge = (classification: string, status: number) => {
    if (status === 403 || classification === "blocked") {
      return "bg-rose-100 text-rose-800 border-rose-200";
    }
    if (status === 400 || classification === "suspicious") {
      return "bg-amber-100 text-amber-800 border-amber-200";
    }
    if (status === 404 && classification === "honeypot") {
      return "bg-indigo-100 text-indigo-800 border-indigo-200";
    }
    return "bg-emerald-100 text-emerald-800 border-emerald-200";
  };

  return (
    <div className="space-y-6">
      <DashboardHeader />

      {/* Honest Backend Error / Disconnected Banner */}
      {error && (
        <div className="flex items-center justify-between rounded-xl border border-rose-200 bg-rose-50 p-4 text-xs text-rose-800">
          <div className="flex items-center gap-3">
            <WifiOff className="h-5 w-5 text-rose-600 shrink-0" />
            <div>
              <p className="font-semibold">Backend Gateway Disconnected</p>
              <p className="text-[11px] text-rose-600 mt-0.5">{error}</p>
            </div>
          </div>
          <button
            onClick={fetchDashboardData}
            className="rounded-lg bg-rose-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-rose-700 transition"
          >
            Retry Connection
          </button>
        </div>
      )}

      {/* Top 4 Primary Live KPI Cards (Driven by Actual Gateway Telemetry) */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* 1. Gateway Traffic Volume */}
        <StatCard
          delay={0}
          title="SecureShop Gateway Requests"
          value={loading ? "..." : (metrics?.total_gateway_requests ?? 0)}
          subtitle={
            metrics
              ? `${metrics.successful_requests} ok · ${metrics.failed_requests} rejected`
              : "Waiting for telemetry..."
          }
          trend={metrics && metrics.total_gateway_requests > 0 ? "Live Gateway Active" : "Standby"}
          trendPositive={true}
          icon={<Globe className="h-5 w-5 text-blue-600" />}
        />

        {/* 2. Detected Threat Events */}
        <StatCard
          delay={0.08}
          title="Threat Events Correlated"
          value={loading ? "..." : (metrics?.threat_events_recorded ?? 0)}
          subtitle={
            metrics?.suspicious_requests
              ? `${metrics.suspicious_requests} suspicious payload flags`
              : "No active anomalous traffic"
          }
          trend={
            metrics && metrics.threat_events_recorded > 0
              ? `${metrics.critical_threats} Critical`
              : "Zero Threats"
          }
          trendPositive={metrics ? metrics.critical_threats === 0 : true}
          icon={<ShieldAlert className="h-5 w-5 text-amber-600" />}
        />

        {/* 3. Perimeter Blocks */}
        <StatCard
          delay={0.16}
          title="Autonomous Perimeter Blocks"
          value={loading ? "..." : (metrics?.active_blocks ?? blocks.filter(b => b.status === "blocked").length)}
          subtitle="Enforced by dynamic firewall"
          trend={
            (metrics?.active_blocks ?? 0) > 0 ? "Threat Contained" : "Perimeter Clear"
          }
          trendPositive={true}
          icon={<ShieldBan className="h-5 w-5 text-rose-600" />}
        />

        {/* 4. Moving Target Defense (MTD) Status */}
        <StatCard
          delay={0.24}
          title="MTD Shuffled Routes"
          value={loading ? "..." : (mtdStatus ? Object.keys(mtdStatus.active_routes).length : 0)}
          subtitle={mtdStatus?.mtd_enabled ? `${metrics?.mtd_rotations_count ?? 0} rotations executed` : "MTD Inactive"}
          trend={mtdStatus?.mtd_enabled ? "Polymorphic Active" : "Standby"}
          trendPositive={!!mtdStatus?.mtd_enabled}
          icon={<RefreshCw className="h-5 w-5 text-emerald-600" />}
        />
      </div>

      {/* Real Secondary Telemetry Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 rounded-xl border border-slate-200 bg-white p-4 shadow-sm text-xs">
        <div>
          <span className="text-slate-500 block text-[11px] font-medium">System Risk Level</span>
          <span className={`inline-block mt-1 font-bold px-2 py-0.5 rounded border text-[10px] ${getThreatBadge(metrics?.current_system_risk_level)}`}>
            {metrics?.current_system_risk_level || "LOW"}
          </span>
        </div>
        <div>
          <span className="text-slate-500 block text-[11px] font-medium">Peak Risk Score</span>
          <span className="font-mono font-bold text-slate-800 text-sm mt-0.5 block">
            {metrics?.current_highest_risk_score ? metrics.current_highest_risk_score.toFixed(1) : "0.0"}
          </span>
        </div>
        <div>
          <span className="text-slate-500 block text-[11px] font-medium">Avg Threat Score</span>
          <span className="font-mono font-bold text-slate-800 text-sm mt-0.5 block">
            {metrics?.average_threat_score ? metrics.average_threat_score.toFixed(1) : "0.0"}
          </span>
        </div>
        <div>
          <span className="text-slate-500 block text-[11px] font-medium">Honeypot Decoy Hits</span>
          <span className="font-mono font-bold text-indigo-600 text-sm mt-0.5 block">
            {metrics?.honeypot_hits_24h ?? 0}
          </span>
        </div>
        <div>
          <span className="text-slate-500 block text-[11px] font-medium">Avg Gateway Latency</span>
          <span className="font-mono font-bold text-emerald-600 text-sm mt-0.5 block">
            {metrics?.avg_gateway_latency_ms ? `${metrics.avg_gateway_latency_ms} ms` : "0.0 ms"}
          </span>
        </div>
      </div>

      {/* Security Assessment Integration Card */}
      <div className="w-full">
        <AnimatedCard delay={0.15}>
          <div className="rounded-xl border border-[var(--border)] bg-white p-6 shadow-sm text-[var(--text-primary)]">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[var(--border)] gap-3">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-50 text-[var(--accent-blue)] border border-blue-100">
                  <ShieldCheck className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="text-base font-semibold text-[var(--text-primary)]">
                    SECURITY ASSESSMENT
                  </h3>
                  <p className="text-xs text-[var(--text-secondary)] mt-0.5">
                    Defensive security posture & compliance evaluation for authorized target
                  </p>
                </div>
              </div>

              <Link
                to="/security-assessment"
                className="inline-flex items-center gap-2 rounded-lg bg-[var(--accent-blue)] px-4 py-2 text-xs font-semibold text-white shadow-xs hover:bg-[var(--accent-blue-hover)] transition-colors self-start sm:self-auto"
              >
                <span>View Assessment</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mt-5">
              <div className="p-3 bg-slate-50 rounded-lg border border-[var(--border)]">
                <span className="text-xs font-medium text-[var(--text-secondary)]">Last Assessment:</span>
                <p className="text-xs font-mono font-semibold text-[var(--text-primary)] mt-1 truncate">
                  {assessment?.completed_at ? new Date(assessment.completed_at).toLocaleString() : "Not Assessed"}
                </p>
              </div>

              <div className="p-3 bg-slate-50 rounded-lg border border-[var(--border)]">
                <span className="text-xs font-medium text-[var(--text-secondary)]">Status:</span>
                <p className="text-xs font-semibold text-emerald-700 mt-1">
                  {assessment ? "Completed" : "Not Assessed"}
                </p>
              </div>

              <div className="p-3 bg-slate-50 rounded-lg border border-[var(--border)]">
                <span className="text-xs font-medium text-[var(--text-secondary)]">Findings:</span>
                <p className="text-xs font-bold text-[var(--text-primary)] mt-1">
                  {assessment?.summary.findings_count ?? 0}
                </p>
              </div>

              <div className="p-3 bg-amber-50/60 rounded-lg border border-amber-100">
                <span className="text-xs font-medium text-amber-800">Warnings:</span>
                <p className="text-xs font-bold text-amber-700 mt-1">
                  {assessment?.summary.warning_checks ?? 0}
                </p>
              </div>

              <div className="p-3 bg-rose-50/60 rounded-lg border border-rose-100">
                <span className="text-xs font-medium text-rose-800">Failed Checks:</span>
                <p className="text-xs font-bold text-rose-700 mt-1">
                  {assessment?.summary.failed_checks ?? 0}
                </p>
              </div>
            </div>
          </div>
        </AnimatedCard>
      </div>

      {/* Security Alerts Section */}
      {alerts && alerts.length > 0 && (
        <div className="w-full">
          <AnimatedCard delay={0.2}>
            <RecentAlerts alerts={alerts} />
          </AnimatedCard>
        </div>
      )}

      {/* Main Two-Column Telemetry Panels */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left Column: Real Gateway Security Event Feed (7 Cols) */}
        <div className="lg:col-span-7">
          <AnimatedCard delay={0.1}>
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <div className="flex items-center gap-2">
                  <Activity className="h-4 w-4 text-blue-600" />
                  <h2 className="text-sm font-bold text-slate-900">Live SecureShop Gateway Stream</h2>
                </div>
                <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-emerald-600">
                  <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
                  Streaming
                </span>
              </div>

              {loading && !metrics ? (
                <div className="py-12 text-center text-xs text-slate-400">Loading live telemetry stream...</div>
              ) : !metrics?.recent_gateway_logs || metrics.recent_gateway_logs.length === 0 ? (
                <div className="py-12 text-center text-xs text-slate-500">
                  <Shield className="h-8 w-8 mx-auto mb-2 text-slate-300" />
                  <p className="font-medium text-slate-700">No Gateway Traffic Recorded Yet</p>
                  <p className="text-[11px] text-slate-400 mt-1">
                    Requests through <code className="bg-slate-100 px-1 py-0.5 rounded font-mono">/gateway/secureshop/...</code> will appear here in real-time.
                  </p>
                </div>
              ) : (
                <div className="mt-3 overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-slate-100 text-slate-500 text-[11px]">
                        <th className="pb-2 font-medium">Time</th>
                        <th className="pb-2 font-medium">Source IP</th>
                        <th className="pb-2 font-medium">Method & Endpoint</th>
                        <th className="pb-2 font-medium">Latency</th>
                        <th className="pb-2 font-medium text-right">Result</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                      {metrics.recent_gateway_logs.slice(0, 8).map((log: GatewayLog) => (
                        <tr key={log.id} className="hover:bg-slate-50/60 transition-colors">
                          <td className="py-2.5 text-slate-400">
                            {new Date(log.timestamp).toLocaleTimeString()}
                          </td>
                          <td className="py-2.5 text-slate-700 font-medium">
                            {log.ip_address}
                          </td>
                          <td className="py-2.5 max-w-[220px] truncate text-slate-800">
                            <span className="font-bold text-slate-600 mr-1.5">{log.method}</span>
                            <span>{log.endpoint}</span>
                          </td>
                          <td className="py-2.5 text-slate-500">
                            {log.response_time_ms ? `${log.response_time_ms.toFixed(1)}ms` : "-"}
                          </td>
                          <td className="py-2.5 text-right">
                            <span
                              className={`rounded px-1.5 py-0.5 text-[10px] font-semibold border ${getLogBadge(
                                log.classification,
                                log.status_code
                              )}`}
                            >
                              {log.status_code} {log.classification.toUpperCase()}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </AnimatedCard>
        </div>

        {/* Right Column: Tracked IP Risk Scores & Active Blocks (5 Cols) */}
        <div className="lg:col-span-5 space-y-4">
          {/* Tracked Risk Scores */}
          <AnimatedCard delay={0.15}>
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-amber-600" />
                  <h2 className="text-sm font-bold text-slate-900">Tracked Threat Scores</h2>
                </div>
                <Link
                  to="/security"
                  className="flex items-center gap-1 text-[11px] font-semibold text-blue-600 hover:text-blue-700"
                >
                  Manage <ArrowUpRight className="h-3 w-3" />
                </Link>
              </div>

              {threats.length === 0 ? (
                <div className="py-8 text-center text-xs text-slate-500">
                  <CheckCircle2 className="h-7 w-7 mx-auto mb-1 text-emerald-500" />
                  <p className="font-medium text-slate-700">No Elevated Threat IPs</p>
                  <p className="text-[10px] text-slate-400 mt-0.5">All monitored traffic has clean threat profiles.</p>
                </div>
              ) : (
                <div className="mt-3 divide-y divide-slate-100">
                  {threats.slice(0, 4).map((threat) => (
                    <div key={threat.ip_address} className="flex items-center justify-between py-2 text-xs">
                      <div>
                        <span className="font-mono font-medium text-slate-800">{threat.ip_address}</span>
                        <p className="text-[10px] text-slate-400">
                          {threat.threat_level.toUpperCase()} · {threat.current_score.toFixed(1)} / 100
                        </p>
                      </div>
                      <span
                        className={`rounded px-1.5 py-0.5 text-[10px] font-bold border ${getThreatBadge(
                          threat.threat_level
                        )}`}
                      >
                        {threat.threat_level}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </AnimatedCard>

          {/* Active Perimeter Blocks */}
          <AnimatedCard delay={0.2}>
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <div className="flex items-center gap-2">
                  <ShieldBan className="h-4 w-4 text-rose-600" />
                  <h2 className="text-sm font-bold text-slate-900">Perimeter Threat Blocks</h2>
                </div>
                <span className="text-[10px] font-mono text-slate-500">
                  {blocks.filter(b => b.status === "blocked").length} ACTIVE
                </span>
              </div>

              {blocks.filter(b => b.status === "blocked").length === 0 ? (
                <div className="py-6 text-center text-xs text-slate-500">
                  <CheckCircle2 className="h-6 w-6 mx-auto mb-1 text-emerald-500" />
                  <p className="font-medium text-slate-600">No Blocked IPs</p>
                  <p className="text-[10px] text-slate-400 mt-0.5">Threshold enforcement ready (≥ 50.0).</p>
                </div>
              ) : (
                <div className="mt-3 divide-y divide-slate-100">
                  {blocks.filter(b => b.status === "blocked").slice(0, 3).map((block) => (
                    <div key={block.id} className="flex items-center justify-between py-2 text-xs">
                      <div>
                        <span className="font-mono font-semibold text-rose-700 text-[11px]">
                          {block.ip_address}
                        </span>
                        <p className="text-[10px] text-slate-500 mt-0.5 line-clamp-1">{block.reason || "Autonomous threshold"}</p>
                      </div>
                      <span className="text-[10px] text-slate-400">
                        {block.blocked_at ? new Date(block.blocked_at).toLocaleTimeString() : "Recent"}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </AnimatedCard>
        </div>
      </div>

      {/* Moving Target Defense (MTD) Dynamic Route Mappings Table */}
      <AnimatedCard delay={0.25}>
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <div className="flex items-center gap-2">
              <RefreshCw className="h-4 w-4 text-emerald-600" />
              <div>
                <h2 className="text-sm font-bold text-slate-900">Moving Target Defense (MTD) Polymorphic Mappings</h2>
                <p className="text-[11px] text-slate-500">
                  Dynamic SHA-256 aliases masking protected administrative endpoints from external discovery.
                </p>
              </div>
            </div>
            <Link
              to="/security"
              className="flex items-center gap-1 text-[11px] font-semibold text-blue-600 hover:text-blue-700"
            >
              MTD Console <ArrowUpRight className="h-3 w-3" />
            </Link>
          </div>

          {!mtdStatus || Object.keys(mtdStatus.active_routes).length === 0 ? (
            <div className="py-8 text-center text-xs text-slate-500">
              <AlertTriangle className="h-7 w-7 mx-auto mb-2 text-slate-300" />
              <p className="font-medium text-slate-600">No Dynamic Routes Active</p>
              <p className="text-[11px] text-slate-400 mt-1">
                MTD engine is idle or waiting for route registration.
              </p>
            </div>
          ) : (
            <div className="mt-3 overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-100 text-slate-500 text-[11px]">
                    <th className="pb-2 font-medium">Internal Protected Target</th>
                    <th className="pb-2 font-medium">Active Dynamic Public Alias</th>
                    <th className="pb-2 font-medium text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {Object.entries(mtdStatus.active_routes).map(([alias, real]) => (
                    <tr key={alias} className="hover:bg-slate-50/60">
                      <td className="py-2.5 font-mono text-slate-700">{real}</td>
                      <td className="py-2.5 font-mono font-medium text-blue-600">{alias}</td>
                      <td className="py-2.5 text-right">
                        <span className="rounded-full bg-emerald-50 px-2 py-0.5 text-[10px] font-bold text-emerald-700 border border-emerald-200">
                          ROUTING ACTIVE
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </AnimatedCard>
    </div>
  );
}
