import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Shield,
  RefreshCw,
  ShieldAlert,
  ShieldBan,
  AlertTriangle,
  ArrowUpRight,
  WifiOff,
  Activity,
  CheckCircle2,
  Globe,
} from "lucide-react";
import StatCard from "../components/dashboard/StatCard";
import DashboardHeader from "../components/dashboard/DashboardHeader";
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

export default function Dashboard() {
  const [mtdStatus, setMtdStatus] = useState<MTDStatusResponse | null>(null);
  const [metrics, setMetrics] = useState<SecurityMetrics | null>(null);
  const [threats, setThreats] = useState<ThreatScore[]>([]);
  const [blocks, setBlocks] = useState<ThreatBlock[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const apiBaseUrl = import.meta.env.VITE_API_URL || "(Relative / same-origin)";

  const fetchDashboardData = async () => {
    try {
      setError(null);
      const [statusData, metricsData, threatsData, blocksData] = await Promise.all([
        getMTDStatus().catch(() => null),
        getSecurityMetrics().catch(() => null),
        getThreats().catch(() => []),
        getBlocks().catch(() => []),
      ]);

      if (!statusData && !metricsData) {
        setError(`Unable to connect to backend API at ${apiBaseUrl}`);
      } else {
        setMtdStatus(statusData);
        setMetrics(metricsData);
        setThreats(threatsData || []);
        setBlocks(blocksData || []);
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
      case "LOW":
      default:
        return "bg-emerald-50 text-emerald-700 border-emerald-200";
    }
  };

  const getClassificationBadge = (classification: string) => {
    switch (classification) {
      case "attack":
        return "bg-rose-100 text-rose-800 border-rose-300";
      case "blocked":
        return "bg-purple-100 text-purple-800 border-purple-300";
      case "honeypot":
        return "bg-orange-100 text-orange-800 border-orange-300";
      case "suspicious":
        return "bg-amber-100 text-amber-800 border-amber-300";
      case "legitimate":
      default:
        return "bg-emerald-100 text-emerald-800 border-emerald-300";
    }
  };

  const getMethodBadge = (method: string) => {
    switch (method) {
      case "POST":
        return "bg-blue-50 text-blue-700 border-blue-200";
      case "PUT":
        return "bg-amber-50 text-amber-700 border-amber-200";
      case "DELETE":
        return "bg-rose-50 text-rose-700 border-rose-200";
      case "GET":
      default:
        return "bg-slate-100 text-slate-700 border-slate-200";
    }
  };

  return (
    <div className="w-full min-w-0 space-y-6 text-slate-900">
      {/* Header */}
      <DashboardHeader onRefresh={fetchDashboardData} />

      {/* Disconnected / Error Banner */}
      {error && (
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 rounded-lg border border-rose-200 bg-rose-50 p-4 text-xs text-rose-800 shadow-sm">
          <div className="flex items-center gap-2.5">
            <WifiOff className="h-5 w-5 shrink-0 text-rose-600" />
            <div>
              <p className="font-semibold">{error}</p>
              <p className="text-rose-600 text-[11px] mt-0.5">
                Verify the ACDF backend FastAPI service is running and accessible from this origin.
              </p>
            </div>
          </div>
          <button
            onClick={fetchDashboardData}
            className="px-3 py-1.5 rounded bg-rose-600 text-white font-medium hover:bg-rose-700 transition flex items-center gap-1.5 shrink-0"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Retry Connection
          </button>
        </div>
      )}

      {/* 4 Primary Cybersecurity Stat Cards */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 xl:grid-cols-4">
        {/* 1. Total Gateway Requests */}
        <StatCard
          delay={0}
          title="Gateway Requests"
          value={loading ? "..." : (metrics?.total_gateway_requests ?? 0)}
          subtitle={metrics ? `${metrics.successful_requests} ok • ${metrics.failed_requests} failed` : "Live proxy traffic"}
          trend={metrics?.total_gateway_requests ? "Active Stream" : "No Traffic"}
          trendPositive={true}
          icon={<Globe className="h-5 w-5 text-blue-600" />}
        />

        {/* 2. Threat Events & Suspicious Activity */}
        <StatCard
          delay={0.08}
          title="Threat Events"
          value={loading ? "..." : (metrics?.threat_events_recorded ?? 0)}
          subtitle={metrics ? `${metrics.suspicious_requests} suspicious hits` : "Correlated signals"}
          trend={metrics?.suspicious_requests ? "Threats Detected" : "Clear"}
          trendPositive={!(metrics?.suspicious_requests)}
          icon={<ShieldAlert className="h-5 w-5 text-amber-600" />}
        />

        {/* 3. Perimeter Threat Blocks */}
        <StatCard
          delay={0.16}
          title="Perimeter Blocks"
          value={loading ? "..." : (metrics?.active_blocks ?? blocks.filter(b => b.status === "blocked").length)}
          subtitle={metrics ? `${metrics.requests_blocked} requests denied` : "Autonomous IP bans"}
          trend={metrics?.active_blocks ? "Enforcing" : "Clean Perimeter"}
          trendPositive={!(metrics?.active_blocks)}
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

      {/* Main Two-Column Telemetry Panels */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left Column: Real Gateway Security Event Feed (7 Cols) */}
        <div className="lg:col-span-7">
          <AnimatedCard delay={0.1}>
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <div className="flex items-center gap-2">
                  <Activity className="h-5 w-5 text-blue-600" />
                  <div>
                    <h2 className="text-sm font-bold text-slate-900">Live Gateway Request Stream</h2>
                    <p className="text-[11px] text-slate-500">
                      Real-time HTTP requests passing through the ACDF Security Gateway
                    </p>
                  </div>
                </div>
                <span className="text-[10px] font-mono text-emerald-600 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-full font-semibold">
                  LIVE TELEMETRY
                </span>
              </div>

              {loading ? (
                <div className="py-12 text-center text-xs text-slate-500">
                  <RefreshCw className="h-5 w-5 animate-spin mx-auto mb-2 text-slate-400" />
                  Loading gateway logs...
                </div>
              ) : !metrics?.recent_gateway_logs || metrics.recent_gateway_logs.length === 0 ? (
                <div className="py-10 text-center text-xs text-slate-500">
                  <Globe className="h-8 w-8 mx-auto mb-2 text-slate-300" />
                  <p className="font-medium text-slate-600">No Gateway Traffic Logged Yet</p>
                  <p className="text-[11px] text-slate-400 mt-1">
                    API calls made to <code className="bg-slate-100 px-1 py-0.5 rounded text-slate-600">/gateway/secureshop/...</code> will appear here automatically.
                  </p>
                </div>
              ) : (
                <div className="mt-3 divide-y divide-slate-100">
                  {metrics.recent_gateway_logs.map((log: GatewayLog) => (
                    <div key={log.id} className="flex items-center justify-between py-2.5 text-xs">
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <span className={`font-mono text-[10px] font-bold px-1.5 py-0.5 rounded border ${getMethodBadge(log.method)}`}>
                            {log.method}
                          </span>
                          <span className="font-mono font-medium text-slate-800 text-[11px]">
                            {log.endpoint}
                          </span>
                          <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded border ${getClassificationBadge(log.classification)}`}>
                            {log.classification}
                          </span>
                        </div>
                        <div className="text-[10px] text-slate-400 flex items-center gap-2">
                          <span className="font-mono">{log.ip_address}</span>
                          <span>•</span>
                          <span>{log.response_time_ms}ms</span>
                          {log.detection_result && log.detection_result !== "none" && (
                            <>
                              <span>•</span>
                              <span className="text-amber-600 font-medium">Trigger: {log.detection_result}</span>
                            </>
                          )}
                        </div>
                      </div>

                      <div className="text-right">
                        <span className={`font-mono text-xs font-bold ${log.status_code < 400 ? 'text-emerald-600' : 'text-rose-600'}`}>
                          {log.status_code}
                        </span>
                        <span className="block text-[10px] text-slate-400">
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </AnimatedCard>
        </div>

        {/* Right Column: Tracked IP Threat Scores & Blocks (5 Cols) */}
        <div className="lg:col-span-5 space-y-5">
          {/* Tracked Threat Scores */}
          <AnimatedCard delay={0.15}>
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-amber-600" />
                  <h2 className="text-sm font-bold text-slate-900">Tracked Risk Scores</h2>
                </div>
                <Link
                  to="/threat-analytics"
                  className="flex items-center gap-1 text-[11px] font-semibold text-blue-600 hover:text-blue-700"
                >
                  Details <ArrowUpRight className="h-3 w-3" />
                </Link>
              </div>

              {threats.length === 0 ? (
                <div className="py-6 text-center text-xs text-slate-500">
                  <Shield className="h-6 w-6 mx-auto mb-1 text-slate-300" />
                  <p className="font-medium text-slate-600">Perimeter Threat Free</p>
                  <p className="text-[10px] text-slate-400 mt-0.5">No offending client IPs detected.</p>
                </div>
              ) : (
                <div className="mt-3 divide-y divide-slate-100">
                  {threats.slice(0, 4).map((threat) => (
                    <div key={threat.ip_address} className="flex items-center justify-between py-2 text-xs">
                      <div>
                        <span className="font-mono font-medium text-slate-800 text-[11px]">
                          {threat.ip_address}
                        </span>
                        {threat.active_block_id && (
                          <span className="ml-2 rounded bg-rose-50 px-1.5 py-0.2 text-[9px] font-bold text-rose-700 border border-rose-200">
                            BLOCKED
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-semibold text-slate-800">
                          {threat.current_score.toFixed(1)}
                        </span>
                        <span className={`rounded-full border px-2 py-0.2 text-[9px] font-bold ${getThreatBadge(threat.threat_level)}`}>
                          {threat.threat_level}
                        </span>
                      </div>
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
