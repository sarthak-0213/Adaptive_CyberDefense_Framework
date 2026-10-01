import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Shield, RefreshCw, Server, UserCheck, ShieldCheck, ArrowRight } from "lucide-react";

import StatCard from "../components/dashboard/StatCard";
import DashboardHeader from "../components/dashboard/DashboardHeader";
import RecentAlerts from "../components/dashboard/RecentAlerts";
import { AnimatedCard } from "../components/AnimatedCard";
import { useAuthStore } from "../store/authStore";
import { getMTDStatus, type MTDStatusResponse } from "../api/mtd";
import { getAlerts } from "../api/alerts";
import { getLatestAssessment, type SecurityAssessmentFullResponse } from "../api/securityAssessment";
import type { Alert } from "../types/dashboard";

export default function Dashboard() {
  const user = useAuthStore((state) => state.user);
  const [mtdStatus, setMtdStatus] = useState<MTDStatusResponse | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [assessment, setAssessment] = useState<SecurityAssessmentFullResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchDashboardData = async () => {
    try {
      setError(null);
      const [statusData, alertData, assessmentData] = await Promise.all([
        getMTDStatus(),
        getAlerts(),
        getLatestAssessment().catch(() => null),
      ]);
      setMtdStatus(statusData);
      setAlerts(alertData);
      setAssessment(assessmentData);
    } catch (err: any) {
      console.error("Dashboard fetch error:", err);
      setError("Backend connection error or unauthenticated");
    } finally {
      setLoading(false);
    }
  };


  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="w-full min-w-0 space-y-8 text-white">
      {/* Header */}
      <DashboardHeader onRefresh={fetchDashboardData} />

      {/* Dynamic Alert Banner if backend is unreachable */}
      {error && (
        <div className="flex items-center gap-3 rounded-lg border border-red-500/30 bg-red-500/10 p-3.5 text-xs text-red-400">
          <Server className="h-4 w-4 shrink-0 text-red-400" />
          <span>{error}. Please check if the backend API service is running.</span>
        </div>
      )}

      {/* Real Information Cards — 4-col on xl, 2-col on md, 1-col on mobile */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 xl:grid-cols-4">
        {/* Authenticated User */}
        <StatCard
          delay={0}
          title="Authenticated User"
          value={user?.email || "Unknown user"}
          subtitle={`Role: ${user?.role || "N/A"}`}
          trend="Authenticated"
          trendPositive={true}
          icon={<UserCheck className="h-5 w-5 text-[var(--accent-blue)]" />}
        />

        {/* MTD Dynamic Defense Status */}
        <StatCard
          delay={0.08}
          title="MTD Defense"
          value={loading ? "Loading…" : mtdStatus?.mtd_enabled ? "Enabled" : "Disabled"}
          subtitle={
            mtdStatus
              ? `Rotation: ${mtdStatus.rotation_interval_seconds}s`
              : "MTD status pending"
          }
          trend={mtdStatus?.mtd_enabled ? "Active Shuffling" : "Inactive"}
          trendPositive={!!mtdStatus?.mtd_enabled}
          icon={<Shield className="h-5 w-5 text-[var(--success)]" />}
        />

        {/* Backend Availability */}
        <StatCard
          delay={0.16}
          title="Backend Connection"
          value={error ? "Disconnected" : "Connected"}
          subtitle="FastAPI Core Engine"
          trend={error ? "Error" : "Online"}
          trendPositive={!error}
          icon={<Server className="h-5 w-5 text-[var(--info)]" />}
        />

        {/* Dynamic Routes Count */}
        <StatCard
          delay={0.24}
          title="Active Dynamic Routes"
          value={mtdStatus ? Object.keys(mtdStatus.active_routes).length : 0}
          subtitle="Protected MTD Endpoints"
          trend="Dynamic Translation"
          trendPositive={true}
          icon={<RefreshCw className="h-5 w-5 text-[var(--warning)]" />}
        />
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
      <div className="w-full">
        <AnimatedCard delay={0.2}>
          <RecentAlerts alerts={alerts} />
        </AnimatedCard>
      </div>
    </div>
  );
}

