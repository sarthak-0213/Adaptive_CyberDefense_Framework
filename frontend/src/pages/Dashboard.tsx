import { useEffect, useState } from "react";
import { Shield, RefreshCw, Server, UserCheck } from "lucide-react";
import StatCard from "../components/dashboard/StatCard";
import DashboardHeader from "../components/dashboard/DashboardHeader";
import RecentAlerts from "../components/dashboard/RecentAlerts";
import { AnimatedCard } from "../components/AnimatedCard";
import { useAuthStore } from "../store/authStore";
import { getMTDStatus, type MTDStatusResponse } from "../api/mtd";
import { getAlerts } from "../api/alerts";
import type { Alert } from "../types/dashboard";

export default function Dashboard() {
  const user = useAuthStore((state) => state.user);
  const [mtdStatus, setMtdStatus] = useState<MTDStatusResponse | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchDashboardData = async () => {
    try {
      setError(null);
      const [statusData, alertData] = await Promise.all([
        getMTDStatus(),
        getAlerts(),
      ]);
      setMtdStatus(statusData);
      setAlerts(alertData);
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

      {/* Security Alerts Section */}
      <div className="w-full">
        <AnimatedCard delay={0.1}>
          <RecentAlerts alerts={alerts} />
        </AnimatedCard>
      </div>
    </div>
  );
}
