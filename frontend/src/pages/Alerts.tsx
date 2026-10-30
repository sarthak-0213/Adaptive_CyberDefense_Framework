import { useEffect, useState } from "react";
import { ShieldAlert, CheckCircle2, Clock, Loader2, RefreshCw } from "lucide-react";
import { getAlerts, resolveAlert } from "../api/alerts";
import type { Alert } from "../types/dashboard";
import { toast } from "sonner";

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAlerts = async () => {
    try {
      setError(null);
      const data = await getAlerts();
      setAlerts(data);
    } catch (err: any) {
      setError("Failed to fetch alerts from backend.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleResolve = async (alertId: string | number) => {
    try {
      await resolveAlert(alertId, "resolved");
      toast.success("Alert resolved successfully");
      fetchAlerts();
    } catch (err) {
      toast.error("Failed to resolve alert");
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-rose-500/10 text-rose-400 border-rose-500/30";
      case "high":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "medium":
        return "bg-yellow-500/10 text-yellow-300 border-yellow-500/30";
      case "low":
      default:
        return "bg-slate-800 text-slate-300 border-slate-700";
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "resolved":
        return "bg-emerald-500/10 text-emerald-400";
      case "active":
        return "bg-rose-500/10 text-rose-400";
      case "investigating":
        return "bg-amber-500/10 text-amber-300";
      default:
        return "bg-slate-800 text-slate-400";
    }
  };

  const activeCount = alerts.filter((a) => a.status === "active").length;
  const resolvedCount = alerts.filter((a) => a.status === "resolved").length;

  return (
    <div className="space-y-8 text-white">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-3xl font-bold text-white tracking-tight">
              Security Incident & Alerts Log
            </h1>
            <span
              className={`rounded-full border px-3 py-0.5 text-xs font-semibold ${
                error
                  ? "border-red-500/30 bg-red-500/10 text-red-400"
                  : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
              }`}
            >
              {error ? "Disconnected" : "Live"}
            </span>
          </div>
          <p className="mt-1 text-sm text-slate-400">
            Real-time security incident alerts, system violations & threat detection events.
          </p>
        </div>

        <button
          onClick={fetchAlerts}
          className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900 px-4 py-2.5 text-xs font-semibold text-slate-300 hover:text-white"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      </div>

      {/* KPI strip */}
      <div className="grid grid-cols-3 gap-4">
        <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-4 shadow-xl">
          <p className="text-xs text-slate-400 uppercase font-semibold">Total Alerts</p>
          <p className="mt-2 text-3xl font-extrabold text-white">{alerts.length}</p>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-4 shadow-xl">
          <p className="text-xs text-rose-400 uppercase font-semibold">Active</p>
          <p className="mt-2 text-3xl font-extrabold text-rose-400">{activeCount}</p>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-4 shadow-xl">
          <p className="text-xs text-emerald-400 uppercase font-semibold">Resolved</p>
          <p className="mt-2 text-3xl font-extrabold text-emerald-400">{resolvedCount}</p>
        </div>
      </div>

      {/* Alerts table */}
      {loading ? (
        <div className="flex flex-col items-center justify-center p-12 space-y-4">
          <Loader2 className="h-8 w-8 animate-spin text-cyan-400" />
          <p className="text-sm text-slate-400">Loading alerts...</p>
        </div>
      ) : alerts.length > 0 ? (
        <div className="rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-semibold uppercase">
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Title</th>
                  <th className="py-3 px-4">Time</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {alerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-4">
                      <span
                        className={`rounded-full border px-2.5 py-0.5 text-[10px] font-bold tracking-wide uppercase ${getSeverityBadge(
                          alert.severity
                        )}`}
                      >
                        {alert.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="font-semibold text-slate-200 text-sm">{alert.title}</span>
                      {alert.description && (
                        <p className="mt-0.5 text-[10px] text-slate-500 max-w-[300px] truncate">
                          {alert.description}
                        </p>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <span className="flex items-center gap-1 text-slate-400">
                        <Clock className="h-3.5 w-3.5 text-slate-500" />
                        {alert.timestamp}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`flex items-center gap-1 rounded-md px-2 py-0.5 font-medium w-fit ${getStatusBadge(
                          alert.status
                        )}`}
                      >
                        {alert.status === "resolved" && <CheckCircle2 className="h-3 w-3" />}
                        {alert.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      {alert.status !== "resolved" && (
                        <button
                          onClick={() => handleResolve(alert.id)}
                          className="rounded bg-emerald-600/20 border border-emerald-500/30 px-2.5 py-1 text-[10px] font-bold text-emerald-400 hover:bg-emerald-600/40 transition"
                        >
                          Resolve
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center rounded-2xl border border-slate-800 bg-slate-900/90 p-12 text-center shadow-xl space-y-4">
          <div className="flex h-16 w-16 items-center justify-center rounded-full bg-slate-800 text-slate-500">
            <ShieldAlert className="h-8 w-8" />
          </div>
          <div className="space-y-2">
            <h3 className="text-xl font-bold text-white">No Security Alerts</h3>
            <p className="text-sm text-slate-400 max-w-md mx-auto">
              Security alerts will appear here when threats or violation incidents are detected.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
