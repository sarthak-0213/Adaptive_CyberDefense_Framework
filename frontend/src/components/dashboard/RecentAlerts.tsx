import { Link } from "react-router-dom";
import { AlertCircle, ArrowUpRight, CheckCircle2, Clock } from "lucide-react";
import type { Alert } from "../../types/dashboard";

interface RecentAlertsProps {
  alerts: Alert[];
}

export default function RecentAlerts({ alerts }: RecentAlertsProps) {
  const getSeverityBadge = (severity: Alert["severity"]) => {
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

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-6 shadow-xl backdrop-blur-sm">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div className="flex items-center gap-2">
          <AlertCircle className="h-5 w-5 text-amber-400" />
          <h2 className="text-lg font-bold text-white">Recent Security Alerts</h2>
        </div>
        <Link
          to="/alerts"
          className="flex items-center gap-1 text-xs font-semibold text-cyan-400 hover:text-cyan-300"
        >
          View all
          <ArrowUpRight className="h-3.5 w-3.5" />
        </Link>
      </div>

      <div className="mt-4 divide-y divide-slate-800/60">
        {alerts.slice(0, 4).map((alert) => (
          <div
            key={alert.id}
            className="flex flex-col justify-between py-3.5 sm:flex-row sm:items-center gap-2"
          >
            <div className="space-y-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span
                  className={`rounded-full border px-2.5 py-0.5 text-[10px] font-bold tracking-wide uppercase ${getSeverityBadge(
                    alert.severity
                  )}`}
                >
                  {alert.severity}
                </span>
                <h3 className="text-sm font-semibold text-slate-200">
                  {alert.title}
                </h3>
              </div>
              {alert.description && (
                <p className="text-xs text-slate-400 max-w-md truncate">
                  {alert.description}
                </p>
              )}
            </div>

            <div className="flex items-center justify-between sm:justify-end gap-3 text-xs">
              <span className="flex items-center gap-1 text-slate-400">
                <Clock className="h-3.5 w-3.5 text-slate-500" />
                {alert.timestamp.split(" ")[1]}
              </span>
              <span
                className={`flex items-center gap-1 rounded-md px-2 py-0.5 font-medium ${
                  alert.status === "resolved"
                    ? "bg-emerald-500/10 text-emerald-400"
                    : alert.status === "active"
                    ? "bg-rose-500/10 text-rose-400"
                    : "bg-amber-500/10 text-amber-300"
                }`}
              >
                {alert.status === "resolved" && <CheckCircle2 className="h-3 w-3" />}
                {alert.status}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
