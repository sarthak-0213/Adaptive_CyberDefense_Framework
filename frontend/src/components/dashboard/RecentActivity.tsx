import { Activity, ShieldAlert, User, Server } from "lucide-react";
import type { ActivityItem } from "../../types/dashboard";

interface RecentActivityProps {
  activities: ActivityItem[];
}

export default function RecentActivity({ activities }: RecentActivityProps) {
  const getCategoryIcon = (category: ActivityItem["category"]) => {
    switch (category) {
      case "security":
        return <ShieldAlert className="h-3.5 w-3.5 text-rose-400" />;
      case "user":
        return <User className="h-3.5 w-3.5 text-indigo-400" />;
      case "system":
      default:
        return <Server className="h-3.5 w-3.5 text-emerald-400" />;
    }
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-6 shadow-xl backdrop-blur-sm">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div className="flex items-center gap-2">
          <Activity className="h-5 w-5 text-cyan-400" />
          <h2 className="text-lg font-bold text-white">System Activity Log</h2>
        </div>
        <span className="text-xs font-mono text-slate-500">REALTIME</span>
      </div>

      <div className="mt-4 relative pl-4 border-l border-slate-800 space-y-4">
        {activities.map((item) => (
          <div key={item.id} className="relative group">
            {/* Timeline dot */}
            <div className="absolute -left-[21px] top-1 rounded-full border border-slate-800 bg-slate-950 p-1">
              {getCategoryIcon(item.category)}
            </div>

            <div className="space-y-0.5">
              <div className="flex items-center justify-between gap-2">
                <h4 className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300">
                  {item.title}
                </h4>
                <span className="text-[10px] font-mono text-slate-500">{item.timestamp}</span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                {item.details}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
