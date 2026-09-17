import { Shield, Cpu, HardDrive, Wifi, Activity } from "lucide-react";
import type { SystemHealthSummary } from "../../types/dashboard";

interface SystemHealthProps {
  health: SystemHealthSummary;
}

export default function SystemHealth({ health }: SystemHealthProps) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-6 shadow-xl backdrop-blur-sm">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-emerald-400" />
          <h2 className="text-lg font-bold text-white">System Telemetry & Health</h2>
        </div>
        <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-xs font-semibold text-emerald-400">
          {health.status} ({health.overallScore}%)
        </span>
      </div>

      <div className="mt-4 space-y-4">
        {/* CPU Usage */}
        <div>
          <div className="flex items-center justify-between text-xs mb-1.5">
            <span className="flex items-center gap-1.5 text-slate-300 font-medium">
              <Cpu className="h-3.5 w-3.5 text-cyan-400" />
              CPU Utilization
            </span>
            <span className="text-slate-400 font-mono">{health.cpuUsage}%</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
            <div
              className="h-full bg-gradient-to-r from-cyan-500 to-emerald-400 transition-all duration-500"
              style={{ width: `${health.cpuUsage}%` }}
            />
          </div>
        </div>

        {/* Memory Usage */}
        <div>
          <div className="flex items-center justify-between text-xs mb-1.5">
            <span className="flex items-center gap-1.5 text-slate-300 font-medium">
              <Activity className="h-3.5 w-3.5 text-indigo-400" />
              RAM Usage
            </span>
            <span className="text-slate-400 font-mono">{health.memoryUsage}%</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
            <div
              className="h-full bg-gradient-to-r from-indigo-500 to-cyan-400 transition-all duration-500"
              style={{ width: `${health.memoryUsage}%` }}
            />
          </div>
        </div>

        {/* Storage */}
        <div>
          <div className="flex items-center justify-between text-xs mb-1.5">
            <span className="flex items-center gap-1.5 text-slate-300 font-medium">
              <HardDrive className="h-3.5 w-3.5 text-purple-400" />
              System Storage
            </span>
            <span className="text-slate-400 font-mono">{health.storageUsage}%</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
            <div
              className="h-full bg-gradient-to-r from-purple-500 to-amber-400 transition-all duration-500"
              style={{ width: `${health.storageUsage}%` }}
            />
          </div>
        </div>

        {/* Network & MTD details */}
        <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-slate-400">
              <Wifi className="h-3.5 w-3.5 text-cyan-400" />
              Network Bandwidth
            </span>
            <span className="font-mono text-white font-semibold">{health.bandwidthMbps} Mbps</span>
          </div>
          <div className="flex items-center justify-between border-t border-slate-800/80 pt-2">
            <span className="text-slate-400">MTD 24h Rotations:</span>
            <span className="font-mono text-emerald-400 font-semibold">{health.mtdRotations24h} dynamic cycles</span>
          </div>
        </div>
      </div>
    </div>
  );
}
