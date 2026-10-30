import { RefreshCw, ShieldCheck, Radio, Search } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

interface DashboardHeaderProps {
  onRefresh?: () => void;
}

export default function DashboardHeader({ onRefresh }: DashboardHeaderProps) {
  const [isRefreshing, setIsRefreshing] = useState(false);

  const handleRefresh = () => {
    setIsRefreshing(true);
    toast.info("Refreshing real-time telemetry stream...");
    if (onRefresh) onRefresh();
    setTimeout(() => {
      setIsRefreshing(false);
      toast.success("Dashboard telemetry up to date");
    }, 600);
  };

  return (
    <div className="flex min-w-0 flex-col gap-4 border-b border-[var(--border)] pb-6 md:flex-row md:items-start md:justify-between">
      {/* Left: title + subtitle — must be allowed to shrink */}
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-2xl font-bold tracking-tight text-[var(--text-primary)]">
            Adaptive Cyber Defense Command
          </h1>
          <span className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-[rgba(30,142,90,0.3)] bg-[rgba(30,142,90,0.1)] px-2.5 py-0.5 text-xs font-semibold text-[var(--success)]">
            <Radio className="h-3 w-3 animate-pulse" />
            LIVE FEED
          </span>
        </div>
        <p className="mt-1 text-sm text-[var(--text-secondary)]">
          Real-time cyber defense telemetry, security incident logging &amp; MTD dynamic
          threat response.
        </p>
      </div>

      {/* Right: controls — wrap gracefully on narrow screens */}
      <div className="flex shrink-0 flex-wrap items-center gap-3">
        <div className="hidden items-center gap-2 rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 py-1.5 text-xs text-[var(--text-secondary)] sm:flex shadow-sm">
          <ShieldCheck className="h-4 w-4 shrink-0 text-[var(--success)]" />
          <span>
            MTD Defense: <strong className="text-[var(--success)]">ACTIVE</strong>
          </span>
        </div>

        {/* Search */}
        <div className="relative w-48 sm:w-56">
          <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-secondary)]" />
          <input
            type="text"
            placeholder="Search assets or alerts..."
            className="w-full rounded-lg border border-[var(--border)] bg-[var(--surface)] py-1.5 pl-8 pr-3 text-xs text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:border-[var(--accent-blue)] focus:outline-none focus:ring-1 focus:ring-[var(--accent-blue)] shadow-sm"
          />
        </div>

        <button
          onClick={handleRefresh}
          disabled={isRefreshing}
          className="flex items-center gap-2 rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3.5 py-1.5 text-xs font-medium text-[var(--text-primary)] transition hover:border-[var(--accent-blue)] hover:bg-[#F0F0EC] active:scale-95 disabled:opacity-50 shadow-sm"
        >
          <RefreshCw
            className={`h-3.5 w-3.5 text-[var(--accent-blue)] ${isRefreshing ? "animate-spin" : ""}`}
          />
          Refresh
        </button>
      </div>
    </div>
  );
}
