import { useEffect } from "react";
import { Command } from "cmdk";
import { useNavigate } from "react-router-dom";
import {
  LayoutDashboard,
  TriangleAlert,
  Shield,
  Activity,
  FileBarChart,
  Settings,
  Search,
} from "lucide-react";

export function CommandPalette({ open, setOpen }: { open: boolean; setOpen: (open: boolean) => void }) {
  const navigate = useNavigate();

  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen(true);
      }
    };

    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, [setOpen]);

  const runCommand = (command: () => void) => {
    setOpen(false);
    command();
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh]">
      <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm" onClick={() => setOpen(false)} />
      <Command
        className="relative z-50 flex w-full max-w-2xl flex-col overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--surface)] text-[var(--text-primary)] shadow-2xl"
        label="Global Command Menu"
      >
        <div className="flex items-center border-b border-[var(--border)] px-3">
          <Search className="mr-2 h-5 w-5 shrink-0 text-[var(--text-secondary)]" />
          <Command.Input
            autoFocus
            className="flex h-14 w-full rounded-md bg-transparent py-3 text-sm outline-none placeholder:text-[var(--text-secondary)]"
            placeholder="Search commands or navigate..."
          />
        </div>
        <Command.List className="max-h-[300px] overflow-y-auto overflow-x-hidden p-2">
          <Command.Empty className="py-6 text-center text-sm text-[var(--text-secondary)]">
            No results found.
          </Command.Empty>

          <Command.Group heading="Navigation" className="text-xs font-medium text-[var(--text-secondary)] px-2 py-1">
            <Command.Item onSelect={() => runCommand(() => navigate("/"))} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm text-[var(--text-primary)] aria-selected:bg-[var(--accent-blue)] aria-selected:text-white">
              <LayoutDashboard className="h-4 w-4" /> Dashboard
            </Command.Item>
            <Command.Item onSelect={() => runCommand(() => navigate("/alerts"))} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm text-[var(--text-primary)] aria-selected:bg-[var(--accent-blue)] aria-selected:text-white">
              <TriangleAlert className="h-4 w-4" /> Alerts
            </Command.Item>
            <Command.Item onSelect={() => runCommand(() => navigate("/security"))} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm text-[var(--text-primary)] aria-selected:bg-[var(--accent-blue)] aria-selected:text-white">
              <Shield className="h-4 w-4" /> Security
            </Command.Item>
            <Command.Item onSelect={() => runCommand(() => navigate("/threats"))} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm text-[var(--text-primary)] aria-selected:bg-[var(--accent-blue)] aria-selected:text-white">
              <Activity className="h-4 w-4" /> Threat Analytics
            </Command.Item>
            <Command.Item onSelect={() => runCommand(() => navigate("/reports"))} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm text-[var(--text-primary)] aria-selected:bg-[var(--accent-blue)] aria-selected:text-white">
              <FileBarChart className="h-4 w-4" /> Reports
            </Command.Item>
            <Command.Item onSelect={() => runCommand(() => navigate("/settings"))} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm text-[var(--text-primary)] aria-selected:bg-[var(--accent-blue)] aria-selected:text-white">
              <Settings className="h-4 w-4" /> Settings
            </Command.Item>
          </Command.Group>

          <Command.Group heading="Actions" className="text-xs font-medium text-[var(--text-secondary)] px-2 py-1 mt-2">
            <Command.Item onSelect={() => runCommand(() => { navigate("/reports"); })} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm text-[var(--text-primary)] aria-selected:bg-[var(--accent-blue)] aria-selected:text-white">
              <FileBarChart className="h-4 w-4" /> Generate Security Audit Report
            </Command.Item>
            <Command.Item onSelect={() => runCommand(() => { window.location.reload(); })} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm text-[var(--text-primary)] aria-selected:bg-[var(--accent-blue)] aria-selected:text-white">
              <Search className="h-4 w-4" /> Refresh Data
            </Command.Item>
          </Command.Group>
        </Command.List>
      </Command>
    </div>
  );
}
